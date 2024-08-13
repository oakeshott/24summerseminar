#!/usr/bin/python3
# -*- coding: utf-8 -*-

from bcc import BPF
from bcc import lib, table
from pyroute2 import IPRoute
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6, inet_ntoa
from struct import pack
import ctypes as ct
import json
import numpy as np
from datetime import datetime

def usage():
    print("Usage: {0} <ifdev> <flag>".format(sys.argv[0]))
    exit(1)

ipr = IPRoute()

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define DEBUG_BUILD
#define FIXED_POINT_DIGITS 16
#define NUM_FEATURES 12
#ifndef abs
#define abs(x) ((x)<0 ? -(x) : (x))
#endif

struct pkt_key_t {
  u32 protocol;
  u32 saddr;
  u32 daddr;
  u32 sport;
  u32 dport;
};

struct pkt_leaf_t {
  u64 num_packets;
  u64 last_packet_timestamp;
  u64 saddr;
  u64 daddr;
  u64 sport;
  u64 dport;
  u64 features[6];
};

BPF_TABLE("lru_hash", struct pkt_key_t, struct pkt_leaf_t, sessions, 1024);
BPF_HASH(pktcnt, int, u32);

int dt_tc_drop_packet(struct __sk_buff *skb) {
  int64_t ts = bpf_ktime_get_ns();
  void* data_end = (void*)(long)skb->data_end;
  void* data = (void*)(long)skb->data;

  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);

  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  struct pkt_key_t pkt_key = {};
  struct pkt_leaf_t pkt_val = {};


  pkt_key.protocol = 0;
  pkt_key.saddr = 0;
  pkt_key.daddr = 0;
  pkt_key.sport = 0;
  pkt_key.dport = 0;

  ethernet: {
    if (data + nh_off > data_end) {
      return TC_ACT_SHOT;
    }
    switch(eth->h_proto) {
      case htons(ETH_P_IP): goto ip;
      default: goto EOP;
    }
  }

  ip: {
    iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
      return TC_ACT_SHOT;
    pkt_key.saddr    = iph->saddr;
    pkt_key.daddr    = iph->daddr;
    pkt_key.protocol = iph->protocol;

    switch(iph->protocol) {
      case IPPROTO_TCP: goto tcp;
      case IPPROTO_UDP: goto udp;
      default: goto EOP;
    }
  }

  tcp: {
    th = (struct tcphdr *)(iph + 1);
    if ((void*)(th + 1) > data_end) {
      return TC_ACT_SHOT;
    }
    pkt_key.sport = ntohs(th->source);
    pkt_key.dport = ntohs(th->dest);

    goto dt;
  }

  udp: {
    uh = (struct udphdr *)(iph + 1);
    if ((void*)(uh + 1) > data_end) {
      return TC_ACT_SHOT;
    }
    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);

    goto dt;
  }

  dt: {
    struct pkt_leaf_t *pkt_leaf = sessions.lookup(&pkt_key);
    if (!pkt_leaf) {
      struct pkt_leaf_t zero = {};
      zero.sport = pkt_key.sport;
      zero.dport = pkt_key.dport;
      zero.saddr = pkt_key.saddr;
      zero.daddr = pkt_key.daddr;
      zero.num_packets = 0;
      zero.last_packet_timestamp = ts;
      sessions.update(&pkt_key, &zero);
      // pkt_leaf = sessions.lookup(&pkt_key);
    }
    /* ADD FLOW EXTRACTION CODE HERE */
    u32 val = 0, *vp, _zero = 0;
    vp = pktcnt.lookup_or_init(&_zero, &val);
    *vp += 1;
  }

  EOP: {
    return TC_ACT_OK;
  }

  return TC_ACT_OK;
}
"""

def map_bpf_table(hashmap, values):
    MAP_SIZE = len(values)
    assert len(hashmap.items()) == MAP_SIZE
    keys = (hashmap.Key * MAP_SIZE)()
    new_values = (hashmap.Leaf * MAP_SIZE)()

    for i in range(MAP_SIZE):
        keys[i] = ct.c_int(i)
        new_values[i] = ct.c_longlong(values[i])
    hashmap.items_update_batch(keys, new_values)

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        usage()
    device = sys.argv[1]

    INGRESS = "ffff:ffff2"
    EGRESS = "ffff:ffff3"

    ret = []
    try:
        b = BPF(text=bpf_text, debug=0)
        fn = b.load_func("dt_tc_drop_packet", BPF.SCHED_CLS)
        idx = ipr.link_lookup(ifname=device)[0]
        ipr.tc("add", "clsact", idx);
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=INGRESS, classid=1, direct_action=True)

        for i in range(0, lib.bpf_num_functions(b.module)):
            func_name = lib.bpf_function_name(b.module, i)
            print(func_name, lib.bpf_function_size(b.module, func_name))

        pktcnt   = b.get_table("pktcnt")
        sessions = b.get_table("sessions")

        while True:
            try:
                pktcnt.clear()
                time.sleep(1)
                for k, v in sessions.items():
                    print(f"{inet_ntop(AF_INET, pack('I', k.saddr))}:{k.sport} -> {inet_ntop(AF_INET, pack('I', k.daddr))}:{k.dport} {k.protocol}")
                for k, v in pktcnt.items():
                    print(f"Packet rate: {v.value}")
            except KeyboardInterrupt:
                break
    finally:
        if "idx" in locals():
            ipr.tc("del", "clsact", idx)
