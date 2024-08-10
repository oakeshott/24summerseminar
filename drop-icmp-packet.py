#!/usr/bin/python3
# -*- coding: utf-8 -*-

from bcc import BPF
from bcc import lib, table
from pyroute2 import IPRoute
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
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

BPF_HASH(pktcnt, int, u32);

int drop_icmp_packet(struct __sk_buff *skb) {
  int64_t ts = bpf_ktime_get_ns();
  void* data_end = (void*)(long)skb->data_end;
  void* data = (void*)(long)skb->data;

  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  struct iphdr *iph;

  int protocol = 0;

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
    protocol = iph->protocol;

    switch(protocol) {
      case IPPROTO_ICMP: goto icmp;
      default: goto EOP;
    }
  }

  icmp: {
    u32 value = 0, *vp;
    vp = pktcnt.lookup_or_init(&protocol, &value);
    *vp += 1;
    return TC_ACT_SHOT;
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
    device = sys.argv[1]

    INGRESS = "ffff:ffff2"
    EGRESS = "ffff:ffff3"

    ret = []
    try:
        b = BPF(text=bpf_text, debug=0)
        fn = b.load_func("drop_icmp_packet", BPF.SCHED_CLS)
        idx = ipr.link_lookup(ifname=device)[0]
        ipr.tc("add", "clsact", idx);
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=INGRESS, classid=1, direct_action=True)

        for i in range(0, lib.bpf_num_functions(b.module)):
            func_name = lib.bpf_function_name(b.module, i)
            print(func_name, lib.bpf_function_size(b.module, func_name))

        pktcnt   = b.get_table("pktcnt")

        while True:
            try:
                time.sleep(1)
                for k, v in pktcnt.items():
                    print("# dropped packets: {v.value}")
            except KeyboardInterrupt:
                break
    finally:
        if "idx" in locals():
            ipr.tc("del", "clsact", idx)
