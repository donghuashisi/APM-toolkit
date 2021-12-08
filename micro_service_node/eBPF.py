# from typing import Optional

# from fastapi import FastAPI

import socket


# app = FastAPI()

from bcc import BPF

import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
import time


bpf_insert_code = """
# include <uapi/linux/ptrace.h>
# include <net/sock.h>
# include <net/tcp.h>
# include <bcc/proto.h>

# define RETRANSMIT  1
# define TLP         2

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
	u32 pid;
	u64 ip;
	u32 seq;
	u32 saddr;
	u32 daddr;
	u16 lport;
	u16 dport;
	u64 state;
	u64 type;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
	u32 pid;
	u32 seq;
	u64 ip;
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	u16 lport;
	u16 dport;
	u64 state;
	u64 type;
};
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
	u32 saddr;
	u32 daddr;
	u16 lport;
	u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	u16 lport;
	u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
	struct tcp_skb_cb *tcb;
	u32 seq;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	const struct sock *skp = (const struct sock *)args->skaddr;
	const struct sk_buff *skb = (const struct sk_buff *)args->skbaddr;
	u16 lport = args->sport;
	u16 dport = args->dport;
	char state = skp->__sk_common.skc_state;
	u16 family = skp->__sk_common.skc_family;

	seq = 0;
	if (skb) {
		/* macro TCP_SKB_CB from net/tcp.h */
		tcb = ((struct tcp_skb_cb *)&((skb)->cb[0]));
		seq = tcb->seq;
	}



	if (family == AF_INET) {

			   struct ipv4_flow_key_t flow_key = {};
			   __builtin_memcpy(&flow_key.saddr, args->saddr, sizeof(flow_key.saddr));
			   __builtin_memcpy(&flow_key.daddr, args->daddr, sizeof(flow_key.daddr));
			   flow_key.lport = lport;
			   flow_key.dport = dport;
			   ipv4_count.increment(flow_key);

	} else if (family == AF_INET6) {

			   struct ipv6_flow_key_t flow_key = {};
			   __builtin_memcpy(&flow_key.saddr, args->saddr_v6, sizeof(flow_key.saddr));
			   __builtin_memcpy(&flow_key.daddr, args->daddr_v6, sizeof(flow_key.daddr));
			   flow_key.lport = lport;
			   flow_key.dport = dport;
			   ipv6_count.increment(flow_key);

	}
	return 0;
}
"""

# initialize BPF


def attach_bpf(during=60):
    my_bpf = BPF(text=bpf_insert_code)
    if not BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
        my_bpf.attach_kprobe(event="tcp_retransmit_skb",
                             fn_name="trace_retransmit")
    time.sleep(int(during))
    counts_tab = my_bpf.get_table("ipv4_count")
    find_entry = False
    entries = []
    for k, v in counts_tab.items():
        find_entry = True
        depict_key = ""
        ep_fmt = "[%s]#%d"
        depict_key = "%-20s <-> %-20s" % (ep_fmt % (inet_ntop(AF_INET, pack('I', k.saddr)), k.lport),
                                          ep_fmt % (inet_ntop(AF_INET, pack('I', k.daddr)), k.dport))

        print("%s %10d" % (depict_key, v.value))
        entries.append({"sip": inet_ntop(AF_INET, pack('I', k.saddr)), "dip": inet_ntop(AF_INET, pack('I', k.daddr)),
                        "sport": k.lport, "dport": k.dport, "num": v.value})

    # print("sish     " + format(entries))
    return entries
    # if find_entry == True:
    #     print("sish     " + format(entries))
    #     return entries
    # else:
    #     return None

if __name__ == '__main__':
    import subprocess
    sub_process_res = subprocess.Popen('/home/sish/sdwan-perf/build/sdwan-perf_linux  -role client -server 192.168.10.3  -num 1 -port 80 -size 10 -reqs 1',
                                       shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(format(attach_bpf(30)))
# @app.get("/")
# def read_root():
#     res = attach_bpf()
#     return res


# @app.get("/items/{item_id}")
# def read_item(item_id: int, q: Optional[str] = None):
#     return {"item_id": item_id, "q": q}


# @app.get("/items/start_bcc")
# def read_item():
#     return {"item_id": item_id, "q": q}
