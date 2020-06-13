#!/usr/bin/env python3
import sys, json, time, traceback, struct
from scapy.all import *
import ctypes as ct
import threading
from queue import Queue
import datetime
from bcc import BPF

def ip_to_string(ip):
    return ".".join(map(lambda n: str(ip>>n & 0xff), [24,16,8,0]))

bpf_prog = r'''
#include <linux/sched.h>
#include <net/inet_sock.h>

struct data_t {
  u32 pid;
  u16 sport;
  u16 dport;
};
BPF_PERF_OUTPUT(events);

int udp_v4(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
  struct data_t data = {};

  data.pid = bpf_get_current_pid_tgid() >> 32;

  if(bpf_ntohs(sk->sk_dport) != 53) {
    return 0;
  }
  data.sport = bpf_ntohs(((struct inet_sock*) sk)->inet_sport);
  data.dport = bpf_ntohs(((struct inet_sock*) sk)->inet_dport);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}
'''

TASK_COMM_LEN = 16    # linux/sched.h

class Data(ct.Structure):
    _fields_ = [
      ('pid', ct.c_uint),
      ('sport', ct.c_ushort),
      ('dport', ct.c_ushort),
    ]

DNS_Q = Queue(10)

def get_cmd_for(pid):
  try:
    with open(f'/proc/{pid}/cmdline') as f:
      return f.read().replace('\0', ' ').rstrip()
  except OSError:
    return 'unknown'

def process_data():
  while True:
    dport, sport, dns = DNS_Q.get()
    m = [x.pid for x in RING if x.sport == sport]
    if m:
      pid = m[0]
      cmd = get_cmd_for(pid)
    else:
      pid = 0
      cmd = '(unknown)'
    dt = datetime.datetime.now()
    J = {
        'ts': int(time.time()),
        'pid': int(pid),
        'cmd': cmd,
        'sport': int(sport),
        'dport': int(dport),
        'q': '{}'.format(dns.q),
    }
    print(json.dumps(J))
    #f'{dt} {pid:5} {cmd[:50]:50} {dns.q}')

RING_pos = 0
RING_size = 30
E = Data()
RING = [E] * RING_size
del E

def on_data(cpu, data, size):
  global RING_pos
  event = ct.cast(data, ct.POINTER(Data)).contents
  RING[RING_pos] = event
  RING_pos = (RING_pos + 1) % RING_size
#  print('on_data...cpu={}, data={}, size={}, event={}, pos={}, '.format(cpu,data,size,event, RING_pos))

def main():
  b = BPF(text=bpf_prog)
  b.attach_kprobe(event='udp_sendmsg', fn_name='udp_v4')

  b['events'].open_perf_buffer(on_data)

  th = threading.Thread(target=process_data, daemon=True)
  th.start()

  th = threading.Thread(target=ipt_main, daemon=True)
  th.start()

  print('DNS snoop started..')

  while True:
    b.kprobe_poll()

from dnslib import DNSRecord
from netfilterqueue import NetfilterQueue

def handle_packet(pkt):
  try:
    payload_len = pkt.get_payload_len()
    ip = pkt.get_payload()
    PKT = IP(ip)

    sport = int.from_bytes(ip[20:22], 'big')
    src_ip = struct.unpack('>I', ip[12:16])[0]

#    dport = int.from_bytes(ip[20:22], 'big')

    # 28 = 20B IPv4 header + 8B UDP header
    dns = DNSRecord.parse(ip[28:])
    dport = 4
    q = PKT[DNSQR].qname
    qt = PKT[DNSQR].qtype
    an = 2 #PKT[DNSQR].an
    an_qty = 3 #PKT[DNSQR].ancount
    print('dport={}, sport={}, payload_len={}, '.format(dport,sport,payload_len))
    print('tcp={},udp={},dns_rr={},qr={},q={},qt={},an={},an_qty={},'.format(
        PKT.haslayer(TCP),
        PKT.haslayer(UDP),
        PKT.haslayer(DNSRR),
        False,
        q,qt,an,an_qty,
    ))
#    if PKT.haslayer(UDP):
#        dport = pkt.getlayer(UDP).dport
    DNS_Q.put((dport, sport, dns))
  finally:
    pkt.accept()

def ipt_main():
  nfqueue = NetfilterQueue()
  nfqueue.bind(2, handle_packet)
  nfqueue.run()

if __name__ == '__main__':
  main()
