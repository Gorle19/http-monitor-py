#!/usr/bin/env python3

from struct import unpack
from bcc import BPF
from socket import if_indextoname

import datetime

C_BPF_KPROBE = """
#include <net/sock.h>

//the structure that will be used as a key for eBPF table 'proc_ports':
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// the structure which will be stored in the eBPF table 'proc_ports', contains information about the process:
struct port_val {
    u32 ifindex;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[64];
};

// Public (accessible from other eBPF programs) eBPF table information about the process is written to.
// It is read when a packet appears on the socket:
BPF_TABLE_PUBLIC("hash", struct port_key, struct port_val, proc_ports, 20480);


int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // preparing the data:
    u32 saddr = sk->sk_rcv_saddr;
    u32 daddr = sk->sk_daddr;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    // Forming the structure-key.
    struct port_key key = {.proto = 6};
    key.saddr = htonl(saddr);
    key.daddr = htonl(daddr);

    key.sport = sport;
    key.dport = htons(dport);

    //Form a structure with socket properties:
    struct port_val val = {};
    val.pid = pid_tgid >> 32;
    val.tgid = (u32)pid_tgid;
    val.uid = (u32)uid_gid;
    val.gid = uid_gid >> 32;
    bpf_get_current_comm(val.comm, 64);

    //Write the value into the eBPF table:
    proc_ports.update(&key, &val);
    return 0;
}
"""

BPF_SOCK_TEXT = r'''
#include <net/sock.h>
#include <bcc/proto.h>

//the structure that will be used as a key for eBPF table 'proc_ports':
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// the structure which will be stored in the eBPF table 'proc_ports', contains information about the process:
struct port_val {
    u32 ifindex;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[64];
};

// eBPF table from which information about the process is extracted.
// Filled when calling kernel functions udp_sendmsg()/tcp_sendmsg():
BPF_TABLE("extern", struct port_key, struct port_val, proc_ports, 20480);

// table for transmitting data to the user space:
BPF_PERF_OUTPUT(tcp_events);

// Among the data passing through the socket collects useful information about the process:
int tcp_matching(struct __sk_buff *skb) {
    u8 *cursor = 0;

    // check the IP protocol:
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    if (ethernet->type == ETH_P_IP) {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

        u8 proto;
        u16 sport;
        u16 dport;

        //check if the packet is a TCP connection (proto 6)
       if (ip->nextp == IPPROTO_TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

            // We don't need packets where no data is transmitted:
            if (!tcp->flag_psh) {
                return 0;
            }

            proto = 6;

            // We get the port data:
            sport = tcp->src_port;
            dport = tcp->dst_port;
        } else {
            return 0;
        }

        // we form the structure-key:
        struct port_key key = {};
        key.proto = proto;
        if (skb->ingress_ifindex == 0) {
            key.saddr = ip->src;
            key.daddr = ip->dst;
            key.sport = sport;
            key.dport = dport;
        } else {
            key.saddr = ip->dst;
            key.daddr = ip->src;
            key.sport = dport;
            key.dport = sport;
        }

        // By the key we are looking for a value in the eBPF table:
        struct port_val *p_val;
        p_val = proc_ports.lookup(&key);

        // If the value is not found, it means that we do not have information about the process, so there is no point in continuing:
        if (!p_val) {
            return 0;
        }

        // network device index:
        p_val->ifindex = skb->ifindex;

        // pass the structure with the process information along with skb->len bytes sent to the socket:
        tcp_events.perf_submit_skb(skb, skb->len, p_val, sizeof(struct port_val));
        
        return 0;
    }

    return 0;
}
'''

def print_data(cpu, data, size):
    import ctypes as ct
    class SkbEvent(ct.Structure):
        _fields_ = [
            ("ifindex", ct.c_uint32),
            ("pid", ct.c_uint32),
            ("tgid", ct.c_uint32),
            ("uid", ct.c_uint32),
            ("gid", ct.c_uint32),
            ("comm", ct.c_char * 64),
            ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 5) - ct.sizeof(ct.c_char * 64)))
        ]
    # We get our 'port_val' structure and also the packet itself in the 'raw' field:
    sk = ct.cast(data, ct.POINTER(SkbEvent)).contents


    # eBPF operates on thread names.
    # Sometimes they are the same as the process names, but often they are not.
    # So we try to get the process name by its PID:
    try:
        with open(f'/proc/{sk.pid}/comm', 'r') as proc_comm:


            proc_name = proc_comm.read().rstrip()
    except:
        proc_name = sk.comm.decode()

    # Get the name of the network interface by index:
    ifname = if_indextoname(sk.ifindex)

    # The length of the Ethernet frame header is 14 bytes:
    ip_packet = bytes(sk.raw[14:])

    # The length of the IP packet header is not fixed due to the arbitrary
    # number of parameters.
    # Of all the possible IP header we are only interested in 20 bytes:
    (length, _, _, _, _, proto, _, saddr, daddr) = unpack('!BBHLBBHLL', ip_packet[:20])
    # The direct length is written in the second half of the first byte (0b00001111 = 15):
    len_iph = length & 15
    # Length is written in 32-bit words, convert it to bytes:
    len_iph = len_iph * 4
    # Convert addresses from numbers to IPs:
    saddr = ".".join(map(str, [saddr >> 24 & 0xff, saddr >> 16 & 0xff, saddr >> 8 & 0xff, saddr & 0xff]))
    daddr = ".".join(map(str, [daddr >> 24 & 0xff, daddr >> 16 & 0xff, daddr >> 8 & 0xff, daddr & 0xff]))

    # HTTP works over TCP
    if proto == 6:
        proto = "TCP"
        tcp_packet = ip_packet[len_iph:]
        # The length of the TCP packet header is also not fixed due to the optional options.
        # Of the entire TCP header we are only interested in the data up to the 13th byte
        # (header length):
        (sport, dport, _, length) = unpack('!HHQB', tcp_packet[:13])
        # The direct length is written in the first half (4 bits):
        len_tcph = length >> 4
        # Length is written in 32-bit words, converted to bytes:
        len_tcph = len_tcph * 4
        # Save pachet payload
        pkt = tcp_packet[len_tcph:]
    # other protocols are not handled:
    else:
        return

    # extract packet timestamp
    ts = datetime.datetime.now().replace(microsecond=0)
   
    # Check HTTP fields (this monitor displays only HTTP packets)
    # Note: the payload is saved in bytes object(b''), so we need to check the decimal ASCII code of the letters

    # Check GET Request (71=G, 69=E, 84=T)
    if pkt[0]==71 and pkt[1]==69 and pkt[2]==84:
        payload = "HTTP GET Request"
        print(f'{ts} \t {ifname} \t\t {proto} \t\t {saddr} \t {sport} \t\t {daddr} \t\t {dport} \t\t\t {payload}')

    # Check POST Request
    if pkt[0]==80 and pkt[1]==79 and pkt[1]==83 and pkt[2]==84:
        payload = "HTTP POST Request"
        print(f'{ts} \t {ifname} \t\t {proto} \t\t {saddr} \t {sport} \t\t {daddr} \t\t {dport} \t\t\t {payload}')

    # Check PUT Request
    if pkt[0]==80 and pkt[1]==85 and pkt[2]==84:
        payload = "HTTP PUT Request"
        print(f'{ts} \t {ifname} \t\t {proto} \t\t {saddr} \t {sport} \t\t {daddr} \t\t {dport} \t\t\t {payload}')
    
    # Check DELETE Request
    if pkt[0]==68 and pkt[1]==69 and pkt[2]==76 and pkt[3]==69 and pkt[2]==84 and pkt[5]==69:
        payload = "HTTP DELETE Request"
        print(f'{ts} \t {ifname} \t\t {proto} \t\t {saddr} \t {sport} \t\t {daddr} \t\t {dport} \t\t\t {payload}')

    # Chech HTTP Response
    if pkt[0]==72 and pkt[1]==84 and pkt[2]==84 and pkt[3]==80:
        payload = "HTTP Response"
        print(f'{ts} \t {ifname} \t\t {proto} \t\t {saddr} \t {sport} \t\t {daddr} \t\t {dport} \t\t\t {payload}')
    

    
####
# Main

# BPF initialization:
bpf_kprobe = BPF(text=C_BPF_KPROBE)

bpf_sock = BPF(text=BPF_SOCK_TEXT)

# Attach TCP kprobe:
bpf_kprobe.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")

# Socket:
function_tcp_matching = bpf_sock.load_func("tcp_matching", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_tcp_matching, '')

print('The program is running. Press Ctrl-C to stop. \n')

print("TIME \t\t\t INTERFACE \t PROTOCOL \t SOURCE IP \t SOURCE PORT \t DESTINATION IP \t DESTINATION PORT \t PAYLOAD")

bpf_sock["tcp_events"].open_perf_buffer(print_data)

while True:
    try:
        bpf_sock.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()