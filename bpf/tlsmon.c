#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

// Ringbuffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Map to track socket -> PID mapping
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct sock_info);
} sock_info SEC(".maps");

// Per-CPU array for temporary buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tls_event);
} heap SEC(".maps");

// Track socket creation via cgroup hook
SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk) {
    struct sock_info info = {};
        
    // Get process info
    info.pid = bpf_get_current_pid_tgid() >> 32;
    info.ppid = 0;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    // Get parent process info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            info.ppid = BPF_CORE_READ(parent, tgid);
            bpf_probe_read_kernel_str(&info.parent_comm, sizeof(info.parent_comm), 
                                    BPF_CORE_READ(parent, comm));
        }
    }
    
    // Store in map using socket cookie as key
    __u64 cookie = bpf_get_socket_cookie((void *)sk);
    if (cookie) {
        bpf_map_update_elem(&sock_info, &cookie, &info, BPF_ANY);
    }
    
    return 1;
}

// Function to process TCP packets that might contain TLS records
static inline void process_tcp_tls(struct __sk_buff *skb, struct sock_info *info) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    // Basic IP header checks
    struct iphdr *ip = data;
    if ((void*)(ip + 1) > data_end)
        return;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return;

    __u32 ip_header_size = ip->ihl * 4;
    if (ip_header_size < 20 || ip_header_size > 60)
        return;
    
    struct tcphdr *tcp = (void*)ip + ip_header_size;
    if ((void*)(tcp + 1) > data_end)
        return;

    __u32 tcp_header_size = tcp->doff * 4;
    if (tcp_header_size < 20 || tcp_header_size > 60)
        return;
    
    __u32 payload_offset = ip_header_size + tcp_header_size;
    if (payload_offset + 5 > skb->len)
        return;
    
    // Read first bytes of potential TLS header
    unsigned char tls_header[8];
    if (bpf_skb_load_bytes(skb, payload_offset, tls_header, sizeof(tls_header)) < 0)
        return;
    
    // Check for handshake (type 0x16) and Client Hello (type 0x01)
    if (tls_header[0] != 0x16 || tls_header[5] != 0x01)
        return;

    // Extract handshake message length from handshake header
    // This is a 3-byte field at offset 6, 7, 8 in the handshake record
    // payload_offset + 6, 7, 8
    unsigned char length_bytes[3];
    if (bpf_skb_load_bytes(skb, payload_offset + 6, length_bytes, 3) < 0)
        return;
        
    // TLS version check
    if (tls_header[1] != 0x03 || tls_header[2] < 0x01 || tls_header[2] > 0x04)
        return;

    // Get heap buffer
    __u32 zero = 0;
    struct tls_event *event = bpf_map_lookup_elem(&heap, &zero);
    if (!event)
        return;
    
    // Initialize event
    __builtin_memset(event, 0, sizeof(*event));
    
    event->event_type = EVENT_TLS;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = info->pid;
    event->ppid = info->ppid;
    __builtin_memcpy(&event->comm, info->comm, sizeof(event->comm));
    __builtin_memcpy(&event->parent_comm, info->parent_comm, sizeof(event->parent_comm));
    
    // Fill in IP and port information
    event->saddr_a = (ip->saddr) & 0xFF;
    event->saddr_b = (ip->saddr >> 8) & 0xFF;
    event->saddr_c = (ip->saddr >> 16) & 0xFF;
    event->saddr_d = (ip->saddr >> 24) & 0xFF;
    
    event->daddr_a = (ip->daddr) & 0xFF;
    event->daddr_b = (ip->daddr >> 8) & 0xFF;
    event->daddr_c = (ip->daddr >> 16) & 0xFF;
    event->daddr_d = (ip->daddr >> 24) & 0xFF;
    
    event->sport = bpf_ntohs(tcp->source);
    event->dport = bpf_ntohs(tcp->dest);
    
    event->version = ((__u32)tls_header[1] << 8) | tls_header[2];
    
    // Convert 3 bytes to a 24-bit length (big-endian)
    event->handshake_length = (length_bytes[0] << 16) | (length_bytes[1] << 8) | length_bytes[2];
    
    // Read payload into event data buffer
    event->data_len = 0;
    if (payload_offset + MAX_TLS_DATA <= skb->len) {
        if (bpf_skb_load_bytes(skb, payload_offset, event->data, MAX_TLS_DATA) == 0) {
            event->data_len = MAX_TLS_DATA;
        }
    }

    // Reserve and copy to final event buffer
    struct tls_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return;

    __builtin_memcpy(evt, event, sizeof(*evt));
    bpf_ringbuf_submit(evt, 0);
}

// Ingress processing hook
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    __u64 cookie = bpf_get_socket_cookie(skb);
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    
    struct sock_info default_info = {};
    if (!info) {
        info = &default_info;
    }
    
    process_tcp_tls(skb, info);
    return 1;
}

// Egress processing hook
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    __u64 cookie = bpf_get_socket_cookie(skb);
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    
    struct sock_info default_info = {};
    if (!info) {
        info = &default_info;
    }
    
    process_tcp_tls(skb, info);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
