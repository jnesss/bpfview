// bpf/dnsmon.c - Simplified DNS monitoring with raw data capture
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
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct sock_info);
} sock_info SEC(".maps");

#define DNS_PORT 53
#define MAX_DNS_DATA 512 // Typical DNS UDP packet size limit

// Updated sock_create function to get parent info
SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk) {
    struct sock_info info = {};
    
    // Get process info
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // Get parent info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            info.ppid = BPF_CORE_READ(parent, tgid);
            bpf_probe_read_kernel(&info.parent_comm, sizeof(info.parent_comm), 
                                BPF_CORE_READ(parent, comm));
        }
    }
    
    // Store in map
    __u64 cookie = bpf_get_socket_cookie((void *)sk);
    if (cookie) {
        bpf_map_update_elem(&sock_info, &cookie, &info, BPF_ANY);
    }
    
    return ALLOW_SK;
}

// Process DNS packets in skb
static inline void process_skb_dns(struct __sk_buff *skb, __u8 event_subtype) {
    __u64 cookie = bpf_get_socket_cookie(skb);
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    if (!info) {
        return;
    }
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    if (bpf_ntohs(skb->protocol) != 0x0800) {
        return;
    }
    
    struct iphdr *ip = data;
    if ((void*)(ip + 1) > data_end) {
        return;
    }
    
    if (ip->protocol != 17) {
        return;
    }
    
    __u32 ip_header_size = ip->ihl * 4;
    struct udphdr *udp = (void*)data + ip_header_size;
    if ((void*)(udp + 1) > data_end) {
        return;
    }
    
    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);
    if (src_port != 53 && dst_port != 53) {
        return;
    }

    void *dns_data = (void*)udp + sizeof(*udp);
    if (dns_data + 12 > data_end) {
        return;
    }

    // Read DNS flags carefully
    __u16 dns_flags;
    if (bpf_probe_read_kernel(&dns_flags, sizeof(dns_flags), dns_data + 2) < 0) {
        return;
    }
    dns_flags = bpf_ntohs(dns_flags);

    dns_event_t *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    
    __builtin_memset(evt, 0, sizeof(*evt));
    
    // Fill in all info including parent details
    evt->event_type = EVENT_DNS;
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = info->pid;
    evt->ppid = info->ppid;
    evt->dns_flags = dns_flags;
    evt->is_response = (dns_flags & 0x8000) ? 1 : 0;
    __builtin_memcpy(&evt->comm, info->comm, sizeof(evt->comm));
    __builtin_memcpy(&evt->parent_comm, info->parent_comm, sizeof(evt->parent_comm));
    
    evt->saddr = ip->saddr;
    evt->daddr = ip->daddr;
    evt->sport = src_port;
    evt->dport = dst_port;
    
    bpf_probe_read_kernel(&evt->raw_data, sizeof(evt->raw_data), dns_data);
    evt->raw_len = sizeof(evt->raw_data);
    
    bpf_ringbuf_submit(evt, 0);
}


// Ingress traffic monitoring
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    process_skb_dns(skb, 1); // Responses typically come in
    return ALLOW_PKT;
}

// Egress traffic monitoring
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    process_skb_dns(skb, 0); // Queries typically go out
    return ALLOW_PKT;
}

char LICENSE[] SEC("license") = "GPL";
