// bpf/netmon.c
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

// Map to track socket -> PID mapping (LRU to handle high volume)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct sock_info);
} sock_info SEC(".maps");

// Active connection tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_tuple);
    __type(value, struct conn_stats);
} active_connections SEC(".maps");

// Track socket creation via cgroup hook
SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk) {
    struct sock_info info = {};
    
    // Get process info
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            info.ppid = BPF_CORE_READ(parent, tgid);
            // Use bpf_probe_read_kernel_str instead of bpf_probe_read_str
            bpf_probe_read_kernel_str(&info.parent_comm, sizeof(info.parent_comm), 
                                    BPF_CORE_READ(parent, comm));
        }
    }
    
    // Store in map using socket cookie as key
    __u64 cookie = bpf_get_socket_cookie((void *)sk);
    if (cookie) {
        bpf_map_update_elem(&sock_info, &cookie, &info, BPF_ANY);
    }
    
    return ALLOW_SK;
}

static void update_conn_stats(struct conn_tuple *tuple, __u32 bytes_in, __u32 bytes_out) {
    struct conn_stats *stats;
    stats = bpf_map_lookup_elem(&active_connections, tuple);
    
    if (stats) {
        // Update existing connection
        __sync_fetch_and_add(&stats->bytes_in, bytes_in);
        __sync_fetch_and_add(&stats->bytes_out, bytes_out);
    } else {
        // New connection
        struct conn_stats new_stats = {
            .start_time = bpf_ktime_get_ns(),
            .bytes_in = bytes_in,
            .bytes_out = bytes_out
        };
        bpf_map_update_elem(&active_connections, tuple, &new_stats, BPF_ANY);
    }
}

// Process CGroup skb to extract connection info
static inline void process_cgroup_skb(struct __sk_buff *skb, __u8 direction) {
    // Get socket cookie
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    // Look up process info
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    if (!info) {
        return;
    }
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse IPv4 packet
    if (bpf_ntohs(skb->protocol) != 0x0800) { // ETH_P_IP
        return;
    }
    
    struct iphdr *ip = data;
    if ((void*)(ip + 1) > data_end) {
        return;
    }
    
    // Extract IP addresses
    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u32 bytes = skb->len;
    
    // Extract protocol-specific info
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)(ip + 1);
        if ((void*)(tcp + 1) > data_end) {
            return;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        
        // Create connection tuple
        struct conn_tuple tuple = {
            .pid = info->pid,
            .protocol = IPPROTO_TCP,
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port
        };
        
        // Update stats based on direction
        if (direction == FLOW_INGRESS) {
            update_conn_stats(&tuple, bytes, 0);
        } else {
            update_conn_stats(&tuple, 0, bytes);
        }
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)(ip + 1);
        if ((void*)(udp + 1) > data_end) {
            return;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        
        // Similar stats tracking for UDP
        struct conn_tuple tuple = {
            .pid = info->pid,
            .protocol = IPPROTO_UDP,
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port
        };
        
        if (direction == FLOW_INGRESS) {
            update_conn_stats(&tuple, bytes, 0);
        } else {
            update_conn_stats(&tuple, 0, bytes);
        }
    }
    
    // Create network event
    struct network_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    
    // Initialize event
    __builtin_memset(evt, 0, sizeof(*evt));
    
    // Fill header information
    evt->event_type = EVENT_NET_CONNECT;
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = info->pid;
    evt->ppid = info->ppid;
    __builtin_memcpy(&evt->comm, info->comm, sizeof(evt->comm));
    __builtin_memcpy(&evt->parent_comm, info->parent_comm, sizeof(evt->parent_comm));
    
    // Fill network details
    evt->saddr = src_ip;
    evt->daddr = dst_ip;
    evt->sport = src_port;
    evt->dport = dst_port;
    evt->protocol = ip->protocol;
    evt->flow_direction = direction;
    evt->bytes = bytes;
    
    bpf_ringbuf_submit(evt, 0);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    process_cgroup_skb(skb, FLOW_INGRESS);
    return ALLOW_PKT;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    process_cgroup_skb(skb, FLOW_EGRESS);
    return ALLOW_PKT;
}

char LICENSE[] SEC("license") = "GPL";
