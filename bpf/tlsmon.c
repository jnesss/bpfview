#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#ifndef ETH_P_IP
#define ETH_P_IP    0x0800  // Internet Protocol packet
#endif

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        unsigned char data[MAX_TLS_DATA];
        __u32 len;
    });
} staging SEC(".maps");


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
    unsigned char length_bytes[3];
    if (bpf_skb_load_bytes(skb, payload_offset + 6, length_bytes, 3) < 0)
        return;
        
    __u32 tls_record_len = (tls_header[3] << 8) | tls_header[4];
    __u32 handshake_len = (length_bytes[0] << 16) | (length_bytes[1] << 8) | length_bytes[2];

    bpf_printk("TLS Record len: %u, Handshake len: %u\n", tls_record_len, handshake_len);
    
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
    event->saddr[0] = (ip->saddr) & 0xFF;
    event->saddr[1] = (ip->saddr >> 8) & 0xFF;
    event->saddr[2] = (ip->saddr >> 16) & 0xFF;
    event->saddr[3] = (ip->saddr >> 24) & 0xFF;
    
    event->daddr[0] = (ip->daddr) & 0xFF;
    event->daddr[1] = (ip->daddr >> 8) & 0xFF;
    event->daddr[2] = (ip->daddr >> 16) & 0xFF;
    event->daddr[3] = (ip->daddr >> 24) & 0xFF;
    
    event->sport = bpf_ntohs(tcp->source);
    event->dport = bpf_ntohs(tcp->dest);
    
    // Set protocol
    event->ip_version = 4;
    event->protocol = IPPROTO_TCP;
    
    event->version = ((__u32)tls_header[1] << 8) | tls_header[2];
    
    // Convert 3 bytes to a 24-bit length (big-endian)
    event->handshake_length = (length_bytes[0] << 16) | (length_bytes[1] << 8) | length_bytes[2];
    
    // Read payload into event data buffer
    event->data_len = 0;
    __u32 zero1 = 0;
    struct {
        unsigned char data[MAX_TLS_DATA];
        __u32 len;
    } *stage = bpf_map_lookup_elem(&staging, &zero1);
    if (!stage)
        return;

    #define CHUNK_SIZE 64

    // try to copy max 512 bytes in 64 byte chunks 
    //  manually unrolled to satisfy verifier, ick i know
    if (payload_offset < skb->len) {
        // Chunk 1
        if (bpf_skb_load_bytes(skb, payload_offset, stage->data, CHUNK_SIZE) == 0) {
            #pragma unroll
            for (int i = 0; i < CHUNK_SIZE; i++) {
                event->data[i] = stage->data[i];
            }
            event->data_len = CHUNK_SIZE;

            // Chunk 2
            if (payload_offset + CHUNK_SIZE < skb->len &&
                bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE, stage->data, CHUNK_SIZE) == 0) {
                #pragma unroll
                for (int i = 0; i < CHUNK_SIZE; i++) {
                    event->data[i + CHUNK_SIZE] = stage->data[i];
                }
                event->data_len = CHUNK_SIZE * 2;

                // Chunk 3
                if (payload_offset + CHUNK_SIZE * 2 < skb->len &&
                    bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 2, stage->data, CHUNK_SIZE) == 0) {
                    #pragma unroll
                    for (int i = 0; i < CHUNK_SIZE; i++) {
                        event->data[i + CHUNK_SIZE * 2] = stage->data[i];
                    }
                    event->data_len = CHUNK_SIZE * 3;

                    // Chunk 4
                    if (payload_offset + CHUNK_SIZE * 3 < skb->len &&
                        bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 3, stage->data, CHUNK_SIZE) == 0) {
                        #pragma unroll
                        for (int i = 0; i < CHUNK_SIZE; i++) {
                            event->data[i + CHUNK_SIZE * 3] = stage->data[i];
                        }
                        event->data_len = CHUNK_SIZE * 4;

                        // Chunk 5
                        if (payload_offset + CHUNK_SIZE * 4 < skb->len &&
                            bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 4, stage->data, CHUNK_SIZE) == 0) {
                            #pragma unroll
                            for (int i = 0; i < CHUNK_SIZE; i++) {
                                event->data[i + CHUNK_SIZE * 4] = stage->data[i];
                            }
                            event->data_len = CHUNK_SIZE * 5;

                            // Chunk 6
                            if (payload_offset + CHUNK_SIZE * 5 < skb->len &&
                                bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 5, stage->data, CHUNK_SIZE) == 0) {
                                #pragma unroll
                                for (int i = 0; i < CHUNK_SIZE; i++) {
                                    event->data[i + CHUNK_SIZE * 5] = stage->data[i];
                                }
                                event->data_len = CHUNK_SIZE * 6;

                                // Chunk 7
                                if (payload_offset + CHUNK_SIZE * 6 < skb->len &&
                                    bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 6, stage->data, CHUNK_SIZE) == 0) {
                                    #pragma unroll
                                    for (int i = 0; i < CHUNK_SIZE; i++) {
                                        event->data[i + CHUNK_SIZE * 6] = stage->data[i];
                                    }
                                    event->data_len = CHUNK_SIZE * 7;

                                    // Chunk 8 - this is where the original implementation ended
                                    if (payload_offset + CHUNK_SIZE * 7 < skb->len &&
                                        bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 7, stage->data, CHUNK_SIZE) == 0) {
                                        #pragma unroll
                                        for (int i = 0; i < CHUNK_SIZE; i++) {
                                            event->data[i + CHUNK_SIZE * 7] = stage->data[i];
                                        }
                                        event->data_len = CHUNK_SIZE * 8;

                                        // Chunk 9
                                        if (payload_offset + CHUNK_SIZE * 8 < skb->len &&
                                            bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 8, stage->data, CHUNK_SIZE) == 0) {
                                            #pragma unroll
                                            for (int i = 0; i < CHUNK_SIZE; i++) {
                                                event->data[i + CHUNK_SIZE * 8] = stage->data[i];
                                            }
                                            event->data_len = CHUNK_SIZE * 9;

                                            // Chunk 10
                                            if (payload_offset + CHUNK_SIZE * 9 < skb->len &&
                                                bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 9, stage->data, CHUNK_SIZE) == 0) {
                                                #pragma unroll
                                                for (int i = 0; i < CHUNK_SIZE; i++) {
                                                    event->data[i + CHUNK_SIZE * 9] = stage->data[i];
                                                }
                                                event->data_len = CHUNK_SIZE * 10;

                                                // Chunk 11
                                                if (payload_offset + CHUNK_SIZE * 10 < skb->len &&
                                                    bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 10, stage->data, CHUNK_SIZE) == 0) {
                                                    #pragma unroll
                                                    for (int i = 0; i < CHUNK_SIZE; i++) {
                                                        event->data[i + CHUNK_SIZE * 10] = stage->data[i];
                                                    }
                                                    event->data_len = CHUNK_SIZE * 11;

                                                    // Chunk 12
                                                    if (payload_offset + CHUNK_SIZE * 11 < skb->len &&
                                                        bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 11, stage->data, CHUNK_SIZE) == 0) {
                                                        #pragma unroll
                                                        for (int i = 0; i < CHUNK_SIZE; i++) {
                                                            event->data[i + CHUNK_SIZE * 11] = stage->data[i];
                                                        }
                                                        event->data_len = CHUNK_SIZE * 12;

                                                        // Chunk 13
                                                        if (payload_offset + CHUNK_SIZE * 12 < skb->len &&
                                                            bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 12, stage->data, CHUNK_SIZE) == 0) {
                                                            #pragma unroll
                                                            for (int i = 0; i < CHUNK_SIZE; i++) {
                                                                event->data[i + CHUNK_SIZE * 12] = stage->data[i];
                                                            }
                                                            event->data_len = CHUNK_SIZE * 13;

                                                            // Chunk 14
                                                            if (payload_offset + CHUNK_SIZE * 13 < skb->len &&
                                                                bpf_skb_load_bytes(skb, payload_offset + CHUNK_SIZE * 13, stage->data, CHUNK_SIZE) == 0) {
                                                                #pragma unroll
                                                                for (int i = 0; i < CHUNK_SIZE; i++) {
                                                                    event->data[i + CHUNK_SIZE * 13] = stage->data[i];
                                                                }
                                                                event->data_len = CHUNK_SIZE * 14;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Calculate start position for remaining bytes
    __u32 bytes_copied = event->data_len;
    __u32 base_offset = payload_offset + bytes_copied;

    // Try to copy a 32-byte chunk
    if (base_offset + 32 <= skb->len && bytes_copied + 32 <= MAX_TLS_DATA) {
        if (bpf_skb_load_bytes(skb, base_offset, stage->data, 32) == 0) {
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                event->data[bytes_copied + i] = stage->data[i];
            }
            bytes_copied += 32;
            base_offset += 32;
        }
    }

    // Try to copy a 16-byte chunk
    if (base_offset + 16 <= skb->len && bytes_copied + 16 <= MAX_TLS_DATA) {
        if (bpf_skb_load_bytes(skb, base_offset, stage->data, 16) == 0) {
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                event->data[bytes_copied + i] = stage->data[i];
            }
            bytes_copied += 16;
            base_offset += 16;
        }
    }

    // Try to copy an 8-byte chunk
    if (base_offset + 8 <= skb->len && bytes_copied + 8 <= MAX_TLS_DATA) {
        if (bpf_skb_load_bytes(skb, base_offset, stage->data, 8) == 0) {
            #pragma unroll
            for (int i = 0; i < 8; i++) {
                event->data[bytes_copied + i] = stage->data[i];
            }
            bytes_copied += 8;
            base_offset += 8;
        }
    }

    // Try to copy a 4-byte chunk
    if (base_offset + 4 <= skb->len && bytes_copied + 4 <= MAX_TLS_DATA) {
        if (bpf_skb_load_bytes(skb, base_offset, stage->data, 4) == 0) {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                event->data[bytes_copied + i] = stage->data[i];
            }
            bytes_copied += 4;
            base_offset += 4;
        }
    }

    // Try to copy a 2-byte chunk
    if (base_offset + 2 <= skb->len && bytes_copied + 2 <= MAX_TLS_DATA) {
        if (bpf_skb_load_bytes(skb, base_offset, stage->data, 2) == 0) {
            event->data[bytes_copied] = stage->data[0];
            event->data[bytes_copied + 1] = stage->data[1];
            bytes_copied += 2;
            base_offset += 2;
        }
    }

    // Try to copy a final byte
    if (base_offset + 1 <= skb->len && bytes_copied + 1 <= MAX_TLS_DATA) {
        unsigned char byte;
        if (bpf_skb_load_bytes(skb, base_offset, &byte, 1) == 0) {
            event->data[bytes_copied] = byte;
            bytes_copied += 1;
        }
    }

    // Update the final data length
    event->data_len = bytes_copied;
            
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
    
    // Only handle IPv4 for now
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        process_tcp_tls(skb, info);
    }
    
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
    
    // Only handle IPv4 for now
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        process_tcp_tls(skb, info);
    }
    
    return 1;
}

char LICENSE[] SEC("license") = "GPL";