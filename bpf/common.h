#ifndef __COMMON_H
#define __COMMON_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define MAX_TLS_DATA 896 
#define MAX_ENTRIES 8192
#define ALLOW_PKT 1
#define ALLOW_SK 1

// Flow direction
#define FLOW_INGRESS 1
#define FLOW_EGRESS 2

// Event types
#define EVENT_PROCESS_EXEC 1   // Process execution
#define EVENT_PROCESS_EXIT 2   // Process exit
#define EVENT_NET_CONNECT  3   // Network connect
#define EVENT_NET_ACCEPT   4   // Network accept
#define EVENT_NET_BIND     5   // Network bind
#define EVENT_DNS          6   // DNS query or response
#define EVENT_TLS          7   // TLS handshake events
#define EVENT_PROCESS_FORK 8   // Process creation via fork/clone
#define EVENT_RESPONSE     9   // Response action taken

// DNS operation flags
#define DNS_QUERY    1   // Outbound DNS query
#define DNS_RESPONSE 2   // Inbound DNS response

// DNS constants
#define DNS_MAX_NAME_LEN 128

// TLS protocol constants
#define TLS_HANDSHAKE       22  // 0x16
#define TLS_CHANGE_CIPHER   20  // 0x14
#define TLS_ALERT          21  // 0x15
#define TLS_APPLICATION    23  // 0x17

// TLS handshake types
#define TLS_CLIENT_HELLO    1
#define TLS_SERVER_HELLO    2

#ifndef ETH_P_IP
#define ETH_P_IP    0x0800  // Internet Protocol packet
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD  // IPv6 over bluebook
#endif

// IP protocol constants (already defined in your code, but adding for completeness)
#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6  // Transmission Control Protocol
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP  17 // User Datagram Protocol
#endif


// Response action flags
#define BLOCK_NETWORK       0x1
#define PREVENT_CHILDREN    0x2

// Socket info for tracking process info
struct sock_info {
    __u32 pid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
};

// Connection tuple for tracking stats
struct conn_tuple {
    __u32 pid;
    __u8  protocol;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Stats for active connections
struct conn_stats {
    __u64 start_time;
    __u64 bytes_in;
    __u64 bytes_out;
};

// Process event structure
struct process_event {
    __u32 event_type;         
    __u32 pid;               
    __u64 timestamp;         
    char comm[TASK_COMM_LEN];
    __u32 ppid;              
    __u32 uid;              
    __u32 gid;              
    __u32 exit_code;        
    char parent_comm[TASK_COMM_LEN];
    char exe_path[64];      
    __u32 flags;           
    __u32 padding;           // ensure 8-byte alignment
} __attribute__((packed));

// Network event structure
struct network_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;              
    __u64 timestamp;
    char comm[TASK_COMM_LEN];        // 16 bytes
    char parent_comm[TASK_COMM_LEN]; // 16 bytes
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  flow_direction;
    __u32 bytes;
    __u8  tcp_flags;                 // New field for TCP flags
    __u8  padding[3];                // Adjusted padding to maintain 8-byte alignment
} __attribute__((packed));

struct dns_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    __u32 saddr;             // Single source IP
    __u32 daddr;             // Single dest IP
    __u16 sport;
    __u16 dport;
    __u8 is_response;
    __u16 dns_flags;    
    __u16 raw_len;
    unsigned char raw_data[512];
} __attribute__((packed));

typedef struct dns_event dns_event_t;

// Command line info structure - used in maps, not on stack
struct cmd_line {
    char args[128];           // Command line arguments (reduced size for BPF verifier)
};

struct tls_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    __u32 version;
    __u32 handshake_length;
    // IP version field
    __u8 ip_version;        // 4 for IPv4, 6 for IPv6
    __u8 protocol;          // Protocol (TCP, UDP, etc.)
    __u8 padding[2];        // Ensure 4-byte alignment
    // Full IPv6 address support
    __u8 saddr[16];         // Source address (also holds IPv4 in first 4 bytes)
    __u8 daddr[16];         // Destination address (also holds IPv4 in first 4 bytes)
    __u16 sport;
    __u16 dport;
    // Raw data
    __u16 data_len;
    unsigned char data[MAX_TLS_DATA];
} __attribute__((packed));

struct process_restrictions {
    __u32 flags;
    __u32 padding;
    __u64 timestamp;
} __attribute__((packed));

struct event {
    __u32 event_type;    
    __u32 pid;
    __u32 ppid; 
    char comm[16];
    __u32 action_taken;
    __u32 blocked_syscall;
    __u32 restriction_flags;
};

#endif /* __COMMON_H */
