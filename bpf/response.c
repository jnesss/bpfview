// bpf/response.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

// Map to track restricted processes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, pid_t);
    __type(value, struct process_restrictions);
} restricted_procs SEC(".maps");

// Ringbuffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static void emit_event(pid_t pid, __u32 action, __u32 flags) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    
    e->pid = pid;
    e->ppid = 0;
    e->action_taken = action;
    e->blocked_syscall = 0;
    e->restriction_flags = flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/bprm_check_security")
int check_exec(struct linux_binprm *bprm) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid >> 32;
    
    struct process_restrictions *restrictions = bpf_map_lookup_elem(&restricted_procs, &pid);
    if (!restrictions) {
        return 0;
    }

    if (restrictions->flags & PREVENT_CHILDREN) {
        emit_event(pid, 1, restrictions->flags);
        return -1;
    }
    
    return 0;
}

SEC("lsm/task_alloc")
int check_task_alloc(struct task_struct *task, unsigned long clone_flags) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid >> 32;

    struct process_restrictions *restrictions = bpf_map_lookup_elem(&restricted_procs, &pid);
    if (!restrictions) {
        return 0;
    }

    if (restrictions->flags & PREVENT_CHILDREN) {
        emit_event(pid, 3, restrictions->flags);  // Different event type for task_alloc
        return -1;
    }

    return 0;
}

SEC("lsm/socket_connect")
int check_connect(struct socket *sock, struct sockaddr *address, int addrlen) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid >> 32;
    
    struct process_restrictions *restrictions = bpf_map_lookup_elem(&restricted_procs, &pid);
    if (!restrictions) {
        return 0;
    }

    if (restrictions->flags & BLOCK_NETWORK) {
        emit_event(pid, 2, restrictions->flags);
        return -1;
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
