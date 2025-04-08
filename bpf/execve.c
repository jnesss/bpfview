// bpf/execve.c - Version 6: Simplified but effective argument capture
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

// Map to store command lines by PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct cmd_line);
} cmdlines SEC(".maps");

// Handle process execution
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space in the ringbuffer
    struct process_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    
    // Fill in basic info
    evt->event_type = EVENT_PROCESS_EXEC;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    evt->pid = pid;
    evt->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Get user/group ID
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid & 0xffffffff;
    evt->gid = uid_gid >> 32;
    
    // Default values
    evt->ppid = 0;
    evt->exit_code = 0;
    evt->flags = 0;
    
    // Get executable path from first argument
    const char *filename = (const char*)(ctx->args[0]);
    if (filename) {
        bpf_probe_read_user_str(&evt->exe_path, sizeof(evt->exe_path), filename);
    }
    
    // Get parent process information
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        // Get parent PID
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            evt->ppid = BPF_CORE_READ(parent, tgid);
            bpf_probe_read_str(&evt->parent_comm, sizeof(evt->parent_comm), 
                               BPF_CORE_READ(parent, comm));
        }
    }
    
    // Submit the event
    bpf_ringbuf_submit(evt, 0);
    
    // Command line capture - simplified approach
    struct cmd_line cmd = {0};
    const char **args = (const char **)(ctx->args[1]);
    if (!args)
        return 0;
    
    // Get arg0 (exec path) - use first 40 bytes
    const char *arg0 = NULL;
    bpf_probe_read(&arg0, sizeof(arg0), &args[0]);
    if (arg0) {
        bpf_probe_read_user_str(cmd.args, 40, arg0);
    }
    
    // Find end of arg0
    int pos = 0;
    for (; pos < 40 && cmd.args[pos]; pos++) {}
    
    // If we have room, add arg1
    if (pos < 120) {
        const char *arg1 = NULL;
        bpf_probe_read(&arg1, sizeof(arg1), &args[1]);
        if (arg1) {
            // Add space separator
            if (pos > 0) {
                cmd.args[pos++] = ' ';
            }
            // Read arg1 (up to 40 bytes)
            char arg1_buf[40] = {0};
            bpf_probe_read_user_str(arg1_buf, sizeof(arg1_buf), arg1);
            
            // Copy to cmd.args
            for (int i = 0; i < 40 && arg1_buf[i] && pos < 120; i++) {
                cmd.args[pos++] = arg1_buf[i];
            }
        }
    }
    
    // If we have room, add arg2
    if (pos < 120) {
        const char *arg2 = NULL;
        bpf_probe_read(&arg2, sizeof(arg2), &args[2]);
        if (arg2) {
            // Add space separator
            if (pos > 0) {
                cmd.args[pos++] = ' ';
            }
            // Read arg2 (up to 30 bytes)
            char arg2_buf[30] = {0};
            bpf_probe_read_user_str(arg2_buf, sizeof(arg2_buf), arg2);
            
            // Copy to cmd.args
            for (int i = 0; i < 30 && arg2_buf[i] && pos < 120; i++) {
                cmd.args[pos++] = arg2_buf[i];
            }
        }
    }
    
    // Ensure null termination
    if (pos < 127) {
        cmd.args[pos] = '\0';
    }
    
    // Store in map
    bpf_map_update_elem(&cmdlines, &pid, &cmd, BPF_ANY);
    
    return 0;
}

// Handle process exit
SEC("tracepoint/sched/sched_process_exit") 
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    // Reserve space in the ringbuffer
    struct process_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    
    // Fill in basic info
    evt->event_type = EVENT_PROCESS_EXIT;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    evt->pid = pid;
    evt->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Get user/group ID
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid & 0xffffffff;
    evt->gid = uid_gid >> 32;
    
    // Default values
    evt->ppid = 0;
    evt->exit_code = 0;
    evt->flags = 0;
    
    // Get exit code from task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        evt->exit_code = BPF_CORE_READ(task, exit_code) >> 8;
    }
    
    // Submit the event
    bpf_ringbuf_submit(evt, 0);
    
    // Clean up command line from map
    bpf_map_delete_elem(&cmdlines, &pid);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
