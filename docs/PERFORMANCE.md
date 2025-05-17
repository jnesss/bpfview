# Performance Optimization Guide

BPFView provides multiple optimization options to minimize its performance impact while maintaining full visibility. This guide covers available features and common optimization scenarios.

## Core Optimization Features

### Process Information Levels
Control the amount of process metadata collected:
```bash
# Full process details (default)
bpfview --process-level full

# Basic process info with minimal /proc reads
bpfview --process-level basic 

# Kernel-only data with almost no /proc access
bpfview --process-level minimal
```

### Process Exclusion Filters
Filter out high-volume system processes:
```bash
# Exclude by command name
bpfview --exclude-comm "chronyd,bpfview"

# Exclude by executable path
bpfview --exclude-exe-path "/usr/sbin/"

# Exclude by username
bpfview --exclude-user "nobody,systemd-resolve"
```

### Network Traffic Filtering
Control network event volume:
```bash
# Exclude specific ports
bpfview --exclude-port "80,443,123"

# Combine with process exclusions
bpfview --exclude-port "80,443" --exclude-comm "chronyd"
```

### Cache Management
Control process cache size and duration:
```bash
# Limit process cache size
bpfview --process-cache-size 5000

# Set cache entry timeout
bpfview --cache-timeout 1h
```

## Common Use Cases

### 1. High-Traffic Web Server
Optimize for a busy web server environment:
```bash
# Exclude web traffic and use minimal process info
bpfview --exclude-port "80,443" \
        --process-level minimal \
        --process-cache-size 10000 \
        --cache-timeout 30m

# Focus only on non-web processes
bpfview --exclude-comm "nginx,apache2" \
        --exclude-port "80,443"
```

### 2. Development Environment
Full visibility with reasonable resource usage:
```bash
# Basic process info with generous cache
bpfview --process-level basic \
        --process-cache-size 5000 \
        --cache-timeout 1h
```

### 3. Busy DNS Server
Optimize for DNS-heavy environments:
```bash
# Exclude DNS traffic and caching daemon
bpfview --exclude-port "53" \
        --exclude-comm "named,pdns" \
        --process-level minimal
```

### 4. System Service Monitoring
Focus on specific system services:
```bash
# Monitor only specific processes
bpfview --comm "postgres,redis" \
        --exclude-comm "chronyd,systemd-journal" \
        --process-level basic
```

## Performance Impact

BPFView's impact varies based on system activity and configuration. With default settings:

- CPU usage: 1-3% on a moderately busy system
- Memory usage: ~50MB base + ~2KB per cached process
- /proc filesystem access: ~1-2 reads per new process (full mode)

Using optimization features can significantly reduce this impact:

- Minimal process level reduces /proc reads by >90%
- Process exclusions can reduce event volume by 50-80%
- Network port exclusions can reduce network events by >70%
- Cache timeouts prevent unbounded memory growth

## Monitoring Performance

BPFView exposes Prometheus metrics for performance monitoring:

```bash
curl localhost:2112/metrics
```

Key metrics include:
- `bpfview_excluded_events_total`: Count of excluded events by type
- `bpfview_proc_reads_total`: Number of /proc filesystem reads
- `bpfview_process_info_duration_seconds`: Time spent collecting process info
- `bpfview_cache_hits_total`: Process cache hit/miss counts
- `bpfview_events_total`: Total events processed by type

Use these metrics to tune optimization settings for your environment.
