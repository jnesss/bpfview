# BPFView: Process-Aware Network Monitoring with Complete Correlation

<p align="center">
  <strong>Link processes, network flows, DNS queries, and TLS/SNI through grep-friendly structured logs. </strong>
</p>

[![Build Status](https://github.com/jnesss/bpfview/actions/workflows/ci.yml/badge.svg)](https://github.com/jnesss/bpfview/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/jnesss/bpfview)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/jnesss/bpfview.svg)](https://github.com/jnesss/bpfview/releases)

BPFView provides nanosecond-precision correlation in real-time, logging every process execution, each network connection, all questions and answers in each DNS resolution, and the clear-text portion of the TLS handshake including the server name to which the connection is intended (SNI).

All network activity is correlated to the process originating the connection and its entire process tree, including the hash of the process executable. Use grep to find all details about processes initiating network connections, DNS requests, and TLS connections. Built on efficient [eBPF technology](https://ebpf.io/what-is-ebpf/), it delivers comprehensive system telemetry with minimal performance impact.

## Key Features

- **Process Attribution**: Every network connection, DNS query, and TLS handshake is linked to its originating process
- **Binary Integrity**: Track and filter processes by executable MD5 hash
- **Container Awareness**: Automatic container detection and correlation
- **Environment Capture**: Full process environment variable tracking
- **Performance Optimized**: Efficient eBPF programs with ring buffer communication

## Technical Capabilities Demonstration

Watch a complete HTTP request unfold across all monitoring dimensions:

```
# Process execution with complete context
[PROCESS] EXEC: pid=2904710 comm=curl ppid=2877411 parent=bash path=/usr/bin/curl uid=1000 gid=1000 cwd=/home/ec2-user/bpfview/logs cmdline="curl https://www.apple.com" user=ec2-user

# DNS resolution with transaction tracking
[DNS] QUERY: conn_uid=b6e5f8077682f66e tx_id=0xaea6 pid=2904710 comm=curl
      172.31.44.65:41568 → 172.31.0.2:53
      DNS Flags: 0x0100, QR bit: false
      Q1: www.apple.com (Type: A)

[DNS] RESPONSE: conn_uid=273013048db460c2 tx_id=0xaea6 pid=2904710 comm=curl
      172.31.0.2:53 → 172.31.44.65:41568
      A1: www.apple.com -> www-apple-com.v.aaplimg.com (TTL: 295s)
      A2: www-apple-com.v.aaplimg.com -> www.apple.com.edgekey.net (TTL: 295s)
      A3: www.apple.com.edgekey.net -> e6858.dsce9.akamaiedge.net (TTL: 295s)
      A4: e6858.dsce9.akamaiedge.net -> 23.221.245.25 (TTL: 15s)

# Network connection with attribution
[NETWORK] Process: curl (PID: 2904710) Parent: bash (PPID: 2877411)
          172.31.44.65:41054 → 23.221.245.25:443 TCP 60 bytes
          ConnectionID: db79358f24023b06

# TLS handshake details
[TLS] UID: db79358f24023b06 Process: curl (PID: 2904710, PPID: 2877411, Parent: bash)
      172.31.44.65:41054 → 23.221.245.25:443
      Version: TLS 1.2
      SNI: www.apple.com
      Cipher Suites: 0x1302, 0x1303, 0x1301, 0x1304, 0xc02c
      Supported Groups: x25519, secp256r1, x448, secp521r1, secp384r1

# Process exit with duration
[PROCESS] EXIT: pid=2904710 comm=curl ppid=2877411 parent=bash uid=1000 gid=1000 exit_code=0 duration=42.046208ms
```

## Process Tree Tracking

BPFView maintains real-time process relationship trees with cycle detection:

```bash
# Track a process and all its children
sudo bpfview --pid 1234 --tree

# Example output shows parent-child relationship:
[PROCESS] EXEC: pid=2877411 comm=bash
[PROCESS] EXEC: pid=2904710 comm=curl ppid=2877411 parent=bash
[PROCESS] EXEC: pid=2904711 comm=curl ppid=2877411 parent=bash
```

<p align="center">
  <img src="docs/process-tree.png" alt="Process Tree Tracking" width="600"/>
  <br>
  <em>Real-time process tree visualization</em>
</p>

## High-Performance Design

BPFView is built for efficiency:

- **Ring Buffer Communication**: Fast, memory-efficient data transfer from kernel to userspace
- **LRU Connection Tracking**: Efficient handling of high-volume network traffic
- **Binary Hash Caching**: Optimized MD5 calculation with cache to prevent redundant computation
- **Selective Event Processing**: Configurable filtering at the eBPF level

## Advanced Security Features

### Binary Hash Tracking
```bash
# Enable binary hash calculation
sudo bpfview --hash-binaries

# Track specific binary versions
sudo bpfview --binary-hash 9c30781b6d88fd2c8acebab96791fcb1

# Real example showing binary hash correlation:
[PROCESS] EXEC: pid=2904710 comm=curl path=/usr/bin/curl binary_hash=9c30781b6d88fd2c8acebab96791fcb1
[NETWORK] Process: curl (PID: 2904710) ConnectionID: db79358f24023b06
```

<p align="center">
  <img src="docs/binary-tracking.png" alt="Binary Hash Tracking" width="600"/>
  <br>
  <em>Binary hash tracking with process correlation</em>
</p>

### Container Integration
```bash
# Automatic container detection from real data:
[PROCESS] EXEC: pid=5678 comm=python3 container=3f4552dfc342 cwd=/app
[NETWORK] Process: python3 (PID: 5678) Parent: containerd
```

<p align="center">
  <img src="docs/container-view.png" alt="Container Integration" width="600"/>
  <br>
  <em>Container process and network activity correlation</em>
</p>

### Environment Variable Tracking
```bash
# Environment variables are captured and logged:
timestamp|sessionid|process_uid|uid|pid|comm|env_var
2025-04-09T02:40:41.440|60d6378b|4f016e0|1000|2904710|curl|PATH=/usr/local/bin:/usr/bin
```

## Technical Implementation

BPFView consists of four specialized eBPF programs:

1. **netmon.c**: Network connection tracking with process context
   - LRU hash maps for connection tracking
   - Efficient packet processing without copying payload
   - Automatic cleanup of expired connections

2. **dnsmon.c**: DNS monitoring with minimal overhead
   - Selective packet capture only for DNS traffic
   - Efficient protocol parsing in kernel space
   - Transaction tracking for query/response correlation

3. **execve.c**: Process execution tracking
   - Precise command-line argument capture
   - Environment variable collection
   - Working directory and binary hash tracking

4. **tlsmon.c**: TLS handshake analysis
   - ClientHello parsing for SNI extraction
   - Cipher suite enumeration
   - Key exchange group tracking
   
## Log Correlation and Analysis

BPFView generates a set of correlated logs that provide complete visibility into system activity. Each event type is logged separately for efficient processing while maintaining relationships through shared identifiers.

### Correlation IDs

BPFView uses several unique identifiers to link events across different log files:

* **session_uid**: Unique identifier for each BPFView run (e.g., `60d6378b`)
* **process_uid**: Consistent identifier for a process across all log types (e.g., `907271e5`)
* **network_uid**: Unique identifier for each network connection (e.g., `db79358f24023b06`)
* **dns_conversation_uid**: Links DNS queries with their responses (e.g., `5551529`)

### Complete Log Examples

#### Process Events (process.log)
```
# Process execution with binary hash and environment details
timestamp|session_uid|process_uid|event_type|pid|ppid|uid_user|gid|comm|parent_comm|exe_path|binary_hash|cmdline|username|container_id|cwd|start_time|exit_time|exit_code|duration
2025-04-09T02:40:41.440071084Z|60d6378b|4f016e0|EXEC|2904710|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T02:40:41.440071084Z|-|-|-
2025-04-09T02:40:41.482117292Z|60d6378b|4f016e0|EXIT|2904710|2877411|1000|1000|curl|-|-|-|-|-|-|-|2025-04-09T02:40:41.440071084Z|2025-04-09T02:40:41.482117292Z|0|42.046208ms
```

#### Network Events (network.log)
```
# Network connections with process attribution and byte counts
timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|protocol|src_ip|src_port|dst_ip|dst_port|direction|bytes
2025-04-09T02:40:41.464748584Z|60d6378b|4f016e0|b6e5f8077682f66e|2904710|curl|2877411|bash|UDP|172.31.44.65|41568|172.31.0.2|53|>|59
2025-04-09T02:40:41.464774498Z|60d6378b|4f016e0|b6e5f8077682f66e|2904710|curl|2877411|bash|UDP|172.31.44.65|41568|172.31.0.2|53|>|59
2025-04-09T02:40:41.466153791Z|60d6378b|4f016e0|273013048db460c2|2904710|curl|2877411|bash|UDP|172.31.0.2|53|172.31.44.65|41568|<|189
2025-04-09T02:40:41.481886338Z|60d6378b|4f016e0|273013048db460c2|2904710|curl|2877411|bash|UDP|172.31.0.2|53|172.31.44.65|41568|<|229
2025-04-09T02:40:41.482210178Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|TCP|172.31.44.65|41054|23.221.245.25|443|>|60
```

#### DNS Events (dns.log)
```
# Full DNS query/response chain with CNAME resolution
timestamp|session_uid|process_uid|network_uid|dns_conversation_uid|pid|comm|ppid|parent_comm|event_type|dns_flags|query|type|txid|src_ip|src_port|dst_ip|dst_port|answers|ttl
2025-04-09T02:40:41.464760384Z|60d6378b|4f016e0|b6e5f8077682f66e|5551529|2904710|curl|2877411|bash|QUERY|0x0100|www.apple.com|A|0xaea6|172.31.44.65|41568|172.31.0.2|53|-|-
2025-04-09T02:40:41.464774934Z|60d6378b|4f016e0|b6e5f8077682f66e|bd360059|2904710|curl|2877411|bash|QUERY|0x0100|www.apple.com|AAAA|0xeca0|172.31.44.65|41568|172.31.0.2|53|-|-
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com|CNAME|0xaea6|172.31.0.2|53|172.31.44.65|41568|www-apple-com.v.aaplimg.com|295
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|www-apple-com.v.aaplimg.com|CNAME|0xaea6|172.31.0.2|53|172.31.44.65|41568|www.apple.com.edgekey.net|295
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com.edgekey.net|CNAME|0xaea6|172.31.0.2|53|172.31.44.65|41568|e6858.dsce9.akamaiedge.net|295
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|e6858.dsce9.akamaiedge.net|A|0xaea6|172.31.0.2|53|172.31.44.65|41568|23.221.245.25|15
```

#### TLS Events (tls.log)
```
# TLS handshake details including cipher suites and supported groups
timestamp|sessionid|process_uid|network_uid|uid|pid|comm|ppid|parent_comm|src_ip|src_port|dst_ip|dst_port|version|sni|cipher_suites|supported_groups
2025-04-09T02:40:41.493653731Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|172.31.44.65|41054|23.221.245.25|443|TLS 1.2|www.apple.com|0x1302,0x1303,0x1301,0x1304,0xc02c|x25519,secp256r1,x448,secp521r1,secp384r1
```

### Cross-Log Analysis Examples

#### 1. Trace DNS Resolution Chain
```bash
# Find DNS requests for apple.com
$ grep apple.com dns.log | grep QUERY | tail -2
2025-04-09T03:13:10.510939968Z|60d6378b|907271e5|bd6fd0d03a2ebe6e|d34a0e3e|2905783|curl|2877411|bash|QUERY|0x0100|www.apple.com|A|0xdd8e|172.31.44.65|57616|172.31.0.2|53|-|-
2025-04-09T03:13:10.511099967Z|60d6378b|907271e5|bd6fd0d03a2ebe6e|bc39dad0|2905783|curl|2877411|bash|QUERY|0x0100|www.apple.com|AAAA|0x9b8b|172.31.44.65|57616|172.31.0.2|53|-|-

# Find the process that initiated those DNS requests
$ grep 907271e5 process.log 
2025-04-09T03:13:10.505955758Z|60d6378b|907271e5|EXEC|2905783|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T03:13:10.505955758Z|-|-|-
2025-04-09T03:13:10.523152867Z|60d6378b|907271e5|EXIT|2905783|2877411|1000|1000|curl|-|-|-|-|-|-|-|2025-04-09T03:13:10.505955758Z|2025-04-09T03:13:10.523152867Z|0|17.197109ms

# Find other processes from the same parent
$ awk -F'|' '$6 == "2877411"' process.log
2025-04-09T02:40:41.440071084Z|60d6378b|4f016e0|EXEC|2904710|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T02:40:41.440071084Z|-|-|-
2025-04-09T02:40:41.482117292Z|60d6378b|4f016e0|EXIT|2904710|2877411|1000|1000|curl|-|-|-|-|-|-|-|2025-04-09T02:40:41.440071084Z|2025-04-09T02:40:41.482117292Z|0|42.046208ms
```

#### 2. Follow Network Connection Chain
```bash
# Find a TLS connection
$ grep "www.apple.com" tls.log
2025-04-09T02:40:41.493653731Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|172.31.44.65|41054|23.221.245.25|443|TLS 1.2|www.apple.com|...

# Find corresponding network traffic
$ grep db79358f24023b06 network.log
2025-04-09T02:40:41.482210178Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|TCP|172.31.44.65|41054|23.221.245.25|443|>|60
```

#### 3. Calculate Process Statistics
```bash
# Get average process duration for curl commands
$ awk -F'|' '$9 == "curl" && $3 == "EXIT" {sum += $20; count++} END {print sum/count " average duration"}' process.log
29.621658ms average duration
```

## Command Line Interface

BPFView offers powerful filtering capabilities:

### Process Filtering
```bash
# Filter by command name
sudo bpfview --comm nginx,php-fpm

# Filter by process ID or parent
sudo bpfview --pid 1234
sudo bpfview --ppid 1000

# Track process trees
sudo bpfview --pid 1234 --tree

# Filter by command line or executable
sudo bpfview --cmdline "api-server"
sudo bpfview --exe "/usr/bin/python"
```

### Network Filtering
```bash
# Filter by ports
sudo bpfview --sport 22,80
sudo bpfview --dport 443,8080

# Filter by IP address
sudo bpfview --src-ip 192.168.1.10
sudo bpfview --dst-ip 10.0.0.1
```

### DNS and TLS Filtering
```bash
# Filter by domain name
sudo bpfview --domain "*.example.com"

# Filter by DNS record type
sudo bpfview --dns-type A,AAAA,CNAME

# Filter by TLS version
sudo bpfview --tls-version "1.2,1.3"

# Filter by SNI host
sudo bpfview --sni "api.example.com"
```

## Feature Comparison

| Feature | BPFView | tcpdump | Wireshark | bcc/BPF Tools |
|---------|---------|---------|-----------|---------------|
| Process Attribution | ✅ | ❌ | ❌ | ⚠️ (complex) |
| Binary Hash Tracking | ✅ | ❌ | ❌ | ❌ |
| Container Detection | ✅ | ❌ | ❌ | ⚠️ |
| Environment Capture | ✅ | ❌ | ❌ | ❌ |
| DNS Monitoring | ✅ | ⚠️ | ✅ | ⚠️ |
| TLS/SNI Visibility | ✅ | ❌ | ✅ | ❌ |
| Process Tree Tracking | ✅ | ❌ | ❌ | ❌ |
| Performance Impact | Low | Low | High | Medium |

## Installation and Platform Support

### Pre-compiled Binaries

BPFView provides pre-compiled binaries for:
- Amazon Linux 2023 (kernel 6.1)
- Ubuntu 24.04.2 LTS (kernel 6.8)

Download the appropriate binary from our [releases page](https://github.com/jnesss/bpfview/releases).

### One-line Install
```bash
curl -sSL https://github.com/jnesss/bpfview/releases/latest/download/install.sh | sudo bash
```

### Building for Different Kernels

BPFView uses CO-RE (Compile Once – Run Everywhere) and BTF (BPF Type Format) for kernel type information. While the repository includes a reference vmlinux.h for Linux kernel 6.1, you may need to generate your own for different kernel versions:

1. Install bpftool:
```bash
# On Ubuntu/Debian
sudo apt-get install linux-tools-common linux-tools-generic

# On RHEL/CentOS
sudo yum install bpftool

# On Amazon Linux
sudo yum install bpftool
```

2. Generate vmlinux.h for your kernel:
```bash
# Check if your kernel has BTF support
bpftool btf dump file /sys/kernel/btf/vmlinux > /dev/null

# If supported, generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

3. Replace the existing vmlinux.h in the project:
```bash
mv vmlinux.h bpf/vmlinux.h
```

### Platform Support Details

Minimum requirements:
- Linux kernel 5.8+ (for ring buffer support)
- BTF-enabled kernel
- CAP_BPF capability or root access

Verified platforms:
- Amazon Linux 2023 (kernel 6.1+)
  * Full feature support
  * Pre-compiled binary available
  * Built-in BTF support

- Ubuntu 22.04 LTS (kernel 5.15+)
  * Full feature support
  * Pre-compiled binary available
  * Built-in BTF support

- Ubuntu 20.04 LTS (kernel 5.4+)
  * Full feature support
  * Pre-compiled binary available
  * BTF support varies by kernel version

- RHEL/CentOS 8.2+ (kernel 4.18+)
  * Full feature support with kernel 5.8+
  * Pre-compiled binary available
  * BTF support requires kernel-devel package

### Building from Source
```bash
git clone https://github.com/jnesss/bpfview.git
cd bpfview
go generate
go build
```

## License

This project uses a dual license approach:
- Go code and overall project: [Apache License 2.0](LICENSE)
- BPF programs (in `bpf/`): GPL v2 (required for kernel integration)

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md).
