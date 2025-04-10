# BPFView: Process and Network Activity Correlation


  <strong>Link processes, network flows, DNS queries, and TLS/SNI through grep-friendly structured logs. </strong>

[![Build Status](https://github.com/jnesss/bpfview/actions/workflows/ci.yml/badge.svg)](https://github.com/jnesss/bpfview/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/jnesss/bpfview)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/jnesss/bpfview.svg)](https://github.com/jnesss/bpfview/releases)

BPFView provides nanosecond-precision correlation in real-time, logging every process execution, each network connection, all questions and answers in each DNS resolution, and the clear-text portion of the TLS handshake including the server name (SNI).

All network activity is correlated to the process originating the connection and its entire process tree, including the hash of the process executable. Use grep to find all details about processes initiating network connections, DNS requests, and TLS connections. Built on efficient [eBPF technology](https://ebpf.io/what-is-ebpf/), it delivers comprehensive system telemetry with minimal performance impact.

## Quick Start

```bash
# Download for your platform (Amazon Linux 2023 or Ubuntu 24.04)
curl -sSL https://github.com/jnesss/bpfview/releases/latest/download/install.sh | sudo bash

# Start monitoring with full process information
sudo bpfview --hash-binaries

# Monitor specific processes
sudo bpfview --comm nginx,php-fpm

# Track all container activity
sudo bpfview --container-id "*"
```

## Key Features

- **Process Attribution**: Every network connection, DNS query, and TLS handshake is linked to its originating process
- **Binary Integrity**: Track and filter processes by executable MD5 hash
- **Container Awareness**: Automatic container detection and correlation
- **Environment Capture**: Full process environment variable tracking
- **DNS & TLS Inspection**: Domain name resolution and TLS handshake monitoring with SNI extraction
- **Performance Optimized**: Efficient eBPF programs with ring buffer communication
- **JA4 Fingerprinting**: Generate standardized JA4 fingerprints for TLS Client Hellos for threat actor identification and correlation

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
      ClientHello len: 508
      JA4: q0t1dapplez508ahttp2c1302
      JA4 Hash: aeb3f012e851713acbf3b08b0cee2eba
      Supported Versions: TLS 1.3, TLS 1.2
      Cipher Suites: 0x1302, 0x1303, 0x1301, 0x1304, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc0ad, 0xc02b
      Supported Groups: x25519, secp256r1, x448, secp521r1, secp384r1, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
      Key Share Groups: x25519

# Process exit with duration
[PROCESS] EXIT: pid=2904710 comm=curl ppid=2877411 parent=bash uid=1000 gid=1000 exit_code=0 duration=42.046208ms
```

## Command Line Interface

BPFView offers comprehensive filtering capabilities that can be combined to precisely target what you want to monitor:

### Process Filtering
```bash
# Filter by command name
sudo bpfview --comm nginx,php-fpm

# Filter by process ID or parent
sudo bpfview --pid 1234
sudo bpfview --ppid 1000

# Track process trees (captures all child processes)
sudo bpfview --pid 1234 --tree

# Filter by command line content
sudo bpfview --cmdline "api-server"

# Filter by executable path
sudo bpfview --exe "/usr/bin/python"

# Filter by username
sudo bpfview --user nginx

# Filter by container ID
sudo bpfview --container-id "3f4552dfc342"
```

### Network Filtering
```bash
# Filter by source/destination ports
sudo bpfview --sport 22,80
sudo bpfview --dport 443,8080

# Filter by IP address
sudo bpfview --src-ip 192.168.1.10
sudo bpfview --dst-ip 10.0.0.1

# Filter by protocol
sudo bpfview --protocol TCP,UDP
```

### DNS and TLS Filtering
```bash
# Filter by domain name (supports wildcards)
sudo bpfview --domain "*.example.com"

# Filter by DNS record type
sudo bpfview --dns-type A,AAAA,CNAME

# Filter by TLS version
sudo bpfview --tls-version "1.2,1.3"

# Filter by SNI host (supports wildcards)
sudo bpfview --sni "api.example.com"
```

### Output Options
```bash
# Change log level
sudo bpfview --log-level debug

# Include timestamps in console output
sudo bpfview --log-timestamp

# Calculate binary hashes of executed binaries
sudo bpfview --hash-binaries
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

BPFView generates structured logs with shared identifiers that enable powerful cross-log correlation:

### Correlation IDs

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
# TLS handshake details including cipher suites, supported groups, and JA4 fingerprint
timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|src_ip|src_port|dst_ip|dst_port|version|sni|cipher_suites|supported_groups|handshake_length|ja4|ja4_hash
2025-04-10T06:39:13.197774743Z|1c024195|e7d6b5f2|e946b2d51ab3dca7|2963837|curl|2887886|bash|172.31.44.65|47658|184.25.113.173|443|TLS 1.0|www.example.com|0x1302,0x1303,0x1301,0x1304,0xc02c,0xc030,0xcca9,0xcca8,0xc0ad,0xc02b|x25519,secp256r1,x448,secp521r1,secp384r1,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192|508|q0t1dexamplez508ahttp2c1302|44a0ad3ebc7a695beca07f7fb96692c0
2025-04-10T06:39:26.123887892Z|1c024195|c7c48a1c|8a901c9dff2fe5fe|2963841|python3|2887886|bash|172.31.44.65|33720|184.25.113.137|443|TLS 1.0|www.example.com|0x1302,0x1303,0x1301,0x1304,0xc02c,0xc030,0xc02b,0xc02f,0xcca9,0xcca8|x25519,secp256r1,x448,secp521r1,secp384r1,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192|508|q0t1dexamplez508a_c1302|c3173f8a5b2706e8895d0e8115635851
```

### Analysis Examples

#### Trace DNS Resolution Chain
```bash
# Find DNS requests for apple.com
$ grep apple.com dns.log | grep QUERY
2025-04-09T03:13:10.510939968Z|60d6378b|907271e5|bd6fd0d03a2ebe6e|d34a0e3e|2905783|curl|2877411|bash|QUERY|0x0100|www.apple.com|A|0xdd8e|172.31.44.65|57616|172.31.0.2|53|-|-
2025-04-09T03:13:10.511099967Z|60d6378b|907271e5|bd6fd0d03a2ebe6e|bc39dad0|2905783|curl|2877411|bash|QUERY|0x0100|www.apple.com|AAAA|0x9b8b|172.31.44.65|57616|172.31.0.2|53|-|-

# Find the process that initiated those DNS requests
$ grep 907271e5 process.log 
2025-04-09T03:13:10.505955758Z|60d6378b|907271e5|EXEC|2905783|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T03:13:10.505955758Z|-|-|-
```

#### Follow Network Connection Chain
```bash
# Find a TLS connection
$ grep "www.apple.com" tls.log
2025-04-09T02:40:41.493653731Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|172.31.44.65|41054|23.221.245.25|443|TLS 1.2|www.apple.com|...

# Find corresponding network traffic
$ grep db79358f24023b06 network.log
2025-04-09T02:40:41.482210178Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|TCP|172.31.44.65|41054|23.221.245.25|443|>|60
```

## Design Principles

BPFView is built with several core design principles in mind:

1. **Immediate Event Processing**: Events are logged as they occur without batching
2. **Unified Correlation**: Every event is linked to its process context
3. **Granular Filtering**: Filter at multiple levels (process, network, DNS, TLS)
4. **Human-Readable Formats**: Logs are easily read by both humans and machine parsers
5. **Minimal Performance Impact**: Efficient BPF programs with low overhead
6. **No External Dependencies**: Single binary with no runtime dependencies

## Feature Comparison

| Feature | BPFView | tcpdump | Wireshark | bcc/BPF Tools |
|---------|---------|---------|-----------|---------------|
| Process Attribution | ✅ | ❌ | ❌ | ⚠️ (complex) |
| Binary Hash Tracking | ✅ | ❌ | ❌ | ❌ |
| Container Detection | ✅ | ❌ | ❌ | ⚠️ |
| Environment Capture | ✅ | ❌ | ❌ | ❌ |
| DNS Monitoring | ✅ | ⚠️ | ✅ | ⚠️ |
| TLS/SNI Visibility | ✅ | ❌ | ✅ | ❌ |
| JA4 Fingerprinting | ✅ | ❌ | ✅ | ❌ |
| Process Tree Tracking | ✅ | ❌ | ❌ | ❌ |
| Performance Impact | Low | Low | High | Medium |

## Installation and Platform Support

### Pre-compiled Binaries

BPFView provides pre-compiled binaries for:
- Amazon Linux 2023 (kernel 6.1)
- Ubuntu 24.04 LTS (kernel 6.8)

Download the appropriate binary from our [releases page](https://github.com/jnesss/bpfview/releases).

### One-line Install
```bash
curl -sSL https://github.com/jnesss/bpfview/releases/latest/download/install.sh | sudo bash
```

### Platform Support Details

Minimum requirements:
- Linux kernel 5.8+ (for ring buffer support)
- BTF-enabled kernel
- CAP_BPF capability or root access

Verified platforms:
- Amazon Linux 2023 (kernel 6.1+)
- Ubuntu 24.04 LTS (kernel 6.8+)

### Building for Different Kernels

BPFView uses CO-RE (Compile Once – Run Everywhere) and BTF (BPF Type Format) for kernel type information. Generate your own vmlinux.h for different kernel versions:

```bash
# Generate vmlinux.h for your kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
mv vmlinux.h bpf/vmlinux.h
```

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
