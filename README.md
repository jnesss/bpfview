# BPFView: Process and Network Activity Correlation

<strong>Link processes, network flows, DNS queries, and TLS/SNI through structured logs with powerful real-time detection.</strong>

[![Build Status](https://github.com/jnesss/bpfview/actions/workflows/ci.yml/badge.svg)](https://github.com/jnesss/bpfview/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/jnesss/bpfview)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/jnesss/bpfview.svg)](https://github.com/jnesss/bpfview/releases)

BPFView provides nanosecond-precision correlation in real-time, logging every process execution, each network connection, all questions and answers in each DNS resolution, and the clear-text portion of the TLS handshake including the server name (SNI).

All network activity is correlated to the process originating the connection and its entire process tree, including the hash of the process executable. Use grep to find all details about processes initiating network connections, DNS requests, and TLS connections. Built on efficient [eBPF technology](https://ebpf.io/what-is-ebpf/), it delivers comprehensive system telemetry with minimal performance impact.

## Quick Start

```bash
# Download for your platform (Amazon Linux 2023 or Ubuntu 24.04)
curl -sSL https://github.com/jnesss/bpfview/releases/latest/download/install.sh | sudo bash

# Start monitoring with full process and binary analysis
sudo bpfview --hash-binaries --package-verify

# Enable real-time detection with Sigma rules
sudo bpfview --hash-binaries --sigma ./sigma

# Track activity of a specific container
sudo bpfview --container-id "3f4552dfc342" --hash-binaries
```

## Documentation

- [Installation & Quick Start Guide](docs/QUICKSTART.md)
- [Detection & Response](docs/DETECTION.md)
- [Performance Optimization](docs/PERFORMANCE.md)
- [Output Formats](docs/FORMATS.md)
- [Advanced Usage](docs/ADVANCED.md)

## Key Features

### Process Attribution
- **Complete Process Context**: Every network connection, DNS query, and TLS handshake is linked to its originating process
- **Process Tree Tracking**: Full visibility into parent-child process relationships
- **Environment Capture**: Complete process environment variable tracking
- **Working Directory Tracking**: See the context in which processes are executed
- **Container Awareness**: Automatic container detection and correlation

### Binary Analysis
- **Executable Hashing**: Track and filter processes by MD5 and SHA256 hash
- **ELF Analysis**: Examine architecture, imports, exports, and linking type
- **Package Verification**: Detect modified system binaries automatically
- **Library Dependency Tracking**: Identify unusual library imports
- **Binary-Process Association**: Track which processes have loaded specific binaries

### Network Visibility
- **Full Flow Tracking**: Monitor TCP, UDP, and ICMP connections
- **Community ID Flow Hashing**: Standard network flow correlation compatible with Zeek, Suricata, and other security tools
- **TCP Flag Analysis**: Track connection state through TCP flags
- **Direction Detection**: Classify traffic as ingress or egress automatically

### DNS Monitoring
- **Full DNS Visibility**: Track all DNS queries and responses
- **CNAME Chain Following**: Complete DNS resolution chain tracking
- **Process Attribution**: Know which process made each DNS lookup
- **Conversation Tracking**: Link queries with their corresponding responses

### TLS Inspection
- **Handshake Monitoring**: Extract SNI, cipher suites, and TLS version
- **JA4 Fingerprinting**: Generate standardized JA4 fingerprints for TLS Client Hellos
- **Cipher Suite Analysis**: Track supported encryption methods
- **Process Context**: Link TLS connections to originating processes

### Real-time Detection
- **Sigma Rule Matching**: Process behavior matching against Sigma rules
- **Multiple Event Types**: Detect patterns in process, network, DNS, and binary events
- **Automatic Rule Reloading**: Dynamic rule updates without service restart
- **Rich Detection Context**: Full process and system context for each rule match

### Automated Response
- **Process Termination**: Kill malicious processes automatically
- **Network Blocking**: Prevent processes from establishing connections
- **Child Process Prevention**: Block process spawning capabilities
- **Memory Dumping**: Capture process memory for forensic analysis

### Flexible Output
- **Multiple Formats**: Text, JSON, ECS, GELF, and SQLite outputs
- **Log Rotation**: Automatic log file management
- **Prometheus Metrics**: Performance and operational metrics
- **Field Customization**: Add host information and customize outputs

## Real-World Detection Example: Cryptocurrency Mining

Watch a complete attack detection chain unfold, showing how BPFView correlates process execution, network activity, DNS activity, and real-time threat detection:

### Console View

```text
# Initial process execution
[PROCESS] EXEC: PID=316331 comm=xmrig ProcessUID=907d6780
      Parent: [311463] bash
      User: ec2-user (1000/1000)
      Path: /tmp/mining_test/xmrig-6.21.0/xmrig
      CWD: /tmp/mining_test/xmrig-6.21.0
      Command: ./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A

# DNS resolution showing mining pool connection attempt
[DNS] QUERY: conn_uid=90cd423634c3c467 tx_id=0x72ba pid=316331 comm=xmrig
      172.31.44.65:44440 → 172.31.0.2:53
      DNS Flags: 0x0100, QR bit: false
      Q1: pool.minexmr.com (Type: A)

# Real-time threat detection
[SIGMA] Match: Linux Crypto Mining Pool Connections (Level: high)
      Process: xmrig (PID: 316331, ProcessUID: 907d6780)
      Rule: Detects process connections to a Monero crypto mining pool
      Details: DestinationHostname equals 'pool.minexmr.com'
      MITRE: Impact (T1496)

# Process termination
[PROCESS] EXIT: PID=316331 comm=xmrig
      Parent: [311463] bash
      Exit Code: 0
      Duration: 5.298698204s
```

### JSON Format Example

```json
{
  "timestamp": "2025-04-15T20:15:06.956325705Z",
  "session_uid": "32476fd8",
  "event_type": "process_exec",
  "process_uid": "4fe5046b",
  "parent_uid": "90ed22d6",
  "process": {
    "pid": 324331,
    "comm": "xmrig",
    "ppid": 311463,
    "parent_comm": "bash",
    "uid": 1000,
    "gid": 1000,
    "exe_path": "/tmp/mining_test/xmrig-6.21.0/xmrig",
    "binary_hash": "86f2790c04ccd113a564cc074efbcdfd",
    "command_line": "./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    "username": "ec2-user",
    "cwd": "/tmp/mining_test/xmrig-6.21.0",
    "start_time": "2025-04-15T20:15:06.956325705Z"
  },
  "message": "process_exec: xmrig (PID: 324331)"
}
```

## Process Lifecycle Visibility

BPFView provides complete process lifecycle visibility by tracking three distinct event types:

### Fork, Exec, and Exit Events

#### FORK Events

Capture the initial process creation via the fork() or clone() system calls

- Records parent-child relationships
- Inherits parent environment and working directory
- Tracks the precise moment of process creation

#### EXEC Events

Track when a process loads a new executable via execve()

- Records full command line arguments
- Captures binary hash for integrity verification
- Documents environment variables and working directory

#### EXIT Events

Record process termination details

- Logs exit code and termination reason
- Calculates precise process duration
- Provides execution timeline completion

## Binary Analysis

BPFView's BinaryAnalyzer component enhances security by monitoring executable integrity and characteristics:

### Binary Integrity
- **Hash Calculation**: MD5 and SHA256 hashes for every executed binary
- **Package Verification**: Validates binaries against system package databases (RPM/DEB)
- **Modification Detection**: Identifies binaries that have been tampered with

### ELF Analysis
- **Architecture Detection**: Identifies binary target architecture (x86_64, ARM, etc.)
- **Type Identification**: Classifies as executable, shared object, or other
- **Import/Export Analysis**: Reviews symbols and library dependencies
- **Static/Dynamic Detection**: Identifies statically vs. dynamically linked binaries

### Integration with Sigma
- **Binary-Specific Rules**: Create detection rules targeting suspicious binaries
- **Package Verification Rules**: Detect modified system binaries
- **ELF Characteristic Rules**: Identify unusual compilation or linking patterns

Enable binary analysis with:
```bash
# Basic binary hashing
sudo bpfview --hash-binaries

# Full analysis with package verification
sudo bpfview --hash-binaries --package-verify
```

## Sigma Detection

BPFView integrates with the Sigma detection standard to provide real-time threat detection:

### Detection Capabilities
- **Process Behavior**: Match on command lines, paths, and user context
- **Network Connections**: Detect suspicious destinations and ports
- **DNS Activity**: Identify malicious domain lookups
- **Binary Analysis**: Flag suspicious binary characteristics

### Response Actions
When a rule matches, BPFView can take automated actions:

1. **Process Termination** (`terminate`): Immediately kills malicious processes
2. **Network Blocking** (`block_network`): Prevents network access
3. **Child Process Prevention** (`prevent_children`): Blocks new process creation
4. **Memory Dumping** (`dump_memory`): Captures process memory for analysis

Enable detection with:
```bash
# Enable Sigma detection with default rules directory
sudo bpfview --sigma ./sigma

# With custom rules and larger queue size
sudo bpfview --sigma ./custom-rules --sigma-queue-size 20000
```

For detailed information on detection rules and capabilities, see the [Detection Guide](docs/DETECTION.md).

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

# Calculate binary hashes of executed binaries
sudo bpfview --hash-binaries

# Output format selection
sudo bpfview --format json  # Use JSON format (default: text)
sudo bpfview --format json-ecs  # Use Elastic Common Schema format
sudo bpfview --format gelf  # Use Graylog Extended Log Format
```

## Technical Implementation

BPFView consists of specialized eBPF programs:

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

5. **binaryanalyzer**: Binary integrity and analysis
   - Binary hash calculation
   - ELF header and section parsing
   - Package verification integration
   
## Log Correlation and Analysis

BPFView generates structured logs with shared identifiers that enable powerful cross-log correlation:

### Correlation IDs

* **session_uid**: Unique identifier for each BPFView run
* **process_uid**: Consistent identifier for a process across all log types
* **network_uid**: Unique identifier for each network connection
* **community_id**: Standardized network flow identifier compatible with Zeek, Suricata, and other tools
* **dns_conversation_uid**: Links DNS queries with their responses

For sophisticated analysis examples, see the [Output Formats Guide](docs/FORMATS.md).

## Performance Optimization

BPFView is designed to operate efficiently with minimal performance impact, but can be further optimized for specific environments and high-volume workloads.

For detailed information about performance features, tuning options, and monitoring capabilities, see the [Performance Optimization Guide](docs/PERFORMANCE.md).

Key optimization features include:
- Process exclusion filters to ignore high-volume system processes
- Process information level control to reduce /proc filesystem access
- Cache size management for memory optimization
- Container-specific optimizations

## License

This project uses a dual license approach:
- Go code and overall project: [Apache License 2.0](LICENSE)
- BPF programs (in `bpf/`): GPL v2 (required for kernel integration)

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md).
