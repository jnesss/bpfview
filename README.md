# BPFView: Process-Aware Network Monitoring Made Simple

<p align="center">
  <img src="docs/bpfview-logo.png" alt="BPFView Logo" width="200"/>
  <br>
  <em>View and correlate endpoint process, network, DNS, and TLS/SNI activity</em>
</p>

[![Build Status](https://github.com/jnesss/bpfview/actions/workflows/ci.yml/badge.svg)](https://github.com/jnesss/bpfview/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/jnesss/bpfview)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/jnesss/bpfview.svg)](https://github.com/jnesss/bpfview/releases)

BPFView is a lightweight, easy-to-use tool that bridges the gap between network and process monitoring. It is a single standalone Linux binary that shows exactly which processes are being executed and provides network traffic attribution when those processes communicate over your network, resolve DNS names, or initiate outbound TLS connections.

## Why BPFView?

- **Process Attribution**: See exactly which process made that connection
- **Zero Config**: Works out-of-the-box with no setup
- **Real-time Monitoring**: Watch process and network activity as it happens
- **Deep Visibility**: Track DNS, TLS/SNI, and process parent-child relationships
- **Low Overhead**: Built on efficient eBPF technology

## Quick Start

```bash
# Download the single binary
wget https://github.com/jnesss/bpfview/releases/latest/download/bpfview

# Make it executable
chmod +x bpfview

# Start monitoring all network traffic with process context
sudo ./bpfview
```

## Use Cases

### Track Web Service Dependencies

```bash
# Monitor what your web service is talking to
sudo ./bpfview --comm nginx
```

![Web Service Monitoring](docs/web-service.png)

### Troubleshoot DNS Issues

```bash
# See all DNS queries with process attribution
sudo ./bpfview --type dns
```

![DNS Monitoring](docs/dns-monitor.png)

### Security Investigation

```bash
# Monitor process trees for suspicious activity
sudo ./bpfview --comm bash --tree
```

![Security Monitoring](docs/security-monitor.png)

## Command Line Options

BPFView offers powerful filtering capabilities through its command line interface:

### Process Filtering

```bash
# Filter by command name (supports multiple comma-separated values)
sudo ./bpfview --comm nginx,php-fpm

# Filter by process ID
sudo ./bpfview --pid 1234

# Filter by parent process ID
sudo ./bpfview --ppid 1000

# Track process trees (captures all child processes)
sudo ./bpfview --pid 1234 --tree

# Filter by command line content
sudo ./bpfview --cmdline "api-server"

# Filter by executable path
sudo ./bpfview --exe "/usr/bin/python"

# Filter by username
sudo ./bpfview --user nginx
```

### Network Filtering

```bash
# Filter by source port(s)
sudo ./bpfview --sport 22,80

# Filter by destination port(s)
sudo ./bpfview --dport 443,8080

# Filter by source IP address
sudo ./bpfview --src-ip 192.168.1.10

# Filter by destination IP address
sudo ./bpfview --dst-ip 10.0.0.1

# Filter by protocol
sudo ./bpfview --protocol TCP,UDP
```

### DNS Filtering

```bash
# Filter by domain name (supports wildcards)
sudo ./bpfview --domain "*.example.com"

# Filter by DNS record type
sudo ./bpfview --dns-type A,AAAA,CNAME
```

### TLS Filtering

```bash
# Filter by TLS version
sudo ./bpfview --tls-version "1.2,1.3"

# Filter by SNI host
sudo ./bpfview --sni "api.example.com"
```

### Output Options

```bash
# Change output format
sudo ./bpfview --output json

# Write to file instead of stdout
sudo ./bpfview --file network-traffic.log

# Show debugging information
sudo ./bpfview --log-level debug

# Include timestamps in console output
sudo ./bpfview --log-timestamp
```

### Binary Hash Calculations

BPFView can calculate and log MD5 hashes of process executables, which is useful for:

- Identifying malicious binaries
- Detecting file modifications
- Correlating processes across systems

```bash
# Enable binary hashing
sudo ./bpfview --hash-binaries

# Filter processes by binary hash
sudo ./bpfview --binary-hash d41d8cd98f00b204e9800998ecf8427e
```

## Output Format

BPFView generates Zeek-inspired logs that are easy to read and process:

### Process Events (process.log)
```
timestamp|session_uid|process_uid|event_type|pid|ppid|uid_user|gid|comm|parent_comm|exe_path|binary_hash|cmdline|username|container_id|cwd|start_time|exit_time|exit_code|duration
2025-04-09T02:40:41.440071084Z|60d6378b|4f016e0|EXEC|2904710|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T02:40:41.440071084Z|-|-|-
2025-04-09T02:40:41.482117292Z|60d6378b|4f016e0|EXIT|2904710|2877411|1000|1000|curl|-|-|-|-|-|-|-|2025-04-09T02:40:41.440071084Z|2025-04-09T02:40:41.482117292Z|0|42.046208ms
```

### Network Events (network.log)
```
timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|protocol|src_ip|src_port|dst_ip|dst_port|direction|bytes
2025-04-09T02:40:41.464748584Z|60d6378b|4f016e0|b6e5f8077682f66e|2904710|curl|2877411|bash|UDP|172.31.44.65|41568|172.31.0.2|53|>|59
2025-04-09T02:40:41.464774498Z|60d6378b|4f016e0|b6e5f8077682f66e|2904710|curl|2877411|bash|UDP|172.31.44.65|41568|172.31.0.2|53|>|59
2025-04-09T02:40:41.466153791Z|60d6378b|4f016e0|273013048db460c2|2904710|curl|2877411|bash|UDP|172.31.0.2|53|172.31.44.65|41568|<|189
2025-04-09T02:40:41.481886338Z|60d6378b|4f016e0|273013048db460c2|2904710|curl|2877411|bash|UDP|172.31.0.2|53|172.31.44.65|41568|<|229
2025-04-09T02:40:41.482210178Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|TCP|172.31.44.65|41054|23.221.245.25|443|>|60
2025-04-09T02:40:41.491557351Z|60d6378b|4f016e0|61fd9f06208c3a9a|2904710|curl|2877411|bash|TCP|23.221.245.25|443|172.31.44.65|41054|<|60
2025-04-09T02:40:41.491592414Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|TCP|172.31.44.65|41054|23.221.245.25|443|>|52
2025-04-09T02:40:41.493641304Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|TCP|172.31.44.65|41054|23.221.245.25|443|>|569
2025-04-09T02:40:41.502971472Z|60d6378b|4f016e0|61fd9f06208c3a9a|2904710|curl|2877411|bash|TCP|23.221.245.25|443|172.31.44.65|41054|<|52
2025-04-09T02:40:41.504376047Z|60d6378b|4f016e0|61fd9f06208c3a9a|2904710|curl|2877411|bash|TCP|23.221.245.25|443|172.31.44.65|41054|<|2948
```

### DNS Events (dns.log)
```
timestamp|session_uid|process_uid|network_uid|dns_conversation_uid|pid|comm|ppid|parent_comm|event_type|dns_flags|query|type|txid|src_ip|src_port|dst_ip|dst_port|answers|ttl
2025-04-09T02:40:41.464760384Z|60d6378b|4f016e0|b6e5f8077682f66e|5551529|2904710|curl|2877411|bash|QUERY|0x0100|www.apple.com|A|0xaea6|172.31.44.65|41568|172.31.0.2|53|-|-
2025-04-09T02:40:41.464774934Z|60d6378b|4f016e0|b6e5f8077682f66e|bd360059|2904710|curl|2877411|bash|QUERY|0x0100|www.apple.com|AAAA|0xeca0|172.31.44.65|41568|172.31.0.2|53|-|-
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com|A|0xaea6|172.31.0.2|53|172.31.44.65|41568|-|-
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com|CNAME|0xaea6|172.31.0.2|53|172.31.44.65|41568|www-apple-com.v.aaplimg.com|295
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|www-apple-com.v.aaplimg.com|CNAME|0xaea6|172.31.0.2|53|172.31.44.65|41568|www.apple.com.edgekey.net|295
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com.edgekey.net|CNAME|0xaea6|172.31.0.2|53|172.31.44.65|41568|e6858.dsce9.akamaiedge.net|295
2025-04-09T02:40:41.466161267Z|60d6378b|4f016e0|273013048db460c2|5551529|2904710|curl|2877411|bash|RESPONSE|0x8180|e6858.dsce9.akamaiedge.net|A|0xaea6|172.31.0.2|53|172.31.44.65|41568|23.221.245.25|15
2025-04-09T02:40:41.481896675Z|60d6378b|4f016e0|273013048db460c2|bd360059|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com|AAAA|0xeca0|172.31.0.2|53|172.31.44.65|41568|-|-
2025-04-09T02:40:41.481896675Z|60d6378b|4f016e0|273013048db460c2|bd360059|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com|CNAME|0xeca0|172.31.0.2|53|172.31.44.65|41568|www-apple-com.v.aaplimg.com|217
2025-04-09T02:40:41.481896675Z|60d6378b|4f016e0|273013048db460c2|bd360059|2904710|curl|2877411|bash|RESPONSE|0x8180|www-apple-com.v.aaplimg.com|CNAME|0xeca0|172.31.0.2|53|172.31.44.65|41568|www.apple.com.edgekey.net|217
2025-04-09T02:40:41.481896675Z|60d6378b|4f016e0|273013048db460c2|bd360059|2904710|curl|2877411|bash|RESPONSE|0x8180|www.apple.com.edgekey.net|CNAME|0xeca0|172.31.0.2|53|172.31.44.65|41568|e6858.dsce9.akamaiedge.net|217
2025-04-09T02:40:41.481896675Z|60d6378b|4f016e0|273013048db460c2|bd360059|2904710|curl|2877411|bash|RESPONSE|0x8180|e6858.dsce9.akamaiedge.net|AAAA|0xeca0|172.31.0.2|53|172.31.44.65|41568|2600:1407:3c00:158b::1aca|20
2025-04-09T02:40:41.481896675Z|60d6378b|4f016e0|273013048db460c2|bd360059|2904710|curl|2877411|bash|RESPONSE|0x8180|e6858.dsce9.akamaiedge.net|AAAA|0xeca0|172.31.0.2|53|172.31.44.65|41568|2600:1407:3c00:1580::1aca|20
```

### TLS Events (tls.log)
```
timestamp|sessionid|process_uid|network_uid|uid|pid|comm|ppid|parent_comm|src_ip|src_port|dst_ip|dst_port|version|sni|cipher_suites|supported_groups
2025-04-09T02:40:41.493653731Z|60d6378b|4f016e0|db79358f24023b06|2904710|curl|2877411|bash|172.31.44.65|41054|23.221.245.25|443|TLS 1.0|www.apple.com|0x1302,0x1303,0x1301,0x1304,0xc02c,0xc030,0xcca9,0xcca8,0xc0ad,0xc02b|x25519,secp256r1,x448,secp521r1,secp384r1,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192
```
## Log Correlation

BPFView makes it easy to correlate events across different log files through several ID fields:

### Correlation IDs

- **session_uid**: A unique identifier for each BPFView run, helping you group related log files
- **process_uid**: A unique identifier for each process, consistent across all log types
- **network_uid** (in the network, TLS, and DNS logs): A unique identifier for each network connection
- **dns_conversation_uid**: A unique identifier associating a DNS request with its set of responses

```
# Find DNS requests for apple.com
$ grep apple.com dns.log | grep QUERY | tail -2
2025-04-09T03:13:10.510939968Z|60d6378b|907271e5|bd6fd0d03a2ebe6e|d34a0e3e|2905783|curl|2877411|bash|QUERY|0x0100|www.apple.com|A|0xdd8e|172.31.44.65|57616|172.31.0.2|53|-|-
2025-04-09T03:13:10.511099967Z|60d6378b|907271e5|bd6fd0d03a2ebe6e|bc39dad0|2905783|curl|2877411|bash|QUERY|0x0100|www.apple.com|AAAA|0x9b8b|172.31.44.65|57616|172.31.0.2|53|-|-

# Find the process that initiated those DNS requests
$ grep 907271e5 process.log 
2025-04-09T03:13:10.505955758Z|60d6378b|907271e5|EXEC|2905783|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T03:13:10.505955758Z|-|-|-
2025-04-09T03:13:10.523152867Z|60d6378b|907271e5|EXIT|2905783|2877411|1000|1000|curl|-|-|-|-|-|-|-|2025-04-09T03:13:10.505955758Z|2025-04-09T03:13:10.523152867Z|0|17.197109ms

# Find the other processes initiated by the same parent process
$ awk -F'|' '$6 == "2877411"' process.log
2025-04-09T02:40:41.440071084Z|60d6378b|4f016e0|EXEC|2904710|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T02:40:41.440071084Z|-|-|-
2025-04-09T02:40:41.482117292Z|60d6378b|4f016e0|EXIT|2904710|2877411|1000|1000|curl|-|-|-|-|-|-|-|2025-04-09T02:40:41.440071084Z|2025-04-09T02:40:41.482117292Z|0|42.046208ms
2025-04-09T03:13:10.505955758Z|60d6378b|907271e5|EXEC|2905783|2877411|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-09T03:13:10.505955758Z|-|-|-
2025-04-09T03:13:10.523152867Z|60d6378b|907271e5|EXIT|2905783|2877411|1000|1000|curl|-|-|-|-|-|-|-|2025-04-09T03:13:10.505955758Z|2025-04-09T03:13:10.523152867Z|0|17.197109ms
```

## Integration Examples

### Monitor Container Network Activity

```bash
# Monitor all network traffic from containers
sudo ./bpfview --container-id "*"

# Track a specific container
sudo ./bpfview --container-id "3f4552dfc342"
```

### Combine with Traditional Tools

```bash
# Send logs to Zeek-compatible processors
sudo ./bpfview --output json | zeek-cut

# Filter with jq
sudo ./bpfview --output json | jq '.events[] | select(.dst_port == 443)'
```

## Requirements

- Linux kernel 5.8+
- CAP_BPF capability or root access

## Installation

### One-line Install

```bash
curl -sSL https://github.com/jnesss/bpfview/releases/latest/download/install.sh | sudo bash
```

### Build from Source

```bash
git clone https://github.com/jnesss/bpfview.git
cd bpfview
go generate
go build
```

## Comparison with Other Tools

| Feature | BPFView | tcpdump | Wireshark | bcc/BPF Tools |
|---------|---------|---------|-----------|---------------|
| Process Attribution | ✅ | ❌ | ❌ | ⚠️ (complex) |
| Easy to Use | ✅ | ⚠️ | ⚠️ | ❌ |
| No Dependencies | ✅ | ✅ | ❌ | ❌ |
| DNS Monitoring | ✅ | ⚠️ | ✅ | ⚠️ |
| TLS/SNI Visibility | ✅ | ❌ | ✅ | ❌ |
| Process Tree Tracking | ✅ | ❌ | ❌ | ❌ |

## License

This project uses a dual license approach:

- The Go code and overall project is licensed under the [Apache License 2.0](LICENSE)
- The BPF programs (in the `bpf/` directory) are licensed under GPL v2, as required for kernel integration

This approach ensures both kernel compatibility and flexibility for users of the library.

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md).
