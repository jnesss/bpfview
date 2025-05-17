# BPFView Quick Start Guide

This guide covers the basic installation and setup of BPFView for various platforms.

## Installation

### Pre-compiled Binaries

BPFView provides pre-compiled binaries for:
- Amazon Linux 2023 (kernel 6.1)
- Ubuntu 24.04 LTS (kernel 6.8)

#### One-line Install
```bash
curl -sSL https://github.com/jnesss/bpfview/releases/latest/download/install.sh | sudo bash
```

### Platform Requirements

Minimum requirements:
- Linux kernel 5.8+ (for ring buffer support)
- BTF-enabled kernel
- CAP_BPF capability or root access

Verified platforms:
- Amazon Linux 2023 (kernel 6.1+)
- Ubuntu 24.04 LTS (kernel 6.8+)

### Building from Source

#### 1. Install Dependencies

```bash
# Install development dependencies
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-generic gcc-multilib make golang-go
```

#### 2. Build Limbo Database (Required Dependency)

```bash
# Clone Limbo repository
git clone https://github.com/tursodatabase/limbo
cd limbo/bindings/go
./build_lib.sh
```

#### 3. Build BPFView

```bash
# Clone BPFView repository
git clone https://github.com/jnesss/bpfview.git
cd bpfview

# Generate BTF headers if needed
# If your kernel doesn't provide BTF info, generate it with:
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Generate eBPF code and build BPFView
go generate
go build

# Verify installation
./bpfview --help
```

## Basic Usage

### Start Monitoring

```bash
# Basic process and network monitoring
sudo bpfview

# With binary hashing and verification
sudo bpfview --hash-binaries --package-verify

# With Sigma detection enabled
sudo bpfview --hash-binaries --sigma ./sigma

# Format output as JSON
sudo bpfview --format json
```

### View Logs

Logs are stored in the `./logs` directory by default:

```bash
# Process events
tail -f logs/process.log

# Network events
tail -f logs/network.log

# DNS events
tail -f logs/dns.log

# TLS events
tail -f logs/tls.log

# If using JSON format
tail -f logs/events.json | jq
```

## Common Use Cases

### Container Monitoring

```bash
# Monitor all containers
sudo bpfview --container-id "*"

# Monitor a specific container
sudo bpfview --container-id "3f4552dfc342"
```

### Network Traffic Analysis

```bash
# Monitor web traffic
sudo bpfview --dport 80,443

# Track outbound DNS traffic
sudo bpfview --dport 53 --protocol UDP
```

### Process Tracking

```bash
# Track specific process and children
sudo bpfview --comm nginx,php-fpm --tree

# Track user activity
sudo bpfview --user admin

# Track by command line pattern
sudo bpfview --cmdline "server --config"
```

### Security Monitoring

```bash
# Enable binary analysis and Sigma detection
sudo bpfview --hash-binaries --package-verify --sigma ./sigma

# With ECS output for Elasticsearch integration
sudo bpfview --hash-binaries --format json-ecs --sigma ./sigma
```

## Performance Considerations

For high-traffic environments, consider using process exclusion:

```bash
# Exclude common system processes
sudo bpfview --exclude-comm "chronyd,systemd-journal" --exclude-port "53,123"

# Use minimal process info level for better performance
sudo bpfview --process-level minimal
```

For more detailed performance tuning, see the [Performance Optimization Guide](PERFORMANCE.md).

## Next Steps

- Explore [Detection & Response](DETECTION.md) for security monitoring
- Learn about [Output Formats](FORMATS.md) for integration with other tools
- Configure [Advanced Usage](ADVANCED.md) options for complex environments
