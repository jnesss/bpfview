# BPFView Advanced Usage Guide

This guide covers advanced configuration options and features available in BPFView, focusing on fine-grained filtering, performance tuning, and integration options.

## Advanced Filtering Techniques

BPFView offers sophisticated filtering capabilities that can be combined for precise event selection.

### Process Filtering

```bash
# Filter by command name
sudo bpfview --comm nginx,php-fpm

# Filter by process ID
sudo bpfview --pid 1234,5678

# Filter by parent process ID
sudo bpfview --ppid 1000

# Filter by binary hash (requires --hash-binaries)
sudo bpfview --hash-binaries --binary-hash 9c30781b6d88fd2c8acebab96791fcb1

# Filter by username
sudo bpfview --user www-data,nginx

# Filter by executable path
sudo bpfview --exe "/usr/bin/python"

# Filter by container ID
sudo bpfview --container-id "3f4552dfc342"
sudo bpfview --container-id "*"  # Match any container
```

### Process Exclusion

```bash
# Exclude specific command names
sudo bpfview --exclude-comm "chronyd,systemd-journal"

# Exclude processes by executable path
sudo bpfview --exclude-exe-path "/usr/sbin/,/usr/lib/systemd/"

# Exclude specific users
sudo bpfview --exclude-user "nobody,www-data"

# Exclude specific containers
sudo bpfview --exclude-container "3f4552dfc342"

# Exclude specific network ports
sudo bpfview --exclude-port "80,443,53"
```

### Network Filtering

```bash
# Filter by protocol
sudo bpfview --protocol TCP,UDP

# Filter by source IP
sudo bpfview --src-ip 192.168.1.10,10.0.0.1

# Filter by destination IP
sudo bpfview --dst-ip 8.8.8.8,1.1.1.1

# Filter by source port
sudo bpfview --sport 22,8080

# Filter by destination port
sudo bpfview --dport 80,443
```

### DNS Filtering

```bash
# Filter by domain name (supports wildcards)
sudo bpfview --domain "*.example.com,evil.com"

# Filter by DNS record type
sudo bpfview --dns-type A,AAAA,CNAME
```

### TLS Filtering

```bash
# Filter by TLS version
sudo bpfview --tls-version 1.2,1.3

# Filter by SNI host (supports wildcards)
sudo bpfview --sni "*.google.com,bank.com"
```

### Combining Filters

Filters can be combined to create precise monitoring configurations:

```bash
# Monitor nginx instances connecting to specific domains
sudo bpfview --comm nginx --domain "*.internal.com,*.example.org"

# Track only SSH connections from a specific user
sudo bpfview --user admin --dport 22

# Monitor all container traffic except for specific ports
sudo bpfview --container-id "*" --exclude-port "80,443"

# Track all child processes of a specific application
sudo bpfview --comm "app-server" --tree
```

## Process Tree Tracking

The `--tree` option enables monitoring of all child processes spawned by matching processes:

```bash
# Track a web server and all its worker processes
sudo bpfview --comm "nginx" --tree

# Track all processes launched by a specific user
sudo bpfview --user admin --tree
```

This tracking persists even when child processes change their command name, helping to monitor complete process chains.

## Binary Analysis Configuration

BPFView can analyze binary files for additional security insights:

```bash
# Enable basic binary hashing
sudo bpfview --hash-binaries

# Enable binary hashing with package verification
sudo bpfview --hash-binaries --package-verify

# Specify a custom database path
sudo bpfview --hash-binaries --binary-db /path/to/custom/binaries.db
```

## Sigma Integration

Configure real-time detection with Sigma rules:

```bash
# Enable Sigma detection with default rules directory
sudo bpfview --sigma ./sigma

# Adjust queue size for high-volume environments
sudo bpfview --sigma ./sigma --sigma-queue-size 50000
```

## Process Information Level

Control how much process information is collected:

```bash
# Minimal process info (lowest overhead)
sudo bpfview --process-level minimal

# Basic process info (balanced)
sudo bpfview --process-level basic

# Full process info (most detailed)
sudo bpfview --process-level full
```

Process level details:
- **minimal**: Only kernel-provided data with almost no /proc access
- **basic**: Core process attributes (executable path, command line)
- **full**: Complete information including environment variables and container details

## Performance Optimization

Fine-tune BPFView's resource usage:

```bash
# Adjust process cache size
sudo bpfview --process-cache-size 5000

# Set cache entry timeout
sudo bpfview --cache-timeout 30m
```

## Output Configuration

### Log Levels

Control how much information is displayed in the console:

```bash
# Error level (minimal output)
sudo bpfview --log-level error

# Warning level
sudo bpfview --log-level warning

# Info level (default)
sudo bpfview --log-level info

# Debug level
sudo bpfview --log-level debug

# Trace level (maximum verbosity)
sudo bpfview --log-level trace
```

### Output Formats

BPFView supports multiple output formats:

```bash
# Text format (default) - pipe-delimited logs
sudo bpfview --format text

# JSON format - single events file
sudo bpfview --format json

# Elastic Common Schema format
sudo bpfview --format json-ecs

# Graylog Extended Log Format
sudo bpfview --format gelf

# SQLite database
sudo bpfview --format sqlite
```

### Output Customization

```bash
# Add timestamps to console output
sudo bpfview --log-timestamp

# Include hostname in all events
sudo bpfview --add-hostname

# Include host IP in all events
sudo bpfview --add-ip

# Specify a custom SQLite database path
sudo bpfview --format sqlite --dbfile /path/to/custom/bpfview.db
```

## Multi-Host Deployment

For distributed environments:

```bash
# Include host details for centralized collection
sudo bpfview --add-hostname --add-ip --format json-ecs
```

## Metrics Endpoint

BPFView exposes Prometheus metrics on port 2112 for monitoring event processing:

```bash
# View metrics
curl localhost:2112/metrics
```

## Command Combinations for Specific Use Cases

### Security Monitoring

```bash
# Comprehensive security monitoring
sudo bpfview --hash-binaries --package-verify --sigma ./sigma --format json-ecs

# Focus on suspicious TLS connections
sudo bpfview --hash-binaries --sigma ./sigma --tls-version 1.0,1.1
```

### Container Monitoring

```bash
# Monitor all container activity
sudo bpfview --container-id "*" --hash-binaries

# Focus on container network connections
sudo bpfview --container-id "*" --exclude-comm "chronyd,systemd" --format json
```

### High-Traffic Environments

```bash
# Optimize for high-volume servers
sudo bpfview --process-level minimal --exclude-comm "nginx,postgres" --exclude-port "80,443,5432"

# Reduce resource usage with focused monitoring
sudo bpfview --process-level basic --process-cache-size 5000 --cache-timeout 1h
```

### Forensic Analysis

```bash
# Detailed logging of all process activity
sudo bpfview --process-level full --hash-binaries --format sqlite --add-hostname --add-ip

# Track process trees of specific applications
sudo bpfview --comm "suspicious-app" --tree --hash-binaries --package-verify
```
