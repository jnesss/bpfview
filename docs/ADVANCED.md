# BPFView Advanced Usage Guide

This guide covers advanced configuration options, deployment strategies, troubleshooting, and integration techniques for BPFView.

## Advanced Filtering Techniques

BPFView offers sophisticated filtering capabilities that can be combined for precise event selection.

### Complex Filter Combinations

```bash
# Monitor web servers and their child processes
sudo bpfview --comm "nginx,apache2" --tree

# Track activity in specific containers excluding system processes
sudo bpfview --container-id "*" --exclude-comm "chronyd,systemd-journal"

# Monitor specific domains and their subdomains
sudo bpfview --domain "*.example.com,*.internal.corp"

# Filter by executable and username simultaneously
sudo bpfview --exe "/usr/bin/python" --user admin,www-data
```

### Process Tree Tracking

The `--tree` option enables monitoring of all child processes spawned by matching processes:

```bash
# Track a specific service and all its children
sudo bpfview --comm "sshd" --tree

# Track all processes launched by a specific user
sudo bpfview --user admin --tree
```

This tracking persists even when child processes change their command name, helping to monitor complete process chains.

### Regex-Like Domain Filtering

Domain and SNI filters support wildcard matching:

```bash
# Match exact domain
sudo bpfview --domain "example.com"

# Match domain and all subdomains
sudo bpfview --domain "*.example.com"

# Match multiple patterns
sudo bpfview --domain "api.*.com,*.internal.corp"
```

### Fine-Grained Process Exclusion

For high-volume environments, process exclusion can significantly improve performance:

```bash
# Exclude by command name with wildcards
sudo bpfview --exclude-comm "kworker/*,jbd2/*"

# Exclude by executable path pattern
sudo bpfview --exclude-exe-path "/usr/lib/systemd/*,/usr/bin/python*"

# Exclude by username
sudo bpfview --exclude-user "nobody,www-data"

# Combine inclusion and exclusion
sudo bpfview --comm nginx --exclude-container "*" --exe-path "/usr/sbin/nginx"
```

## Advanced Configuration

### Customizing Process Information Level

The `--process-level` option controls how much process information is collected:

```bash
# Minimal - Only kernel-provided data with almost no /proc access
sudo bpfview --process-level minimal

# Basic - Core process info (executable path, command line)
sudo bpfview --process-level basic

# Full - Complete information including environment variables
sudo bpfview --process-level full
```

Use case comparison:
- **Minimal**: High-volume production servers (lowest overhead)
- **Basic**: General monitoring with good performance
- **Full**: Detailed forensic analysis and security monitoring

### Advanced Sigma Configuration

Customize Sigma detection behavior:

```bash
# Larger queue for high-volume environments
sudo bpfview --sigma ./rules --sigma-queue-size 50000

# Custom rules location with memory dumping enabled
sudo bpfview --sigma /etc/bpfview/rules --dump-dir /var/forensics/dumps
```

### Custom Database Configuration

For SQLite output, configure database location and options:

```bash
# Custom database path
sudo bpfview --format sqlite --dbfile /path/to/custom/bpfview.db

# Specify journal mode
sudo bpfview --format sqlite --dbfile :memory: --db-journal WAL
```

### Binary Analyzer Configuration

Configure the binary analyzer component:

```bash
# Custom binary metadata database path
sudo bpfview --hash-binaries --binary-db /path/to/database.db

# Adjust worker pool size for binary analysis
sudo bpfview --hash-binaries --binary-workers 4
```

## Production Deployment

### System Service Setup

Create a systemd service for persistent monitoring:

```ini
# /etc/systemd/system/bpfview.service
[Unit]
Description=BPFView Process and Network Monitoring
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bpfview --hash-binaries --package-verify --sigma /etc/bpfview/sigma --format json-ecs
Restart=on-failure
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable bpfview
sudo systemctl start bpfview
```

### Log Rotation Integration

Configure logrotate for BPFView logs:

```
# /etc/logrotate.d/bpfview
/var/log/bpfview/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl restart bpfview
    endscript
}
```

### Secure Deployment Recommendations

1. **Run with Limited Privileges**:
   - Create a dedicated service user
   - Use capabilities instead of root when possible
   - Configure secomp/apparmor profiles

2. **Secure Output Files**:
   - Set appropriate permissions on log directories
   - Use encrypted filesystems for sensitive logs
   - Implement fine-grained access controls

3. **Network Security**:
   - Restrict Prometheus metric endpoint
   - Use TLS for log shipping
   - Implement network segmentation

4. **Monitoring BPFView Itself**:
   - Set up alerts for BPFView service status
   - Monitor log file sizes and rotation
   - Track Prometheus metrics for health

### Multi-Host Deployment

For distributed environments:

1. **Centralized Collection**:
   - Use Filebeat/Logstash to ship logs to central location
   - Include `--add-hostname` and `--add-ip` for host identification
   - Configure consistent session UIDs across fleet

2. **Configuration Management**:
   - Use Ansible/Chef/Puppet for consistent deployment
   - Centralize Sigma rules distribution
   - Implement RBAC for configuration changes

3. **Scalability Considerations**:
   - Use `--process-level minimal` on high-traffic hosts
   - Implement appropriate exclusion filters based on host role
   - Configure resource limits based on system capacity

## Integration with Security Tools

### SIEM Integration

For Security Information and Event Management systems:

1. **Elastic Stack**:
   - Use `--format json-ecs` for direct Elasticsearch compatibility
   - Configure Kibana dashboards for BPFView events
   - Set up alerts based on Sigma matches

2. **Splunk**:
   - Use `--format json` and configure appropriate props/transforms
   - Create Splunk dashboards for process and network monitoring
   - Import MITRE ATT&CK framework for alerting

3. **Custom SIEM**:
   - Use structured output formats (JSON, ECS, or GELF)
   - Normalize timestamp and fields for correlation
   - Maintain unique identifiers for cross-event analysis

### Threat Hunting Integration

For active threat hunting:

1. **Hunting Queries**:
   - Create SQL templates for common hunting scenarios
   - Use process-network-DNS correlation for attack chain analysis
   - Implement JA4 fingerprinting for client behavior profiling

2. **Binary Analysis Integration**:
   - Search for modified system binaries
   - Profile statically linked binaries outside standard locations
   - Track binaries with unusual import patterns

3. **Automated Analysis**:
   - Integration with YARA for binary scanning
   - Memory dump integration with Volatility
   - Automated binary submission to sandbox environments

### Prometheus Integration

Configure additional metrics options:

```bash
# Custom Prometheus endpoint
sudo bpfview --metrics-addr "127.0.0.1:9100"

# Detailed metrics collection
sudo bpfview --detailed-metrics
```

Example Prometheus queries:
```
# Event processing rate
rate(bpfview_events_total[5m])

# Error rate by event type
rate(bpfview_processing_errors_total[5m])

# Process cache hit ratio
bpfview_cache_hits_total / (bpfview_cache_hits_total + bpfview_cache_misses_total)
```

## Advanced Troubleshooting

### Performance Issues

1. **High CPU Usage**:
   - Check for high-volume processes and exclude them:
     ```bash
     sudo bpfview --log-level debug --exclude-comm "high-volume-process"
     ```
   - Reduce process information level:
     ```bash
     sudo bpfview --process-level minimal
     ```
   - Check process cache hit ratio in metrics
   - Monitor eBPF map usage statistics

2. **Memory Usage Problems**:
   - Adjust process cache size:
     ```bash
     sudo bpfview --process-cache-size 5000
     ```
   - Set shorter cache timeout:
     ```bash
     sudo bpfview --cache-timeout 30m
     ```
   - Monitor memory usage with `pmap -x $(pidof bpfview)`

3. **Disk Space Issues**:
   - Implement log rotation
   - Use more selective filtering
   - For SQLite format, implement regular vacuuming:
     ```bash
     sqlite3 bpfview.db "VACUUM;"
     ```

### Debug Logging

Enable verbose logging for troubleshooting:

```bash
# Debug level logging
sudo bpfview --log-level debug

# Trace level for maximum verbosity (high volume!)
sudo bpfview --log-level trace
```

Inspect specific components:
```bash
# Follow debug logs for specific components
sudo bpfview --log-level debug | grep '\[binary\]'
sudo bpfview --log-level debug | grep '\[sigma\]'
```

### Common Error Resolution

1. **eBPF Verification Errors**:
   - Ensure kernel headers match running kernel
   - Check for BPF restrictions in seccomp profiles
   - Verify eBPF features are enabled in kernel

2. **Missing Events**:
   - Check process exclusion filters
   - Verify process level configuration
   - Ensure proper permissions for /proc access
   - Check for race conditions in high-volume environments

3. **Sigma Rule Issues**:
   - Validate rule syntax with `--log-level debug`
   - Check field names match exactly
   - Verify rule logsource category matches event type
   - Monitor sigma queue size with metrics

4. **Binary Analysis Failures**:
   - Check permissions for binary files
   - Verify package database access
   - Inspect specific binary analysis with debug logging
   - Check for library dependencies for ELF parsing

## Advanced Topics

### Custom Metrics Collection

BPFView's Prometheus metrics can be extended with custom metrics:

```bash
# Enable histogram metrics for latency analysis
sudo bpfview --with-histograms

# Enable per-process metrics collection
sudo bpfview --process-metrics
```

### Event Enrichment

Enhance events with additional context:

```bash
# Add GeoIP information for external connections
sudo bpfview --with-geoip

# Add process reputation data
sudo bpfview --with-reputation=/path/to/repodb
```

### CPU Pinning

For optimal performance on multi-core systems:

```bash
# Pin ring buffer processing to specific CPUs
sudo bpfview --cpu-pin 0,1,2,3

# Set process priority
sudo nice -n -10 bpfview
```

### Custom eBPF Map Configurations

Fine-tune eBPF map settings:

```bash
# Larger connection tracking table
sudo bpfview --conn-map-size 65536

# Custom process map size
sudo bpfview --process-map-size 16384
```

## Appendix: Environment Variables

BPFView respects several environment variables for configuration:

| Variable                   | Description                           | Example                         |
|----------------------------|---------------------------------------|---------------------------------|
| `BPFVIEW_LOG_LEVEL`        | Sets logging level                    | `export BPFVIEW_LOG_LEVEL=debug` |
| `BPFVIEW_LOG_DIR`          | Log directory                         | `export BPFVIEW_LOG_DIR=/var/log/bpfview` |
| `BPFVIEW_SIGMA_DIR`        | Sigma rules directory                 | `export BPFVIEW_SIGMA_DIR=/etc/sigma` |
| `BPFVIEW_FORMAT`           | Output format                         | `export BPFVIEW_FORMAT=json-ecs` |
| `BPFVIEW_PROCESS_LEVEL`    | Process info collection level         | `export BPFVIEW_PROCESS_LEVEL=basic` |
| `BPFVIEW_EXCLUDE_COMM`     | Processes to exclude                  | `export BPFVIEW_EXCLUDE_COMM="chronyd,sshd"` |
| `BPFVIEW_CACHE_SIZE`       | Process cache size                    | `export BPFVIEW_CACHE_SIZE=10000` |
| `BPFVIEW_CACHE_TIMEOUT`    | Cache entry timeout                   | `export BPFVIEW_CACHE_TIMEOUT=1h` |
| `BPFVIEW_METRICS_ADDR`     | Prometheus metrics endpoint           | `export BPFVIEW_METRICS_ADDR=":2112"` |
| `BPFVIEW_BINARY_DB`        | Binary analyzer database path         | `export BPFVIEW_BINARY_DB=/var/db/binary.db` |
