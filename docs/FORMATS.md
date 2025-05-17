# BPFView Output Formats

BPFView supports multiple output formats to integrate with different analysis platforms and workflows. This guide explains the available formats and how to use them effectively.

## Format Overview

BPFView currently supports the following output formats:

| Format    | Description                                      | Integration Targets                     |
|-----------|--------------------------------------------------|----------------------------------------|
| Text      | Pipe-delimited text logs (default)               | Command-line analysis, grep, awk        |
| JSON      | Single structured JSON file                      | Generic JSON processing, custom tools   |
| JSON-ECS  | Elastic Common Schema JSON                       | Elasticsearch, Kibana                   |
| GELF      | Graylog Extended Log Format                      | Graylog                                 |
| SQLite    | SQLite database                                  | SQL analysis, database integration      |

## Selecting a Format

To specify the output format, use the `--format` flag:

```bash
# Text format (default)
sudo bpfview

# JSON format
sudo bpfview --format json

# Elastic Common Schema format
sudo bpfview --format json-ecs

# Graylog format
sudo bpfview --format gelf

# SQLite database
sudo bpfview --format sqlite
```

## Text Format (Default)

The text format creates separate log files with pipe-delimited fields for easy command-line analysis.

### Log Files

- `process.log`: Process execution, fork, and exit events
- `network.log`: Network connections with process attribution
- `dns.log`: DNS queries and responses
- `tls.log`: TLS handshakes with SNI and cipher information
- `sigma.log`: Sigma rule matches (if enabled)
- `binary.log`: Binary analysis results (if enabled)

### Example

```
timestamp|session_uid|process_uid|event_type|pid|ppid|uid_user|gid|comm|parent_comm|exe_path|binary_hash|cmdline|username|container_id|cwd|start_time|exit_time|exit_code|duration
2025-04-15T19:58:47.674451292Z|26d27091|b43317c5|EXEC|323583|311463|1000|1000|xmrig|bash|/tmp/mining_test/xmrig-6.21.0/xmrig|86f2790c04ccd113a564cc074efbcdfd|./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A|ec2-user|-|/tmp/mining_test/xmrig-6.21.0|2025-04-15T19:58:47.674451292Z|-|-|-
```

### Analysis with Text Format

The text format is optimized for command-line tools:

```bash
# Find all nginx processes
grep 'nginx' logs/process.log

# Track DNS requests for a specific domain
grep 'example.com' logs/dns.log

# Count connections by destination port
awk -F'|' '{print $14}' logs/network.log | sort | uniq -c | sort -nr

# Follow a process through its lifecycle
PROCESS_UID="b43317c5"
grep "$PROCESS_UID" logs/*.log
```

### Log Rotation

Text logs are automatically rotated when BPFView starts, preserving previous sessions with timestamp and session_uid.

## JSON Format

The JSON format writes all events to a single `events.json` file with each line containing a complete JSON object.

### Example

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

### Analysis with JSON Format

JSON format works well with tools like jq:

```bash
# Install jq if needed
sudo apt install jq   # Ubuntu/Debian
sudo yum install jq   # Amazon Linux/RHEL/CentOS

# Filter for specific events
cat logs/events.json | jq 'select(.event_type == "process_exec")'
cat logs/events.json | jq 'select(.event_type == "tls_handshake")'

# Filter by process
cat logs/events.json | jq 'select(.process.name == "curl")'

# Find processes accessing specific domains
cat logs/events.json | jq 'select(.event_type == "dns_query" and .dns.questions[].name | contains("example.com"))'

# Advanced analysis with process context
cat logs/events.json | jq 'select(.event_type == "process_exec" and .process.command_line | contains("sudo"))'
```

## JSON-ECS Format (Elastic Common Schema)

The JSON-ECS format follows the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html) for seamless integration with the Elastic Stack (Elasticsearch, Kibana, etc.).

### Example

```json
{
  "@timestamp": "2025-04-15T20:35:34.633110478Z",
  "ecs.version": "8.12.0",
  "event.type": "process",
  "event.subtype": "",
  "event.category": "process",
  "event.kind": "event",
  "event.dataset": "bpfview",
  "event.sequence": "42bf57cc",
  "event.action": "process_stopped",
  "event.outcome": "exit_code_3",
  "message": "process_exit: wget (PID: 325409)",
  "host.os.type": "linux",
  "host.os.kernel": "linux",
  "process.name": "wget",
  "process.pid": 325409,
  "process.executable": "/usr/bin/wget",
  "process.command_line": "wget https://www.example.com",
  "process.working_directory": "/home/ec2-user/bpfview/logs",
  "process.start": "2025-04-15T20:35:34.45432104Z",
  "process.end": "2025-04-15T20:35:34.641756128Z",
  "process.exit_code": 3,
  "process.duration": "187.435088ms",
  "process.parent.pid": 311463,
  "user.id": "1000",
  "user.name": "ec2-user",
  "user.group.id": "1000",
  "labels": {
    "process_uid": "",
    "session_uid": "42bf57cc"
  }
}
```

### Elastic Stack Integration

To integrate with Elasticsearch:

1. Configure Filebeat to read the events:

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /path/to/bpfview/logs/events.ecs.json
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

2. Create dashboards in Kibana for:
   - Process execution events
   - Network connections
   - DNS queries
   - TLS handshakes
   - Sigma detection matches

### Kibana Visualization Examples

Example Kibana queries:

```
# Find all process executions
event.type:process AND event.action:process_exec

# Find network connections to suspicious ports
event.type:network_flow AND destination.port:(4444 OR 8888 OR 31337)

# Show DNS queries for specific domains
event.type:dns AND dns.question.name:*example.com*

# View all Sigma detections
event.type:sigma
```

## GELF Format (Graylog)

The GELF format (Graylog Extended Log Format) is optimized for integration with Graylog.

### Example

```json
{
  "version": "1.1",
  "host": "ip-172-31-44-65.us-east-2.compute.internal",
  "short_message": "TLS handshake: www.example.com (TLS 1.2)",
  "timestamp": 1744749387.189833,
  "level": 6,
  "full_message": "TLS handshake: www.example.com (TLS 1.2)\n\nTLS Details:\nVersion: TLS 1.2\nServer Name: www.example.com\n\nSupported Cipher Suites:\n  1. 0x1302\n  2. 0x1303\n  ...",
  "_timestamp_human": "2025-04-15T20:36:27.189833043Z",
  "_event_type": "tls_handshake",
  "_event_category": "network",
  "_session_uid": "e51b81c7",
  "_process_uid": "ada0a9ce",
  "_network_uid": "8bb7fc23e8207b5c",
  "_community_id": "1:hGwz8hjWadgTBmaMGu7CG+d/TXw=",
  "_process_id": 325489,
  "_process_name": "wget",
  "_parent_id": 311463,
  "_parent_name": "bash",
  "_source_ip": "172.31.44.65",
  "_source_port": 36316,
  "_dest_ip": "23.55.220.147",
  "_dest_port": 443,
  "_tls_version": "TLS 1.2",
  "_tls_sni": "www.example.com",
  "_tls_cipher_suites": [
    "0x1302",
    "0x1303",
    "0x1301",
    "0x1304",
    "0xc030",
    "0xcca8",
    "0xc014",
    "0xc02f",
    "0xc013",
    "0xc02c"
  ],
  "_tls_ja4": "t13d3612h2_018971650b2c_89b78339ac4c",
  "_tls_ja4_hash": "66c38d1d91e43ce4fc953cd3dae25f9b"
}
```

### Graylog Integration

To integrate with Graylog:

1. Configure a GELF TCP or UDP input in Graylog
2. Use filebeat or another log shipper to send the GELF JSON logs to Graylog:

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /path/to/bpfview/logs/events.gelf.json
  json.keys_under_root: true
  json.add_error_key: true

output.logstash:
  hosts: ["graylog:5044"]
```

3. Create Graylog dashboards and alerts based on BPFView events

### Graylog Search Examples

```
# Find all process executions
_event_type:process_exec

# Track network connections by a specific process
_process_name:nginx

# Detect suspicious DNS queries 
_event_type:dns_query AND _dns_questions:*evil.com*

# Find modified system binaries
_binary_from_package:true AND _binary_package_verified:false
```

## SQLite Format

The SQLite format stores events in a structured database for SQL-based analysis.

### Database Structure

Main tables:
- `processes`: Process execution events
- `network_connections`: Network connection events
- `dns_events`: DNS queries and responses
- `tls_events`: TLS handshake events
- `sigma_matches`: Security detection matches
- `binary_events`: Binary analysis results

### SQL Analysis Examples

The SQLite format enables powerful SQL-based analysis:

```sql
-- Find processes connecting to suspicious ports
SELECT p.pid, p.comm, p.cmdline, p.exe_path, p.username, 
       n.dst_ip, n.dst_port, n.timestamp
FROM processes p
JOIN network_connections n ON p.process_uid = n.process_uid
WHERE n.dst_port IN (4444, 8888, 9999, 31337);

-- Identify potential DNS exfiltration
SELECT d.pid, d.comm, d.query, d.record_type, 
       LENGTH(d.query) as query_length, p.exe_path
FROM dns_events d
JOIN processes p ON d.process_uid = p.process_uid
WHERE LENGTH(d.query) > 50
AND d.event_type = 'query'
ORDER BY query_length DESC;

-- Find processes with suspicious timing between fork and exec
SELECT p1.pid, p1.comm, p2.comm, 
       (julianday(p2.timestamp) - julianday(p1.timestamp)) * 86400000 as delay_ms
FROM processes p1
JOIN processes p2 ON p1.pid = p2.pid
WHERE p1.event_type = 'fork' AND p2.event_type = 'exec'
AND delay_ms > 500;

-- Track modified system binaries
SELECT b.path, b.md5_hash, b.package_name, b.package_version,
       p.pid, p.comm, p.cmdline, p.username, p.timestamp
FROM binary_events b
JOIN processes p ON b.process_uid = p.process_uid
WHERE b.is_from_package = 1 AND b.package_verified = 0;
```

### Integration with Other Tools

The SQLite database can be used with various visualization and analysis tools:

```bash
# Export query results to CSV
sqlite3 -header -csv logs/bpfview.db \
  "SELECT process_uid, comm, cmdline, timestamp FROM processes" > processes.csv

# Use with data analysis tools
python3 -c "
import pandas as pd
import sqlite3
conn = sqlite3.connect('logs/bpfview.db')
df = pd.read_sql_query('SELECT * FROM processes', conn)
print(df.describe())
"
```

## Adding Host Information

For multi-host deployments, you can include host information in logs:

```bash
# Add hostname to all events
sudo bpfview --add-hostname

# Add host IP to all events
sudo bpfview --add-ip

# Both hostname and IP
sudo bpfview --add-hostname --add-ip
```

## Output Path Configuration

By default, logs are stored in the `./logs` directory. To change this:

```bash
# For SQLite format
sudo bpfview --format sqlite --dbfile /path/to/custom/bpfview.db

# For other formats, use symbolic links or mount points
ln -s /path/to/logs ./logs
```

## Performance Considerations

Different output formats have different performance characteristics:

- **Text**: Fastest, lowest resource usage
- **JSON/GELF**: Medium performance, higher disk usage
- **JSON-ECS**: Similar to JSON but with larger events
- **SQLite**: Highest resource usage, best for analysis

For high-volume environments, consider:

```bash
# Use text format with process exclusions
sudo bpfview --exclude-comm "chronyd,systemd-journal" --format text

# Use minimal process info with JSON
sudo bpfview --process-level minimal --format json
```

## Integration Examples

### Elastic Stack Pipeline

```bash
# Generate ECS output
sudo bpfview --format json-ecs --add-hostname --hash-binaries --sigma ./sigma

# Configure Filebeat to ship to Elasticsearch
# filebeat.yml configured as shown in ECS section
```

### Graylog Pipeline

```bash
# Generate GELF output
sudo bpfview --format gelf --hash-binaries --sigma ./sigma

# Ship GELF logs to Graylog
# Configure as shown in GELF section
```

### Custom Analysis Pipeline

```bash
# Generate SQLite database
sudo bpfview --format sqlite --dbfile /shared/bpfview.db

# Run analysis queries from separate system
sqlite3 /shared/bpfview.db < analysis_queries.sql
```
