# BPFView Detection & Response

This guide covers the security detection and response capabilities of BPFView, including binary analysis and Sigma rule integration.

## Binary Analysis

BPFView's BinaryAnalyzer component enhances security monitoring by analyzing executables as they run.

### Key Capabilities

- **Binary Hashing**: Calculate MD5 and SHA256 hashes of executed binaries
- **ELF Analysis**: Extract metadata from ELF headers (type, architecture, symbols)
- **Package Verification**: Validate binaries against system package databases
- **Modified Binary Detection**: Identify tampered system files
- **Static/Dynamic Analysis**: Detect statically vs. dynamically linked binaries
- **Process-Binary Association**: Track which processes load which binaries

### Enabling Binary Analysis

```bash
# Basic binary hashing
sudo bpfview --hash-binaries

# Full analysis with package verification
sudo bpfview --hash-binaries --package-verify

# With custom database path
sudo bpfview --hash-binaries --binary-db /path/to/database.db
```

### Binary Analysis Events

BPFView generates detailed events whenever it analyzes a binary:

```json
{
  "timestamp": "2025-04-15T20:29:23.261786343Z",
  "session_uid": "e53f074a",
  "event_type": "binary_seen",
  "process_uid": "4fe5046b",
  "binary": {
    "path": "/usr/bin/python3",
    "md5_hash": "86f2790c04ccd113a564cc074efbcdfd",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_size": 4247784,
    "is_elf": true,
    "elf_type": "executable",
    "architecture": "x86_64",
    "interpreter": "/lib64/ld-linux-x86-64.so.2",
    "import_count": 247,
    "export_count": 32,
    "is_statically_linked": false,
    "is_from_package": true,
    "package_name": "python3-base",
    "package_version": "3.11.2-1.amzn2023.0.1",
    "package_verified": true,
    "package_manager": "rpm"
  },
  "message": "Binary observed: /usr/bin/python3 (executable x86_64)"
}
```

### Package Verification

When `--package-verify` is enabled, BPFView checks each binary against system package databases:

- **RPM Verification**: Uses `rpm -V` to check file integrity on RPM-based systems
- **DEB Verification**: Validates against `/var/lib/dpkg/info/*.md5sums` on Debian-based systems

Modified system binaries are flagged with:
```
package_verified: false
```

## Sigma Detection

BPFView integrates with the [Sigma](https://github.com/SigmaHQ/sigma) detection standard to provide real-time threat detection.

### Event Types

BPFView supports Sigma rules for multiple event categories:

1. **process_creation**: Process execution events
2. **network_connection**: Network connection events
3. **dns_query**: DNS request and response events
4. **binary**: Binary analysis results

### Enabling Sigma Detection

```bash
# Basic detection with default rules directory
sudo bpfview --sigma ./sigma

# With custom queue size for high-volume environments
sudo bpfview --sigma ./sigma --sigma-queue-size 20000

# Combining binary analysis and Sigma detection
sudo bpfview --hash-binaries --package-verify --sigma ./sigma
```

### Rule Structure

BPFView uses standard Sigma rule format:

```yaml
title: Suspicious Base64 Encoded Execution
id: 63e8d28c-4865-4c8f-900d-0d5461ea1b15
status: stable
description: Detects base64 encoded execution via command line
author: Your Name
date: 2025/04/10
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'echo'
      - 'bash -c'
    CommandLine|endswith: '| base64 -d | bash'
  condition: selection
falsepositives:
  - Legitimate administrative scripts
level: high
tags:
  - attack.execution
  - attack.t1059
actions:
  - type: terminate  # Kill process automatically
  - type: dump_memory  # Save process memory for forensic analysis
```

### Response Actions

BPFView supports the following response actions that can be triggered by Sigma rules:

1. **Process Termination** (`terminate`)
   - Immediately kills a process when a rule matches
   - Implemented using SIGKILL from userspace

2. **Network Access Blocking** (`block_network`)
   - Prevents a process from establishing new network connections
   - Implemented using eBPF LSM hooks

3. **Child Process Prevention** (`prevent_children`)
   - Blocks a process from creating new child processes
   - Implemented using eBPF LSM hooks for task creation
   
4. **Memory Dumping** (`dump_memory`)
   - Saves process memory at time of detection
   - Implemented by reading from /proc/[pid]/mem

### Detection Examples

#### Modified System Binary Detection

```yaml
title: Modified System Binary
id: 5a92c826-79f2-4709-bef4-18a7b1864fc2
status: stable
description: Detects execution of modified system binaries
author: BPFView Team
date: 2025/04/15
logsource:
  category: binary
  product: linux
detection:
  selection:
    IsFromPackage: true
    PackageVerified: false
  condition: selection
falsepositives:
  - Manual package modifications
level: high
tags:
  - attack.persistence
  - attack.t1574
actions:
  - type: alert
  - type: terminate
```

#### DNS Exfiltration Detection

```yaml
title: DNS Exfiltration Detection
id: 79ae0c3e-6721-4944-b5cf-8bde8bf2ca1a
status: stable
description: Detects potential DNS exfiltration
author: BPFView Team
date: 2025/04/15
logsource:
  category: dns_query
  product: linux
detection:
  selection:
    query|contains:
      - '.base64.'
      - '.encode.'
      - '.exfil.'
    query|endswith:
      - '.com'
      - '.net'
      - '.org'
    query|startswith|startswith|base64offset|contains:
      - 'data.'
    query|endswith|base64decode|endswith:
      - '='
  condition: selection
falsepositives:
  - Legitimate DNS-based services
level: medium
tags:
  - attack.exfiltration
  - attack.t1048
actions:
  - type: alert
  - type: block_network
```

#### Suspicious Binary Characteristics

```yaml
title: Statically Linked Non-Standard Binary
id: 1f2c3a45-6d7e-8f9a-0b1c-2d3e4f5a6b7c
status: stable
description: Detects execution of statically linked binaries outside of system directories
author: BPFView Team
date: 2025/04/15
logsource:
  category: binary
  product: linux
detection:
  selection:
    IsStaticallyLinked: true
  filter:
    Path|startswith:
      - '/usr/bin/'
      - '/usr/sbin/'
      - '/bin/'
      - '/sbin/'
  condition: selection and not filter
falsepositives:
  - Legitimate statically linked utilities
level: medium
tags:
  - attack.defense_evasion
  - attack.t1027
actions:
  - type: alert
```

## Real-World Example: Crypto Mining Detection

The following example shows a complete detection chain for cryptocurrency mining:

1. **Process Execution**:
```
[PROCESS] EXEC: PID=316331 comm=xmrig ProcessUID=907d6780
      Parent: [311463] bash
      User: ec2-user (1000/1000)
      Path: /tmp/mining_test/xmrig-6.21.0/xmrig
      CWD: /tmp/mining_test/xmrig-6.21.0
      Command: ./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A
```

2. **DNS Resolution**:
```
[DNS] QUERY: conn_uid=90cd423634c3c467 tx_id=0x72ba pid=316331 comm=xmrig
      172.31.44.65:44440 → 172.31.0.2:53
      DNS Flags: 0x0100, QR bit: false
      Q1: pool.minexmr.com (Type: A)
```

3. **Sigma Detection**:
```
[SIGMA] Match: Linux Crypto Mining Pool Connections (Level: high)
      Process: xmrig (PID: 316331, ProcessUID: 907d6780)
      Rule: Detects process connections to a Monero crypto mining pool
      Details: DestinationHostname equals 'pool.minexmr.com'
      MITRE: Impact (T1496)
```

4. **Automatic Response**:
```
[RESPONSE] Action: terminate executed for PID 316331
      Rule: Linux Crypto Mining Pool Connections
      Process: xmrig (316331)
      Action Result: Success
```

5. **Process Termination**:
```
[PROCESS] EXIT: PID=316331 comm=xmrig
      Parent: [311463] bash
      Exit Code: 9
      Duration: 1.298698204s
```

## Creating Your Own Rules

### Best Practices

1. **Rule Structure**:
   - Use clear, descriptive titles
   - Include MITRE ATT&CK mappings
   - Document possible false positives
   - Set appropriate severity levels

2. **Detection Logic**:
   - Start with specific indicators
   - Use multiple conditions for higher accuracy
   - Implement appropriate filters to reduce false positives
   - Test thoroughly in non-production environment first

3. **Rule Organization**:
   - Group rules logically in directories (e.g., by tactic, technique)
   - Use consistent naming conventions
   - Version control your rule sets

### Testing Rules

Test your rules thoroughly before using them in production:

```bash
# Run in debug mode to see rule processing details
sudo bpfview --sigma ./test-rules --log-level debug

# Intentionally trigger a rule for testing
./trigger-test.sh
```

## Troubleshooting Detection

### Common Issues

1. **Rule Not Matching**:
   - Verify field names match exactly (case-sensitive)
   - Check that value types match (string vs. number vs. boolean)
   - Ensure your rule's category matches the event type

2. **Performance Problems**:
   - Increase queue size: `--sigma-queue-size 50000`
   - Make conditions more specific
   - Reduce the number of rules
   - Use the `--process-level minimal` option

3. **False Positives**:
   - Add more specific conditions
   - Implement appropriate filters
   - Use multiple indicators instead of single patterns
