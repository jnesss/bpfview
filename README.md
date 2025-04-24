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

# Track activity of a specific container
sudo bpfview --container-id "3f4552dfc342"

# Enable Sigma rule detection
sudo bpfview --sigma ./sigma
```

## Key Features

- **Process Attribution**: Every network connection, DNS query, and TLS handshake is linked to its originating process
- **Community ID Flow Hashing**: Standard network flow correlation compatible with Zeek, Suricata, and other security tools
- **Binary Integrity**: Track and filter processes by executable MD5 hash
- **Container Awareness**: Automatic container detection and correlation
- **Environment Capture**: Full process environment variable tracking
- **DNS & TLS Inspection**: Domain name resolution and TLS handshake monitoring with SNI extraction
- **Performance Optimized**: Efficient eBPF programs with ring buffer communication
- **Real-time Sigma Detection**: Process behavior matching against Sigma rules with immediate alerts
- **Automatic Rule Reloading**: Dynamic rule updates without service restart
- **Rich Detection Context**: Full process and system context for each rule match
- **JA4 Fingerprinting**: Generate standardized JA4 fingerprints for TLS Client Hellos for threat actor identification and correlation

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
### Text Output Format View
```text
$ sudo ./bpfview --hash-binaries --sigma ./sigma --format text
System boot time: 2025-04-10T15:46:40Z
2025/04/15 19:58:45 Initializing process cache...
2025/04/15 19:58:45 Process cache initialized
2025/04/15 19:58:45 Loading network rule: Linux Reverse Shell Indicator (sigma/net_connection_lnx_back_connect_shell_dev.yml)
2025/04/15 19:58:45 Loading network rule: Linux Crypto Mining Pool Connections (sigma/net_connection_lnx_crypto_mining_indicators.yml)
2025/04/15 19:58:45 Loading network rule: Communication To LocaltoNet Tunneling Service Initiated - Linux (sigma/net_connection_lnx_domain_localtonet_tunnel.yml)
2025/04/15 19:58:45 Loading network rule: Communication To Ngrok Tunneling Service - Linux (sigma/net_connection_lnx_ngrok_tunnel.yml)
2025/04/15 19:58:45 Loading network rule: Potentially Suspicious Malware Callback Communication - Linux (sigma/net_connection_lnx_susp_malware_callback_port.yml)
2025/04/15 19:58:45 Loading process creation rule: Decode Base64 Encoded Text (sigma/proc_creation_lnx_base64_decode.yml)
2025/04/15 19:58:45 Started Sigma rule processing
2025/04/15 19:58:45 Sigma detection enabled:
2025/04/15 19:58:45   - Rules directory: ./sigma
2025/04/15 19:58:45   - Event queue size: 10000
2025/04/15 19:58:45 Initializing BPF programs...
2025/04/15 19:58:45 Attaching BPF programs...
2025/04/15 19:58:45 Successfully attached 11 BPF programs
2025/04/15 19:58:45 Setting up ringbuffer readers...
2025/04/15 19:58:45 Starting event monitoring...
Press Ctrl+C to stop

# process.log
timestamp|session_uid|process_uid|event_type|pid|ppid|uid_user|gid|comm|parent_comm|exe_path|binary_hash|cmdline|username|container_id|cwd|start_time|exit_time|exit_code|duration
2025-04-15T19:58:47.674451292Z|26d27091|b43317c5|EXEC|323583|311463|1000|1000|xmrig|bash|/tmp/mining_test/xmrig-6.21.0/xmrig|86f2790c04ccd113a564cc074efbcdfd|./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A|ec2-user|-|/tmp/mining_test/xmrig-6.21.0|2025-04-15T19:58:47.674451292Z|-|-|-

# network.log
timestamp|session_uid|process_uid|network_uid|community_id|pid|comm|ppid|parent_comm|protocol|src_ip|src_port|dst_ip|dst_port|direction|bytes|tcp_flags
2025-04-15T19:58:47.681084478Z|26d27091|b43317c5|d6cce83a127971e8|1:YSCxg8y33TGKoRN5q1SXHK0f9XY=|323583|xmrig|311463|bash|UDP|172.31.44.65|44355|172.31.0.2|53|>|62|-
2025-04-15T19:58:47.681110696Z|26d27091|b43317c5|d6cce83a127971e8|1:YSCxg8y33TGKoRN5q1SXHK0f9XY=|323583|xmrig|311463|bash|UDP|172.31.44.65|44355|172.31.0.2|53|>|62|-
2025-04-15T19:58:47.682173283Z|26d27091|b43317c5|d6cce83a127971e8|1:YSCxg8y33TGKoRN5q1SXHK0f9XY=|323583|xmrig|311463|bash|UDP|172.31.0.2|53|172.31.44.65|44355|<|122|-
2025-04-15T19:58:47.684441294Z|26d27091|b43317c5|d6cce83a127971e8|1:YSCxg8y33TGKoRN5q1SXHK0f9XY=|323583|xmrig|311463|bash|UDP|172.31.0.2|53|172.31.44.65|44355|<|122|-

# dns.log
timestamp|session_uid|process_uid|network_uid|community_id|dns_conversation_uid|pid|comm|ppid|parent_comm|event_type|dns_flags|query|type|txid|src_ip|src_port|dst_ip|dst_port|answers|ttl
2025-04-15T19:58:47.681099506Z|26d27091|b43317c5|d6cce83a127971e8|1:YSCxg8y33TGKoRN5q1SXHK0f9XY=|82afc580|323583|xmrig|311463|bash|QUERY|0x0100|pool.minexmr.com|A|0xbca7|172.31.44.65|44355|172.31.0.2|53|-|-
2025-04-15T19:58:47.681112099Z|26d27091|b43317c5|d6cce83a127971e8|1:YSCxg8y33TGKoRN5q1SXHK0f9XY=|8e9244b8|323583|xmrig|311463|bash|QUERY|0x0100|pool.minexmr.com|AAAA|0x719b|172.31.44.65|44355|172.31.0.2|53|-|-

# sigma.log
timestamp|session_uid|detection_source|rule_id|rule_name|rule_level|severity_score|rule_description|match_details|mitre_tactics|mitre_techniques|process_uid|process_name|process_path|process_cmdline|process_hash|process_start_time|pid|username|working_dir|parent_process_uid|parent_name|parent_path|parent_cmdline|parent_hash|parent_start_time|ppid|network_uid|community_id|dns_conversation_uid|src_ip|src_port|dst_ip|dst_port|protocol|direction|direction_desc|container_id|rule_references|tags
2025-04-15T19:58:47.681099506Z|26d27091|dns_query|a46c93b7-55ed-4d27-a41b-c259456c4746|Linux Crypto Mining Pool Connections|high|70|Detects process connections to a Monero crypto mining pool|'DestinationHostname' equals 'pool.minexmr.com'|Impact|T1496|b43317c5|xmrig|/tmp/mining_test/xmrig-6.21.0/xmrig|./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A|86f2790c04ccd113a564cc074efbcdfd|2025-04-15T19:58:47.674451292Z|323583|ec2-user|/tmp/mining_test/xmrig-6.21.0|90ed22d6|bash|/usr/bin/bash|-bash|abb8abb399698492682001a40813ebb5|2025-04-15T15:12:52.770964662Z|311463|d6cce83a127971e8|1:YSCxg8y33TGKoRN5q1SXHK0f9XY=|82afc580|172.31.44.65|44355|172.31.0.2|53|UDP|egress|Outgoing traffic to external service|-|https://www.poolwatch.io/coin/monero|
```

#### Correlation IDs listed above:
- session_uid ```26d27091```:  Identifies all events captured during this bpfview session
- process_uid ```b43317c5```:  Uniquely identifies the process involved across all log files
- network_uid ```d6cce83a127971e8```:  Correlates the network resquest/response, the DNS conversation, and the Sigma detection match
- community_id ```1:YSCxg8y33TGKoRN5q1SXHK0f9XY=```: Correlates the network, DNS, TLS, and Sigma results to external log sources
- dns_conversation_uid ```d6cce83a127971e8```:  Identifies the request and response for the A record for pool.minexmr.com

### JSON Output Format


#### Initial Process Execution
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

#### Network Connection for DNS lookup
```json
{
  "timestamp": "2025-04-15T20:15:06.963020024Z",
  "session_uid": "32476fd8",
  "event_type": "network_flow",
  "process_uid": "4fe5046b",
  "network_uid": "0f566ba38e122f9d",
  "community_id": "1:d/FNBJhX+PP7t/O6DEMHrGsG7y0="
  "process": {
    "pid": 324331,
    "comm": "xmrig",
    "ppid": 311463,
    "parent_comm": "bash"
  },
  "network": {
    "protocol": "UDP",
    "source_ip": "172.31.44.65",
    "source_port": 59267,
    "dest_ip": "172.31.0.2",
    "dest_port": 53,
    "direction": "egress",
    "direction_description": "Outgoing traffic to external service",
    "bytes": 62
  },
  "message": "Network connection: 172.31.44.65:59267 → 172.31.0.2:53 (udp)"
}
```

#### DNS Resolution
```json
{
  "timestamp": "2025-04-15T20:15:06.963029272Z",
  "session_uid": "32476fd8",
  "event_type": "dns_query",
  "process_uid": "4fe5046b",
  "network_uid": "0f566ba38e122f9d",
  "community_id": "1:d/FNBJhX+PP7t/O6DEMHrGsG7y0=",
  "dns_conversation_uid": "84ad6a0e",
  "process": {
    "pid": 324331,
    "comm": "xmrig",
    "ppid": 311463,
    "parent_comm": "bash"
  },
  "dns": {
    "type": "query",
    "flags": 256,
    "transaction_id": 52660,
    "questions": [
      {
        "name": "pool.minexmr.com",
        "type": "A",
        "class": 1
      }
    ]
  },
  "network": {
    "source_ip": "172.31.44.65",
    "source_port": 59267,
    "dest_ip": "172.31.0.2",
    "dest_port": 53
  },
  "message": "DNS query: pool.minexmr.com"
}
```

#### Sigma Detection
```json
{
  "timestamp": "2025-04-15T20:15:06.963029272Z",
  "session_uid": "32476fd8",
  "event_type": "sigma_match",
  "event_category": "network",
  "rule": {
    "id": "a46c93b7-55ed-4d27-a41b-c259456c4746",
    "name": "Linux Crypto Mining Pool Connections",
    "level": "high",
    "description": "Detects process connections to a Monero crypto mining pool",
    "match_details": "'DestinationHostname' equals 'pool.minexmr.com'",
    "references": [
      "https://www.poolwatch.io/coin/monero"
    ],
    "tags": [
      "attack.impact",
      "attack.t1496"
    ]
  },
  "process": {
    "process_uid": "4fe5046b",
    "pid": 324331,
    "name": "xmrig",
    "exe_path": "/tmp/mining_test/xmrig-6.21.0/xmrig",
    "command_line": "./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    "working_directory": "/tmp/mining_test/xmrig-6.21.0",
    "username": "ec2-user",
    "start_time": "2025-04-15T20:15:06.956325705Z",
    "binary_hash": "86f2790c04ccd113a564cc074efbcdfd",
    "environment": [
      "SHELL=/bin/bash",
      "HISTCONTROL=ignoredups",
      "SYSTEMD_COLORS=false",
      "HISTSIZE=1000",
      "HOSTNAME=ip-172-31-44-65.us-east-2.compute.internal",
      "PWD=/tmp/mining_test/xmrig-6.21.0",
      "LOGNAME=ec2-user",
      "XDG_SESSION_TYPE=tty",
      "MOTD_SHOWN=pam",
      "HOME=/home/ec2-user",
      "LANG=C.UTF-8",
      "LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=01;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=01;36:*.au=01;36:*.flac=01;36:*.m4a=01;36:*.mid=01;36:*.midi=01;36:*.mka=01;36:*.mp3=01;36:*.mpc=01;36:*.ogg=01;36:*.ra=01;36:*.wav=01;36:*.oga=01;36:*.opus=01;36:*.spx=01;36:*.xspf=01;36:",
      "SSH_CONNECTION=50.54.128.65 54057 172.31.44.65 22",
      "XDG_SESSION_CLASS=user",
      "SELINUX_ROLE_REQUESTED=",
      "TERM=xterm-256color",
      "LESSOPEN=||/usr/bin/lesspipe.sh %s",
      "USER=ec2-user",
      "SELINUX_USE_CURRENT_RANGE=",
      "SHLVL=1",
      "XDG_SESSION_ID=23",
      "XDG_RUNTIME_DIR=/run/user/1000",
      "S_COLORS=auto",
      "SSH_CLIENT=50.54.128.65 54057 22",
      "which_declare=declare -f",
      "PATH=/home/ec2-user/.local/bin:/home/ec2-user/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/usr/local/go/bin",
      "SELINUX_LEVEL_REQUESTED=",
      "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
      "MAIL=/var/spool/mail/ec2-user",
      "SSH_TTY=/dev/pts/1",
      "BASH_FUNC_which%%=() {  ( alias;\n eval ${which_declare} ) | /usr/bin/which --tty-only --read-alias --read-functions --show-tilde --show-dot \"$@\"\n}",
      "_=./xmrig",
      "OLDPWD=/home/ec2-user/bpfview/logs",
      ""
    ]
  },
  "parent_process": {
    "process_uid": "90ed22d6",
    "pid": 311463,
    "name": "bash",
    "exe_path": "/usr/bin/bash",
    "command_line": "-bash",
    "start_time": "2025-04-15T15:12:52.770964662Z",
    "binary_hash": "abb8abb399698492682001a40813ebb5"
  },
  "network": {
    "network_uid": "0f566ba38e122f9d",
    "community_id": "1:d/FNBJhX+PP7t/O6DEMHrGsG7y0=",
    "dns_conversation_uid": "84ad6a0e",
    "source_ip": "172.31.44.65",
    "source_port": 59267,
    "destination_ip": "172.31.0.2",
    "destination_port": 53,
    "direction": "egress",
    "destination_hostname": "pool.minexmr.com"
  },
  "message": "Sigma rule match: Linux Crypto Mining Pool Connections (Level: high) - Process: xmrig [324331]",
  "detection_source": "dns_query",
  "labels": {
    "session_uid": "32476fd8",
    "process_uid": "4fe5046b",
    "parent_uid": "90ed22d6",
    "network_uid": "0f566ba38e122f9d",
    "community_id": "1:d/FNBJhX+PP7t/O6DEMHrGsG7y0=",
    "dns_conversation_uid": "84ad6a0e"
  }
}
```

#### Process Termination
```json
{
  "timestamp": "2025-04-15T20:15:11.362956681Z",
  "session_uid": "32476fd8",
  "event_type": "process_exit",
  "process_uid": "",
  "process": {
    "pid": 324331,
    "comm": "xmrig",
    "ppid": 311463,
    "parent_comm": "",
    "uid": 1000,
    "gid": 1000,
    "exe_path": "/tmp/mining_test/xmrig-6.21.0/xmrig",
    "command_line": "./xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    "username": "ec2-user",
    "cwd": "/tmp/mining_test/xmrig-6.21.0",
    "start_time": "2025-04-15T20:15:06.956325705Z",
    "exit_time": "2025-04-15T20:15:11.362956681Z",
    "exit_description": "Success",
    "duration": "4.406630976s"
  },
  "message": "process_exit: xmrig (PID: 324331)"
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

### Enhanced Security Analysis

This comprehensive process tracking enables detection of sophisticated attacks:

- **Process Hollowing**: Detect unusual delays between fork and exec events that may indicate memory manipulation
- **Fork Bombs**: Identify processes that fork repeatedly without ever calling exec
- **Failed Executions**: Spot processes that attempt to execute non-existent binaries
- **Process Substitution**: Detect when a seemingly innocent process loads an unexpected executable

### SQLite Forensic Analysis

BPFView's SQLite output format stores each process event with its specific event type, enabling powerful forensic queries:

```sql
-- Find process exec/fork anomalies (fork without corresponding exec)
SELECT p1.pid, p1.comm, p1.process_uid, p1.timestamp 
FROM processes p1
WHERE p1.event_type = 'fork'
AND NOT EXISTS (
    SELECT 1 FROM processes p2
    WHERE p2.pid = p1.pid AND p2.event_type = 'exec'
);

-- Detect suspicious timing between fork and exec (potential process hollowing)
SELECT p1.pid, p1.comm, p2.comm, 
       p2.timestamp - p1.timestamp AS delay_microseconds
FROM processes p1
JOIN processes p2 ON p1.pid = p2.pid
WHERE p1.event_type = 'fork' AND p2.event_type = 'exec'
AND (p2.timestamp - p1.timestamp) > 500000; -- More than 500ms delay

-- Identify processes with unexpected exit codes
SELECT p1.pid, p1.comm, p3.exit_code, p1.cmdline
FROM processes p1
JOIN processes p3 ON p1.pid = p3.pid
WHERE p1.event_type = 'exec' AND p3.event_type = 'exit'
AND p3.exit_code > 0;
```

### Complete Process Timeline

BPFView gives you a comprehensive view of the entire process lifecycle:

```
[PROCESS] FORK: PID=442954 comm=setup-policy-ro ProcessUID=2ac5def9
      Parent: [443274] setup-policy-ro
      User: root (0/0)
      Path: /usr/bin/bash (inherited)
      CWD: / (inherited)
      Command: /usr/bin/bash /usr/bin/setup-policy-routes ens5 refresh (inherited)

[PROCESS] EXEC: PID=442954 comm=setup-policy-ro ProcessUID=4f8cef96
      Parent: [443274] setup-policy-ro
      User: root (0/0)
      Path: /usr/bin/bash
      CWD: /
      Command: /usr/bin/bash /usr/bin/setup-policy-routes ens5 refresh

[PROCESS] EXIT: PID=442954 comm=setup-policy-ro
      Parent: [443274] setup-policy-ro
      User: root (0/0)
      Exit Code: 0
      Duration: 125.784ms
```

This granular process tracing provides unparalleled visibility for security monitoring, troubleshooting, and performance analysis.

## Real-Time Response Actions

BPFView can not only detect suspicious activity but also take immediate response actions when threats are identified. These actions are triggered by Sigma rules and provide automated security enforcement with minimal performance impact.

### Available Response Actions

BPFView supports the following response actions that can be specified in Sigma rules:

1. **Process Termination** (`terminate`)
   - Immediately kills a process when a rule matches
   - Preserves process exit events in logs for forensic analysis

2. **Network Access Blocking** (`block_network`)
   - Prevents a process from establishing new network connections
   - Implemented using eBPF LSM hooks for kernel-level enforcement
   - Ideal for containing malware or preventing data exfiltration

3. **Child Process Prevention** (`prevent_children`)
   - Blocks a process from creating new child processes
   - Stops malware from spawning additional processes
   - Implemented using eBPF LSM hooks for task creation
   
4. **Dump Process Memory** (`dump_memory`)
   - Preserves process memory at the time of Sigma matching
   - Reads from /proc/pid/mem, does not PtraceAttach or send signal to process
   - Saves process metadata to file alongside dump

### Example Sigma Rules with Response Actions

```yaml
title: Python3 Process Termination Test
id: 59fc8b3d-d91a-4a3c-8f87-c65fe76371be
status: test
description: Detects python3 execution and terminates the process
author: Test Author
date: 2025/04/18
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ProcessName|contains:
      - python3
    Image|endswith:
      - /python3
      - /python3.9
  condition: selection
actions:
  - type: terminate
level: info
```

```yaml
title: Python3 Process Network Block Test
id: 79043c45-6176-4556-8e23-98a7c3e22b72
status: test
description: Detects python3 execution and blocks network access
author: Test Author
date: 2025/04/18
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ProcessName|contains:
      - python3
    Image|endswith:
      - /python3
  condition: selection
actions:
  - type: block_network
level: info
```

### Command Line Use

To enable response actions, simply run BPFView with the Sigma rules directory:

```bash
# Enable Sigma detection with response actions
sudo bpfview --sigma ./sigma
```

### Implementation Details

BPFView's response actions are implemented using a hybrid approach:
- Process termination is handled directly in userspace for maximum reliability
- Network and process creation blocking are enforced at the kernel level using eBPF LSM hooks
- All actions are logged with detailed context for auditing and forensic purposes

Response actions provide a powerful way to automatically contain threats as soon as they're detected, significantly reducing the time between detection and response in your security operations.


## Command Line Interface

BPFView offers comprehensive filtering capabilities that can be combined to precisely target what you want to monitor:

### Process Filtering (Selective Inclusion)
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

### Detection Options
```bash
# Enable Sigma detection with rules directory
sudo bpfview --sigma-rules /path/to/rules

# Configure detection queue size
sudo bpfview --sigma-rules ./rules --sigma-queue-size 20000
```

### Output Options
```bash
# Change log level
sudo bpfview --log-level debug

# Include timestamps in console output
sudo bpfview --log-timestamp

# Calculate binary hashes of executed binaries
sudo bpfview --hash-binaries

# Output format selection
sudo bpfview --format json  # Use JSON format (default: text)
sudo bpfview --format json-ecs  # Use Elastic Common Schema format
sudo bpfview --format gelf  # Use Graylog Extended Log Format
```

### Process Exclusions (Selective Exclusion)

BPFView allows you to exclude specific processes from monitoring, which is useful for filtering out high-volume system processes that aren't relevant to your analysis:

```bash
# Exclude processes by command name
sudo bpfview --exclude-comm "chronyd,bpfview"

# Exclude processes by executable path
sudo bpfview --exclude-exe-path "/usr/sbin/"

# Exclude processes by username
sudo bpfview --exclude-user "nobody,systemd-resolve" 

# Exclude processes by container ID
sudo bpfview --exclude-container "3f4552dfc342"

# Combine exclusions with inclusions
sudo bpfview --comm nginx --exclude-comm "chronyd,sshd"
```

Exclusions are evaluated during event processing and provide a high-performance way to filter out noisy system processes. When exclusions are enabled, BPFView reports metrics about excluded processes that can be viewed via the Prometheus endpoint.

## Performance Optimization

BPFView is designed to operate efficiently with minimal performance impact, but can be further optimized for specific environments and high-volume workloads.

For detailed information about performance features, tuning options, and monitoring capabilities, see the [Performance Optimization Guide](PERFORMANCE.md).

Key optimization features include:
- Process exclusion filters to ignore high-volume system processes
- Process information level control to reduce /proc filesystem access
- Cache size management for memory optimization
- Container-specific optimizations

The `--process-level` option provides three levels of detail collection:
- **full** (default): Complete process information including environment variables, working directory, and container details
- **basic**: Core process attributes (executable path, command line) with minimal /proc reads
- **minimal**: Only kernel-provided data with almost no /proc filesystem access

These features allow BPFView to scale from development environments to high-volume production servers while maintaining low overhead.

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
* **community_id**: Standardized network flow identifier compatible with Zeek, Suricata, and other network security tools (e.g., `1:DGVS3V8Lu7Pj+BRFwP5vh1+WX6g=`)
* **dns_conversation_uid**: Links DNS queries with their responses (e.g., `5551529`)

### Complete Log Examples

#### Process Events (process.log)
```
# Process execution with binary hash and environment details
timestamp|session_uid|process_uid|event_type|pid|ppid|uid_user|gid|comm|parent_comm|exe_path|binary_hash|cmdline|username|container_id|cwd|start_time|exit_time|exit_code|duration
2025-04-15T20:21:13.911446353Z|9cf3844b|7df935f6|EXEC|324614|311463|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-15T20:21:13.911446353Z|-|-|-
2025-04-15T20:21:13.928451561Z|9cf3844b||EXIT|324614|311463|1000|1000|curl|-|/usr/bin/curl|-|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-15T20:21:13.911446353Z|2025-04-15T20:21:13.928451561Z|0|17.005208ms
```

#### Network Events (network.log)
```
# Network connections with process attribution and byte counts and TCP flags
timestamp|session_uid|process_uid|network_uid|community_id|pid|comm|ppid|parent_comm|protocol|src_ip|src_port|dst_ip|dst_port|direction|bytes|tcp_flags
2025-04-15T20:21:13.928921649Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|TCP|172.31.44.65|37176|23.202.93.28|443|>|60|SYN
2025-04-15T20:21:13.938474097Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|TCP|23.202.93.28|443|172.31.44.65|37176|<|60|SYN,ACK
2025-04-15T20:21:13.938510735Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|TCP|172.31.44.65|37176|23.202.93.28|443|>|52|ACK
2025-04-15T20:21:13.940705012Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|TCP|172.31.44.65|37176|23.202.93.28|443|>|569|PSH,ACK
2025-04-15T20:21:13.950270313Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|TCP|23.202.93.28|443|172.31.44.65|37176|<|52|ACK
2025-04-15T20:21:13.951504127Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|TCP|23.202.93.28|443|172.31.44.65|37176|<|2948|PSH,ACK
```

#### DNS Events (dns.log)
```
# Full DNS query/response chain with CNAME resolution
timestamp|session_uid|process_uid|network_uid|community_id|dns_conversation_uid|pid|comm|ppid|parent_comm|event_type|dns_flags|query|type|txid|src_ip|src_port|dst_ip|dst_port|answers|ttl
2025-04-15T20:21:13.917469825Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|86f112ea|324614|curl|311463|bash|QUERY|0x0100|www.apple.com|A|0x08a0|172.31.44.65|54732|172.31.0.2|53|-|-
2025-04-15T20:21:13.9174856Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|c3bc8fe2|324614|curl|311463|bash|QUERY|0x0100|www.apple.com|AAAA|0xf59c|172.31.44.65|54732|172.31.0.2|53|-|-
2025-04-15T20:21:13.918948405Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|86f112ea|324614|curl|311463|bash|RESPONSE|0x8180|www.apple.com|CNAME|0x08a0|172.31.0.2|53|172.31.44.65|54732|www-apple-com.v.aaplimg.com|142
2025-04-15T20:21:13.918948405Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|86f112ea|324614|curl|311463|bash|RESPONSE|0x8180|www-apple-com.v.aaplimg.com|CNAME|0x08a0|172.31.0.2|53|172.31.44.65|54732|www.apple.com.edgekey.net|142
2025-04-15T20:21:13.918948405Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|86f112ea|324614|curl|311463|bash|RESPONSE|0x8180|www.apple.com.edgekey.net|CNAME|0x08a0|172.31.0.2|53|172.31.44.65|54732|e6858.dsce9.akamaiedge.net|142
2025-04-15T20:21:13.918948405Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|86f112ea|324614|curl|311463|bash|RESPONSE|0x8180|e6858.dsce9.akamaiedge.net|A|0x08a0|172.31.0.2|53|172.31.44.65|54732|23.202.93.28|5
2025-04-15T20:21:13.92822166Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|c3bc8fe2|324614|curl|311463|bash|RESPONSE|0x8180|www.apple.com|CNAME|0xf59c|172.31.0.2|53|172.31.44.65|54732|www-apple-com.v.aaplimg.com|142
2025-04-15T20:21:13.92822166Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|c3bc8fe2|324614|curl|311463|bash|RESPONSE|0x8180|www-apple-com.v.aaplimg.com|CNAME|0xf59c|172.31.0.2|53|172.31.44.65|54732|www.apple.com.edgekey.net|142
2025-04-15T20:21:13.92822166Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|c3bc8fe2|324614|curl|311463|bash|RESPONSE|0x8180|www.apple.com.edgekey.net|CNAME|0xf59c|172.31.0.2|53|172.31.44.65|54732|e6858.dsce9.akamaiedge.net|142
2025-04-15T20:21:13.92822166Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|c3bc8fe2|324614|curl|311463|bash|RESPONSE|0x8180|e6858.dsce9.akamaiedge.net|AAAA|0xf59c|172.31.0.2|53|172.31.44.65|54732|2600:1407:3c00:1aa0::1aca|20
2025-04-15T20:21:13.92822166Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|c3bc8fe2|324614|curl|311463|bash|RESPONSE|0x8180|e6858.dsce9.akamaiedge.net|AAAA|0xf59c|172.31.0.2|53|172.31.44.65|54732|2600:1407:3c00:1aa1::1aca|20
```

#### TLS Events (tls.log)
```
# TLS handshake details including cipher suites, supported groups, and JA4 fingerprint
timestamp|session_uid|process_uid|network_uid|community_id|pid|comm|ppid|parent_comm|src_ip|src_port|dst_ip|dst_port|version|sni|cipher_suites|supported_groups|handshake_length|ja4|ja4_hash
2025-04-15T20:21:13.940716292Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|172.31.44.65|37176|23.202.93.28|443|TLS 1.0|www.apple.com|0x1302,0x1303,0x1301,0x1304,0xc02c,0xc030,0xcca9,0xcca8,0xc0ad,0xc02b|x25519,secp256r1,x448,secp521r1,secp384r1,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192|508|q0t1dapplez508ahttp2c1302|aeb3f012e851713acbf3b08b0cee2eba
```

#### Sigma Events (sigma.log)
```
# Behavior matching against Sigma rules with immediate alerts
timestamp|session_uid|detection_source|rule_id|rule_name|rule_level|severity_score|rule_description|match_details|mitre_tactics|mitre_techniques|process_uid|process_name|process_path|process_cmdline|process_hash|process_start_time|pid|username|working_dir|parent_process_uid|parent_name|parent_path|parent_cmdline|parent_hash|parent_start_time|ppid|network_uid|community_id|dns_conversation_uid|src_ip|src_port|dst_ip|dst_port|protocol|direction|direction_desc|container_id|rule_references|tags
2025-04-15T20:24:39.214844757Z|bbd246fc|process_creation|e2072cab-8c9a-459b-b63c-40ae79e27031|Decode Base64 Encoded Text|low|30|Detects usage of base64 utility to decode arbitrary base64-encoded text|'Image' endswith '/base64' WITH 'CommandLine' contains '-d'|Defense-Evasion|T1027|bb020aea|base64|/usr/bin/base64|base64 -d|d7523068e26db58aa6f29839e91b86eb|2025-04-15T20:24:39.214844757Z|324779|ec2-user|/home/ec2-user/bpfview/logs|90ed22d6|bash|/usr/bin/bash|-bash|abb8abb399698492682001a40813ebb5|2025-04-15T15:12:52.770964662Z|311463|-|-|-|-|-|-|-|-|-|-|-|https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md|
```

### Analysis Examples

#### Trace DNS Resolution Chain
```bash
# Find DNS requests for apple.com
$ grep apple.com dns.log | grep QUERY
2025-04-15T20:21:13.917469825Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|86f112ea|324614|curl|311463|bash|QUERY|0x0100|www.apple.com|A|0x08a0|172.31.44.65|54732|172.31.0.2|53|-|-
2025-04-15T20:21:13.9174856Z|9cf3844b|7df935f6|e7f9889571112233|1:LQU9qZlK+B5F3KDmev6m5PMibrg=|c3bc8fe2|324614|curl|311463|bash|QUERY|0x0100|www.apple.com|AAAA|0xf59c|172.31.44.65|54732|172.31.0.2|53|-|-

# Find the process that initiated those DNS requests
$ grep 7df935f6 process.log 
2025-04-15T20:21:13.911446353Z|9cf3844b|7df935f6|EXEC|324614|311463|1000|1000|curl|bash|/usr/bin/curl|9c30781b6d88fd2c8acebab96791fcb1|curl https://www.apple.com|ec2-user|-|/home/ec2-user/bpfview/logs|2025-04-15T20:21:13.911446353Z|-|-|-
```

#### Follow Network Connection Chain
```bash
# Find a TLS connection
$ grep apple.com tls.log 
2025-04-15T20:21:13.940716292Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|172.31.44.65|37176|23.202.93.28|443|TLS 1.0|www.apple.com|0x1302,0x1303,0x1301,0x1304,0xc02c,0xc030,0xcca9,0xcca8,0xc0ad,0xc02b|x25519,secp256r1,x448,secp521r1,secp384r1,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192|508|q0t1dapplez508ahttp2c1302|aeb3f012e851713acbf3b08b0cee2eba

# Find corresponding network traffic
$ grep fdaa795fe689e39d network.log  | head -1
2025-04-15T20:21:13.928921649Z|9cf3844b|7df935f6|fdaa795fe689e39d|1:6pJiG+rf3CQf7TqoqzIcjZHQwWk=|324614|curl|311463|bash|TCP|172.31.44.65|37176|23.202.93.28|443|>|60|SYN
```

### Sigma Detection Events

BPFView supports real-time Sigma rule detection:

```bash
# Enable Sigma detection with default rules directory
sudo bpfview --sigma ./sigma

# Customize detection queue size
sudo bpfview --sigma-rules ./rules --sigma-queue-size 20000
```

Detection events are logged in all supported formats:

#### Text Format (sigma.log)
```
timestamp|session_uid|detection_source|rule_id|rule_name|rule_level|severity_score|rule_description|match_details|mitre_tactics|mitre_techniques|process_uid|process_name|process_path|process_cmdline|process_hash|process_start_time|pid|username|working_dir|parent_process_uid|parent_name|parent_path|parent_cmdline|parent_hash|parent_start_time|ppid|network_uid|community_id|dns_conversation_uid|src_ip|src_port|dst_ip|dst_port|protocol|direction|direction_desc|container_id|rule_references|tags
2025-04-15T20:24:39.214844757Z|bbd246fc|process_creation|e2072cab-8c9a-459b-b63c-40ae79e27031|Decode Base64 Encoded Text|low|30|Detects usage of base64 utility to decode arbitrary base64-encoded text|'Image' endswith '/base64' WITH 'CommandLine' contains '-d'|Defense-Evasion|T1027|bb020aea|base64|/usr/bin/base64|base64 -d|d7523068e26db58aa6f29839e91b86eb|2025-04-15T20:24:39.214844757Z|324779|ec2-user|/home/ec2-user/bpfview/logs|90ed22d6|bash|/usr/bin/bash|-bash|abb8abb399698492682001a40813ebb5|2025-04-15T15:12:52.770964662Z|311463|-|-|-|-|-|-|-|-|-|-|-|https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md|
```

#### JSON Format
```json
{
  "timestamp": "2025-04-15T20:29:23.261786343Z",
  "session_uid": "e53f074a",
  "event_type": "sigma_match",
  "event_category": "process",
  "rule": {
    "id": "e2072cab-8c9a-459b-b63c-40ae79e27031",
    "name": "Decode Base64 Encoded Text",
    "level": "low",
    "description": "Detects usage of base64 utility to decode arbitrary base64-encoded text",
    "match_details": "'Image' endswith '/base64' WITH 'CommandLine' contains '-d'",
    "references": [
      "https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md"
    ],
    "tags": [
      "attack.defense-evasion",
      "attack.t1027"
    ]
  },
  "process": {
    "process_uid": "28032300",
    "pid": 325004,
    "name": "base64",
    "exe_path": "/usr/bin/base64",
    "command_line": "base64 -d",
    "working_directory": "/home/ec2-user/bpfview/logs",
    "username": "ec2-user",
    "start_time": "2025-04-15T20:29:23.261786343Z",
    "binary_hash": "d7523068e26db58aa6f29839e91b86eb",
    "environment": [
      "SHELL=/bin/bash",
      "HISTCONTROL=ignoredups",
...
      "OLDPWD=/tmp/mining_test/xmrig-6.21.0",
      ""
    ]
  },
  "parent_process": {
    "process_uid": "90ed22d6",
    "pid": 311463,
    "name": "bash",
    "exe_path": "/usr/bin/bash",
    "command_line": "-bash",
    "start_time": "2025-04-15T15:12:52.770964662Z",
    "binary_hash": "abb8abb399698492682001a40813ebb5"
  },
  "message": "Sigma rule match: Decode Base64 Encoded Text (Level: low) - Process: base64 [325004]",
  "detection_source": "process_creation",
  "labels": {
    "session_uid": "e53f074a",
    "process_uid": "28032300",
    "parent_uid": "90ed22d6"
  }
}
```

#### ECS Format
```json
{
  "@timestamp": "2025-04-15T20:31:25.726083486Z",
  "ecs.version": "8.12.0",
  "event.type": "sigma",
  "event.subtype": "process_creation",
  "event.category": "process",
  "event.kind": "alert",
  "event.dataset": "bpfview",
  "event.sequence": "9eec2e97",
  "event.action": "detection",
  "event.outcome": "success",
  "message": "Sigma rule match: Decode Base64 Encoded Text (Level: low) - Process: base64 [325162]",
  "host.os.type": "linux",
  "host.os.kernel": "linux",
  "process.name": "base64",
  "process.pid": 325162,
  "process.executable": "/usr/bin/base64",
  "process.command_line": "base64 -d",
  "process.working_directory": "/home/ec2-user/bpfview/logs",
  "process.hash.md5": "d7523068e26db58aa6f29839e91b86eb",
  "process.env": [
    "SHELL=/bin/bash",
    "HISTCONTROL=ignoredups",
...
    "OLDPWD=/tmp/mining_test/xmrig-6.21.0",
    ""
  ],
  "process.start": "2025-04-15T20:31:25.722137518Z",
  "process.parent.name": "bash",
  "process.parent.pid": 311463,
  "process.parent.executable": "/usr/bin/bash",
  "process.parent.command_line": "-bash",
  "process.parent.hash.md5": "abb8abb399698492682001a40813ebb5",
  "process.parent.start": "2025-04-15T15:12:52.770964662Z",
  "user.id": "1000",
  "user.name": "ec2-user",
  "user.group.id": "1000",
  "rule.id": "e2072cab-8c9a-459b-b63c-40ae79e27031",
  "rule.name": "Decode Base64 Encoded Text",
  "rule.description": "Detects usage of base64 utility to decode arbitrary base64-encoded text",
  "rule.level": "low",
  "rule.reference": [
    "https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md"
  ],
  "rule.tags": [
    "attack.defense-evasion",
    "attack.t1027"
  ],
  "rule.matched_details": "'Image' endswith '/base64' WITH 'CommandLine' contains '-d'",
  "rule.matched_fields": {
    "details": "'Image' endswith '/base64' WITH 'CommandLine' contains '-d'"
  },
  "labels": {
    "process_uid": "bb24a688",
    "session_uid": "9eec2e97"
  }
}
```

#### GELF Format 
```json
{
  "version": "1.1",
  "host": "ip-172-31-44-65.us-east-2.compute.internal",
  "short_message": "sigma_match: Decode Base64 Encoded Text (Level: low) - Process: base64 [325247]",
  "timestamp": 1744749158.052693,
  "level": 6,
  "full_message": "sigma_match: Decode Base64 Encoded Text (Level: low) - Process: base64 [325247]\n\nRule Details:\nID: e2072cab-8c9a-459b-b63c-40ae79e27031\nDescription: Detects usage of base64 utility to decode arbitrary base64-encoded text\nMatch Details: 'Image' endswith '/base64' WITH 'CommandLine' contains '-d'\n\nReferences:\n  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md\n\nTags:\n  - attack.defense-evasion\n  - attack.t1027\n\nProcess Details:\nName: base64 (PID: 325247)\nCommand: base64 -d\nWorking Directory: /home/ec2-user/bpfview/logs\nUsername: ec2-user\n",
  "_rule_id": "e2072cab-8c9a-459b-b63c-40ae79e27031",
  "_rule_name": "Decode Base64 Encoded Text",
  "_rule_level": "low",
  "_rule_description": "Detects usage of base64 utility to decode arbitrary base64-encoded text",
  "_match_details": "'Image' endswith '/base64' WITH 'CommandLine' contains '-d'",
  "_rule_references": [
    "https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md"
  ],
  "_rule_tags": [
    "attack.defense-evasion",
    "attack.t1027"
  ],
  "_timestamp_human": "2025-04-15T20:32:38.052692913Z",
  "_event_type": "sigma_match",
  "_event_category": "",
  "_session_uid": "cec2073e",
  "_process_uid": "d1e17a56",
  "_process_id": 325247,
  "_process_name": "base64",
  "_parent_id": 311463,
  "_cmdline": "base64 -d",
  "_username": "ec2-user",
  "_working_dir": "/home/ec2-user/bpfview/logs"
}
```

## Output Formats

BPFView supports multiple output formats:

### Text Format (Default)
Traditional pipe-delimited logs split into process.log, network.log, dns.log, tls.log, and sigma.log files. Optimized for grep and command-line analysis.

### JSON Format
Single events.json file with structured JSON events. Each line is a complete JSON object containing:
- Process execution and exit events with full context and human-readable messages
- Network flows with protocol details, byte counts, and direction descriptions
- DNS queries and responses with full CNAME chains
- TLS handshakes with cipher suites and JA4 fingerprints

```bash
# Generate standard JSON logs
sudo bpfview --format json

# View with jq for pretty formatting
cat logs/events.json | jq
```

Example JSON output:
```json
{
  "timestamp": "2025-04-15T20:29:23.566463869Z",
  "session_uid": "e53f074a",
  "event_type": "network_flow",
  "process_uid": "ed38b9e4",
  "network_uid": "ab817774e6d607fe",
  "community_id": "1:P3qmhAtpONF0G0I7XDN83xd0Kzc="
  "process": {
    "pid": 1617,
    "comm": "chronyd",
    "ppid": 1,
    "parent_comm": "systemd"
  },
  "network": {
    "protocol": "UDP",
    "source_ip": "172.31.44.65",
    "source_port": 57306,
    "dest_ip": "169.254.169.123",
    "dest_port": 123,
    "direction": "egress",
    "direction_description": "Outgoing traffic to external service",
    "bytes": 76
  },
  "message": "Network connection: 172.31.44.65:57306 → 169.254.169.123:123 (udp)"
}

```

### Elastic Common Schema (ECS) Format
Structured JSON format compatible with Elastic Stack (Elasticsearch, Kibana, etc.). Each event follows the standardized [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html) for easy integration with existing ELK deployments.

```bash
# Generate ECS-compatible logs
sudo bpfview --format json-ecs

# View with jq for pretty formatting
cat logs/events.ecs.json | jq
```

Example ECS output:
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
  "user.parent.id": "0",
  "user.parent.group.id": "0",
  "labels": {
    "process_uid": "",
    "session_uid": "42bf57cc"
  }
}
```

### GELF Format (Graylog)
[Graylog Extended Log Format](https://docs.graylog.org/docs/gelf) for direct integration with Graylog log management. Includes structured fields with underscore prefixes for custom fields.

```bash
# Generate GELF-compatible logs
sudo bpfview --format gelf

# View with jq for pretty formatting
cat logs/events.gelf.json | jq '.'
```

Example GELF output:
```json
{
  "version": "1.1",
  "host": "ip-172-31-44-65.us-east-2.compute.internal",
  "short_message": "TLS handshake: www.example.com (TLS 1.2)",
  "timestamp": 1744749387.189833,
  "level": 6,
  "full_message": "TLS handshake: www.example.com (TLS 1.2)\n\nTLS Details:\nVersion: TLS 1.2\nServer Name: www.example.com\n\nSupported Cipher Suites:\n  1. 0x1302\n  2. 0x1303\n  3. 0x1301\n  4. 0x1304\n  5. 0xc030\n  6. 0xcca8\n  7. 0xc014\n  8. 0xc02f\n  9. 0xc013\n  10. 0xc02c\n\nFingerprinting:\n  JA4: q0t3dexamplez508a_c1302\n  JA4 Hash: 66c38d1d91e43ce4fc953cd3dae25f9b\n\nProcess Details:\nProcess: wget (PID: 325489)\nParent: bash (PPID: 311463)\n\nConnection Details:\nSource: 172.31.44.65:36316\nDestination: 23.55.220.147:443\n",
  "_rule_id": "",
  "_rule_name": "",
  "_rule_level": "",
  "_rule_description": "",
  "_match_details": "",
  "_rule_references": null,
  "_rule_tags": null,
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
  "_tls_ja4": "q0t3dexamplez508a_c1302",
  "_tls_ja4_hash": "66c38d1d91e43ce4fc953cd3dae25f9b"
}
```

### Viewing JSON Logs

For all JSON formats, the `jq` utility is recommended for viewing and filtering:

```bash
# Install jq if needed
sudo apt install jq   # Ubuntu/Debian
sudo yum install jq   # Amazon Linux/RHEL/CentOS

# Filter for specific events
cat logs/events.json | jq 'select(.event_type == "process_exec")'
cat logs/events.ecs.json | jq 'select(."event.type" == "tls")'
cat logs/events.gelf.json | jq 'select(._event_type == "dns_query")'

# Filter by process
cat logs/events.json | jq 'select(.process.name == "curl")'
cat logs/events.ecs.json | jq 'select(."process.name" == "nginx")'

# Extract session correlation data
cat logs/events.gelf.json | jq 'select(._conversation_id != null) | {timestamp, process: ._process_name, dns: ._dns_questions, conversation: ._conversation_id}'
```

## Design Principles

BPFView is built with several core design principles in mind:

1. **Immediate Event Processing**: Events are logged as they occur without batching
2. **Unified Correlation**: Every event is linked to its process context
3. **Granular Filtering**: Filter at multiple levels (process, network, DNS, TLS)
4. **Human-Readable Formats**: Logs are easily read by both humans and machine parsers
5. **Minimal Performance Impact**: Efficient BPF programs with low overhead
6. **No External Dependencies**: Single binary with no runtime dependencies

## Prometheus Metrics

BPFView exposes Prometheus metrics on port 2112 for monitoring event processing:

```bash
# View metrics
curl localhost:2112/metrics
```

### Available Metrics

| Metric Name | Labels | Description |
|-------------|--------|-------------|
| bpfview_events_total | event_type | Total number of events processed by type (process, network, dns, tls, response) |
| bpfview_processing_errors_total | event_type | Total number of event processing errors by type |

### Example Output

```
# HELP bpfview_events_total Total number of events processed by type
# TYPE bpfview_events_total counter
bpfview_events_total{event_type="dns"} 4
bpfview_events_total{event_type="network"} 680
bpfview_events_total{event_type="process"} 929
bpfview_events_total{event_type="tls"} 1

# HELP bpfview_processing_errors_total Total number of event processing errors by type
# TYPE bpfview_processing_errors_total counter
bpfview_processing_errors_total{event_type="dns"} 0
bpfview_processing_errors_total{event_type="network"} 2
bpfview_processing_errors_total{event_type="process"} 0
bpfview_processing_errors_total{event_type="tls"} 0
```

### Prometheus Configuration

Add this job to your Prometheus config to scrape BPFView metrics:

```yaml
scrape_configs:
  - job_name: 'bpfview'
    static_configs:
      - targets: ['localhost:2112']
```

These metrics enable monitoring of:

- Event processing volume by type
- Error rates and types
- System health and performance

The metrics endpoint is automatically enabled when BPFView starts, with no additional configuration required.

## Feature Comparison

| Feature | BPFView | tcpdump | Wireshark | bcc/BPF Tools |
|---------|---------|---------|-----------|---------------|
| Process Attribution | ✅ | ❌ | ❌ | ⚠️ (complex) |
| Community ID Flow Hashing | ✅ | ❌ | ✅ | ❌ |
| Binary Hash Tracking | ✅ | ❌ | ❌ | ❌ |
| Container Detection | ✅ | ❌ | ❌ | ⚠️ |
| Environment Capture | ✅ | ❌ | ❌ | ❌ |
| DNS Monitoring | ✅ | ⚠️ | ✅ | ⚠️ |
| TLS/SNI Visibility | ✅ | ❌ | ✅ | ❌ |
| JA4 Fingerprinting | ✅ | ❌ | ✅ | ❌ |
| Process Tree Tracking | ✅ | ❌ | ❌ | ❌ |
| Sigma Rule Detection | ✅ | ❌ | ❌ | ❌ |
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
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-generic gcc-multilib make golang-go
git clone https://github.com/jnesss/bpfview.git
cd bpfview
 (copy or create bpf/vmlinux.h)
go generate
go build
```

## License

This project uses a dual license approach:
- Go code and overall project: [Apache License 2.0](LICENSE)
- BPF programs (in `bpf/`): GPL v2 (required for kernel integration)

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md).
