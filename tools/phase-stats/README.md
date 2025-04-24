# Phase Stats

A utility tool for analyzing phase timings of BPFView handlers.

## Building

```bash
go build -o phase-stats main.go
```

## Usage

```bash
# List all available handlers
./phase-stats -list

# Show stats for a specific handler
./phase-stats -handler process_exec

# Show stats for all handlers
./phase-stats -all

# Specify a different metrics endpoint
./phase-stats -url http://hostname:2112/metrics -handler process_exec
```

## Example Output

```
Dns_event Handler Timing Breakdown
=====================================
dns_event: avg=1.346ms (count=4)
  ├─ console_logging: avg=0.313ms (23.3%)
  ├─ file_logging: avg=0.014ms (1.1%)
  ├─ generate_uids: avg=0.005ms (0.4%)
  ├─ sigma_detection: avg=0.002ms (0.2%)
  ├─ parse_dns_data: avg=0.001ms (0.1%)
  ├─ generate_correlation_ids: avg=0.001ms (0.1%)
  ├─ create_basic_info: avg=0.001ms (0.1%)
  ├─ process_lookup: avg=0.001ms (0.0%)
  ├─ network_conversion: avg=0.000ms (0.0%)
  └─ filtering: avg=0.000ms (0.0%)

Network_event Handler Timing Breakdown
=====================================
network_event: avg=0.072ms (count=1381)
  ├─ file_logging: avg=0.022ms (30.7%)
  ├─ console_logging: avg=0.017ms (22.5%)
  ├─ sigma_detection: avg=0.008ms (11.2%)
  ├─ prepare_message: avg=0.005ms (7.4%)
  ├─ process_lookup: avg=0.003ms (3.5%)
  ├─ filtering: avg=0.000ms (0.4%)
  └─ enrich_data: avg=0.000ms (0.1%)

Process_exec Handler Timing Breakdown
=====================================
process_exec: avg=1.982ms (count=553)
  ├─ exec_wait: avg=1.390ms (66.1%)
  ├─ proc_check1: avg=0.138ms (6.7%)
  ├─ process_enrichment: avg=0.138ms (4.1%)
  ├─ proc_check2: avg=0.089ms (3.4%)
  ├─ console_logging: avg=0.049ms (2.3%)
  ├─ file_logging: avg=0.041ms (1.9%)
  ├─ kernel_cmdline: avg=0.014ms (0.7%)
  ├─ cache_update: avg=0.012ms (0.6%)
  ├─ message_formatting: avg=0.005ms (0.3%)
  ├─ sigma_detection: avg=0.004ms (0.2%)
  ├─ init: avg=0.004ms (0.2%)
  ├─ parent_lookup: avg=0.003ms (0.1%)
  ├─ process_tree_update: avg=0.001ms (0.1%)
  ├─ event_counting: avg=0.001ms (0.0%)
  ├─ kernel_exepath: avg=0.001ms (0.0%)
  ├─ filtering: avg=0.000ms (0.0%)
  └─ username_lookup: avg=0.000ms (0.0%)

Process_exit Handler Timing Breakdown
=====================================
process_exit: avg=0.128ms (count=692)
  ├─ file_logging: avg=0.060ms (47.2%)
  ├─ console_logging: avg=0.037ms (28.5%)
  ├─ cache_update: avg=0.010ms (7.4%)
  ├─ message_formatting: avg=0.008ms (6.2%)
  ├─ debug_logging: avg=0.005ms (3.1%)
  ├─ cache_lookup: avg=0.003ms (2.0%)
  ├─ parent_lookup: avg=0.002ms (1.2%)
  ├─ init: avg=0.002ms (1.0%)
  ├─ info_update: avg=0.000ms (0.2%)
  └─ filtering: avg=0.000ms (0.2%)

Process_fork Handler Timing Breakdown
=====================================
process_fork: avg=0.141ms (count=801)
  ├─ file_logging: avg=0.048ms (35.7%)
  ├─ console_logging: avg=0.045ms (30.1%)
  ├─ cache_update: avg=0.013ms (7.7%)
  ├─ message_formatting: avg=0.006ms (4.5%)
  ├─ process_completion: avg=0.006ms (4.0%)
  ├─ init: avg=0.006ms (2.7%)
  ├─ parent_lookup: avg=0.006ms (2.2%)
  ├─ sigma_detection: avg=0.003ms (2.0%)
  ├─ process_tree_update: avg=0.003ms (1.6%)
  ├─ event_counting: avg=0.000ms (0.2%)
  ├─ filtering: avg=0.000ms (0.2%)
  └─ info_enrichment: avg=0.000ms (0.1%)

Tls_event Handler Timing Breakdown
=====================================
tls_event: avg=1.931ms (count=2)
  ├─ create_basic_info: avg=0.708ms (36.7%)
  ├─ console_logging: avg=0.156ms (6.6%)
  ├─ parse_tls_data: avg=0.060ms (4.1%)
  ├─ file_logging: avg=0.029ms (1.4%)
  ├─ process_lookup: avg=0.001ms (0.0%)
  └─ filtering: avg=0.000ms (0.0%)
```