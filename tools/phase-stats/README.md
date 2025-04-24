# Phase Stats

A utility tool for analyzing phase timings of BPFView event handlers and exclusion engine performance.

## Building

```bash
go build -o phase-stats main.go
```

## Usage

# List all available handlers
./phase-stats -list

# Show stats for a specific handler
./phase-stats -handler process_exec

# Show stats for all handlers
./phase-stats -all

# Show exclusion statistics
./phase-stats -exclusions

# Show all handlers and exclusion statistics
./phase-stats -all -exclusions

# Auto-refresh statistics every 5 seconds
./phase-stats -refresh 5

# Specify a different metrics endpoint
./phase-stats -url http://hostname:2112/metrics -handler process_exec
```

## Handler Timing Analysis

The tool breaks down each handler's processing phases to identify bottlenecks:

```
Process_exec Handler Timing Breakdown
=====================================
process_exec: avg=2.099ms (count=215)
  Phase                Avg Time  Percentage  Count  
  -----                --------  ----------  -----  
  exec_wait            1.461ms   66.6%       215    
  proc_check1          0.173ms   7.2%        215    
  proc_check2          0.101ms   3.6%        215    
  file_logging         0.067ms   2.5%        215    
  process_enrichment   0.101ms   2.5%        215    
  console_logging      0.055ms   2.5%        215    
  cache_update         0.021ms   0.8%        215
```

Each handler displays:

- Average total execution time
- Count of events processed
- Breakdown of each processing phase with:

-- Average time per phase
-- Percentage of total handler time
-- Number of times the phase was executed

## Exclusion Statistics

When run with the -exclusions flag, the tool provides detailed metrics about the exclusion engine:

```
Exclusion Statistics
===================
Total Exclusions: 77

Exclusions by Type:
  Rule Type  Pattern  Count  
  ---------  -------  -----  
  comm       bpfview  7      
  comm       chronyd  70     

Exclusion Latency Distribution (microseconds):
  Range            Count  Histogram                                 
  -----            -----  ---------                                 
  64.00 - 128.00   1405   ████████████████████████████████████████  

Latency Statistics:
  ├─ Average: 1.737 μs
  └─ Maximum: 512.000 μs

Excluded Events by Size:
  ├─ Average Size: 92 bytes
  └─ Total Events: 77
```

This provides insights into:

- Total number of excluded events
- Breakdown by exclusion rule type and pattern
- Latency distribution of exclusion checks
- Visual histogram of exclusion performance
- Size statistics of excluded events

## General Statistics

With the ```-all -exclusions``` flags, the tool also displays system-wide statistics:

```
General Statistics
===================
Total Events Processed:
  ├─ network: 568
  ├─ process: 1661
  ├─ tls: 2
  ├─ dns: 4
  └─ Total: 2235

Resource Usage:
  ├─ Goroutines: 15
  └─ Memory: 34.90 MB
```

## Use Cases

- **Performance Optimization**: Identify which processing phases consume the most time
- **Exclusion Tuning**: Validate that exclusion rules are working as expected
- **Resource Monitoring**: Track event processing volume and memory usage
- **Continuous Monitoring**: Use with -refresh for real-time performance visibility

This tool helps understand BPFView's internal performance characteristics and optimize its configuration for specific environments.