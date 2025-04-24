package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" netmon ./bpf/netmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" dnsmon ./bpf/dnsmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tlsmon ./bpf/tlsmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" execve ./bpf/execve.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" response ./bpf/response.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/jnesss/bpfview/outputformats"
	"github.com/jnesss/bpfview/types"
)

type bpfObjects struct {
	netmon   netmonObjects
	dnsmon   dnsmonObjects
	execve   execveObjects
	tlsmon   tlsmonObjects
	response responseObjects
}

type readerContext struct {
	reader     *ringbuf.Reader
	name       string
	bpfObjects interface{} // This will hold netmonObjects, dnsmonObjects, etc.
}

var (
	globalLogger        *Logger
	globalEngine        *FilterEngine
	globalExcludeEngine *ExclusionEngine
	globalSigmaEngine   *SigmaEngine
	globalSessionUid    string
	globalProcessLevel  types.ProcessInfoLevel
	responseManager     *ResponseManager
)

var BootTime time.Time

func main() {
	var config struct {
		logLevel         string
		showTimestamp    bool
		filterConfig     FilterConfig
		HashBinaries     bool
		format           string
		addHostname      bool
		addIP            bool
		sigmaRulesDir    string
		sigmaQueueSize   int
		dbPath           string
		processCacheSize int64
		processLevel     string
		cacheTimeout     time.Duration
	}

	rootCmd := &cobra.Command{
		Use:   "bpfview",
		Short: "Process and network monitoring tool",
		Long:  `BPFView provides process attribution for network connections, DNS queries, and TLS handshakes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Enable debug output from the verifier
			os.Setenv("LIBBPF_STRICT_MODE", "1")
			os.Setenv("LIBBPF_DEBUG", "1")

			// Set boot time
			BootTime = calculateBootTime()
			outputformats.SetBootTime(BootTime)

			// Convert string log level to enum
			consoleLevel := LogLevelInfo // default
			switch strings.ToLower(config.logLevel) {
			case "error":
				consoleLevel = LogLevelError
			case "warning":
				consoleLevel = LogLevelWarning
			case "info":
				consoleLevel = LogLevelInfo
			case "debug":
				consoleLevel = LogLevelDebug
			case "trace":
				consoleLevel = LogLevelTrace
			}

			// Get hostname/IP if enabled
			var hostname, hostIP string
			if config.addHostname || config.format == "gelf" { // GELF requires hostname
				hostname, _ = os.Hostname()
			}
			if config.addIP {
				hostIP = getDefaultIP()
			}

			// Create log directory if it doesn't exist
			logDir := "./logs"
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return fmt.Errorf("failed to create log directory: %v", err)
			}

			// Create formatter based on config
			var formatter outputformats.EventFormatter
			switch config.format {
			case "json", "json-ecs", "gelf":
				// Determine file name based on format
				fileName := "events.json"
				if config.format == "json-ecs" {
					fileName = "events.ecs.json"
				} else if config.format == "gelf" {
					fileName = "events.gelf.json"
				}

				// Rotate existing file if it exists
				jsonPath := filepath.Join(logDir, fileName)
				if _, err := os.Stat(jsonPath); err == nil {
					// File exists, get timestamp and session_uid from first event
					file, err := os.Open(jsonPath)
					if err == nil {
						defer file.Close()

						// Define struct based on format
						var timestamp time.Time
						var sessionUID string

						switch config.format {
						case "gelf":
							var gelfEvent struct {
								Timestamp  float64 `json:"timestamp"`
								SessionUID string  `json:"_session_uid"`
							}
							if err := json.NewDecoder(file).Decode(&gelfEvent); err == nil {
								// Convert GELF timestamp (Unix epoch with fractional seconds)
								sec := int64(gelfEvent.Timestamp)
								nsec := int64((gelfEvent.Timestamp - float64(sec)) * 1e9)
								timestamp = time.Unix(sec, nsec)
								sessionUID = gelfEvent.SessionUID
							}

						case "json-ecs":
							var ecsEvent struct {
								Timestamp  string `json:"@timestamp"`
								SessionUID string `json:"event.sequence"`
							}
							if err := json.NewDecoder(file).Decode(&ecsEvent); err == nil {
								timestamp, _ = time.Parse(time.RFC3339Nano, ecsEvent.Timestamp)
								sessionUID = ecsEvent.SessionUID
							}

						default: // regular JSON
							var jsonEvent struct {
								Timestamp  string `json:"timestamp"`
								SessionUID string `json:"session_uid"`
							}
							if err := json.NewDecoder(file).Decode(&jsonEvent); err == nil {
								timestamp, _ = time.Parse(time.RFC3339Nano, jsonEvent.Timestamp)
								sessionUID = jsonEvent.SessionUID
							}
						}

						// Only rotate if we got a valid timestamp
						if !timestamp.IsZero() {
							if sessionUID == "" {
								sessionUID = "unknown"
							}
							// Create archived name including session_uid
							archivedPath := filepath.Join(logDir,
								fmt.Sprintf("%s.%s.%s.json", fileName[:len(fileName)-5],
									timestamp.Format("2006-01-02-15-04-05"),
									sessionUID))

							// Close file before rename
							file.Close()

							if err := os.Rename(jsonPath, archivedPath); err != nil {
								return fmt.Errorf("failed to rotate %s: %v", fileName, err)
							}
						}
					}
				}

				// Now open the new file
				outputFile, err := os.OpenFile(filepath.Join(logDir, fileName),
					os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					return fmt.Errorf("failed to open output file: %v", err)
				}

				// Create appropriate formatter
				switch config.format {
				case "json":
					formatter = outputformats.NewJSONFormatter(outputFile, hostname, hostIP, globalSessionUid, config.sigmaRulesDir != "")
				case "json-ecs":
					formatter = outputformats.NewECSFormatter(outputFile, hostname, hostIP, globalSessionUid, config.sigmaRulesDir != "")
				case "gelf":
					formatter = outputformats.NewGELFFormatter(outputFile, hostname, hostIP, globalSessionUid, config.sigmaRulesDir != "")
				}

			case "sqlite":
				sqliteFormatter, err := outputformats.NewSQLiteFormatter(config.dbPath, hostname, hostIP, globalSessionUid, config.sigmaRulesDir != "")
				if err != nil {
					return fmt.Errorf("failed to create sqlite formatter: %v", err)
				}
				formatter = sqliteFormatter

			case "text", "":
				textFormatter, err := outputformats.NewTextFormatter(logDir, hostname, hostIP, globalSessionUid, config.sigmaRulesDir != "")
				if err != nil {
					return fmt.Errorf("failed to create text formatter: %v", err)
				}
				formatter = textFormatter

			default:
				return fmt.Errorf("unknown format: %s (supported formats: text, json, json-ecs, gelf, sqlite)", config.format)

			}

			// Initialize formatter
			if err := formatter.Initialize(); err != nil {
				return fmt.Errorf("failed to initialize formatter: %v", err)
			}
			defer formatter.Close()

			// Initialize logger with formatter
			logger, err := NewLogger(formatter, consoleLevel, config.showTimestamp)
			if err != nil {
				return fmt.Errorf("failed to initialize logger: %v", err)
			}
			globalLogger = logger
			defer logger.Close()

			// copy HashBinaries setting from local var
			config.filterConfig.HashBinaries = config.HashBinaries

			// Create filter engine
			engine := NewFilterEngine(config.filterConfig)
			globalEngine = engine

			// Initialize process cache
			log.Printf("Initializing process cache with size %d and TTL %v...",
				config.processCacheSize, config.cacheTimeout)
			processCache, err = NewProcessCache(config.processCacheSize, config.cacheTimeout)
			if err != nil {
				log.Fatalf("Failed to initialize process cache: %v", err)
			}

			// Initialize process cache with existing processes
			initializeProcessCache()

			// Initialize and start metrics collection
			metricsCollector := NewMetricsCollector(processCache)
			metricsCollector.Start()
			defer metricsCollector.Stop()

			if config.sigmaRulesDir != "" {
				var err error
				globalSigmaEngine, err = NewSigmaEngine(config.sigmaRulesDir, config.sigmaQueueSize)
				if err != nil {
					return fmt.Errorf("failed to initialize sigma detection: %v", err)
				}
				defer globalSigmaEngine.Close()

				// Log initial state
				log.Printf("Sigma detection enabled:")
				log.Printf("  - Rules directory: %s", config.sigmaRulesDir)
				log.Printf("  - Event queue size: %d", config.sigmaQueueSize)
			}

			// Initialize exclusion engine
			exclusionConfig := ExclusionConfig{
				CommNames:    config.filterConfig.ExcludeComm,
				ExePaths:     config.filterConfig.ExcludeExePath,
				UserNames:    config.filterConfig.ExcludeUser,
				ContainerIDs: config.filterConfig.ExcludeContainer,
				ExcludePorts: config.filterConfig.ExcludePorts,
			}
			globalExcludeEngine = NewExclusionEngine(exclusionConfig, config.filterConfig.TrackTree)

			globalProcessLevel = getProcessInfoLevel(config.processLevel)
			processLevelInfo.WithLabelValues(config.processLevel).Set(1)
			log.Printf("Using process information level: %s", config.processLevel)

			log.Println("Initializing BPF programs...")
			objs, err := setupBPF()
			if err != nil {
				return fmt.Errorf("failed to setup BPF: %v", err)
			}

			responseManager = NewResponseManager(&objs.response)

			// Ensure programs are closed on exit
			defer objs.netmon.Close()
			defer objs.dnsmon.Close()
			defer objs.execve.Close()
			defer objs.tlsmon.Close()
			defer objs.response.Close()

			// Attach all programs
			log.Println("Attaching BPF programs...")
			links := attachPrograms(objs.netmon, objs.dnsmon, objs.execve, objs.tlsmon, objs.response)
			defer closeLinks(links)

			// Create readers for all ringbuffers
			log.Println("Setting up ringbuffer readers...")
			readers := setupRingbufReaders(objs.netmon, objs.dnsmon, objs.execve, objs.tlsmon, objs.response)
			defer closeReaders(readers)

			// Set up signal handling
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			log.Println("Starting event monitoring...")
			fmt.Println("Press Ctrl+C to stop")

			// Create error channel for goroutine errors
			errChan := make(chan error, len(readers))

			// Start a goroutine for each reader
			var wg sync.WaitGroup
			for i, rd := range readers {
				wg.Add(1)
				go func(rc readerContext, idx int) {
					defer wg.Done()
					if err := processEvents(ctx, rc); err != nil {
						errChan <- fmt.Errorf("reader %d error: %v", idx, err)
					}
				}(rd, i)
			}

			// Wait for either context cancellation or an error
			select {
			case <-ctx.Done():
				log.Println("Received shutdown signal")
			case err := <-errChan:
				log.Printf("Error from reader: %v", err)
			}

			log.Println("Shutting down...")

			// Close all readers
			log.Println("Closing ringbuffer readers...")
			closeReaders(readers)

			// Wait with timeout for goroutines to finish
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				log.Println("All readers cleaned up successfully")
			case <-time.After(5 * time.Second):
				log.Println("Timed out waiting for readers to clean up")
			}

			log.Println("Cleanup complete")
			return nil
		},
	}

	// Just use your existing flag definitions, but organize them with comments
	// Process filters
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.CommandNames, "comm", nil, "Filter by command names")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.PIDs, "pid", nil, "Filter by process IDs")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.PPIDs, "ppid", nil, "Filter by parent process IDs")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.BinaryHashes, "binary-hash", nil, "Filter by MD5 hash of the executable")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.UserNames, "user", nil, "Filter by username")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.ExePaths, "exe", nil, "Filter by executable path (exact or prefix)")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.ContainerIDs, "container-id", nil, "Filter by container ID (use '*' to match any container)")
	rootCmd.PersistentFlags().BoolVar(&config.filterConfig.TrackTree, "tree", false, "Track process tree")

	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.ExcludeComm, "exclude-comm", nil, "Exclude processes by command name")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.ExcludeExePath, "exclude-exe-path", nil, "Exclude processes by executable path")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.ExcludeUser, "exclude-user", nil, "Exclude processes by username")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.ExcludeContainer, "exclude-container", nil, "Exclude processes by container ID")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.ExcludePorts, "exclude-port", nil, "Exclude specific ports from monitoring")

	// Optional features
	rootCmd.PersistentFlags().BoolVar(&config.HashBinaries, "hash-binaries", false, "Calculate MD5 hash of process executables")
	rootCmd.Flags().StringVar(&config.sigmaRulesDir, "sigma", "",
		"Directory containing Sigma rules for process and network detection (if not specified, Sigma detection is disabled)")
	rootCmd.Flags().IntVar(&config.sigmaQueueSize, "sigma-queue-size", 10000,
		"Maximum number of events to queue for Sigma detection")

	// Network filters
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.Protocols, "protocol", nil, "Filter by protocol (TCP, UDP, ICMP)")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.SrcIPs, "src-ip", nil, "Filter by source IP address")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.DstIPs, "dst-ip", nil, "Filter by destination IP address")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.SrcPorts, "sport", nil, "Filter by source port")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.DstPorts, "dport", nil, "Filter by destination port")

	// DNS filtering options
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.Domains, "domain", nil, "Filter by domain name (supports wildcards like '*.example.com')")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.DNSTypes, "dns-type", nil, "Filter by DNS record type (A, AAAA, CNAME, etc.)")

	// TLS filtering options
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.TLSVersions, "tls-version", nil, "Filter by TLS version (1.0, 1.1, 1.2, 1.3)")
	rootCmd.PersistentFlags().StringSliceVar(&config.filterConfig.SNIHosts, "sni", nil, "Filter by SNI host (supports wildcards)")

	// Output options
	rootCmd.PersistentFlags().StringVar(&config.processLevel, "process-level", "full", "Process information collection level (minimal, basic, full)")
	rootCmd.PersistentFlags().StringVar(&config.logLevel, "log-level", "info", "Log level (error, warning, info, debug, trace)")
	rootCmd.PersistentFlags().BoolVar(&config.showTimestamp, "log-timestamp", false, "Show timestamps in console logs")
	rootCmd.PersistentFlags().StringVar(&config.format, "format", "text", "Output log format: text, json, json-ecs, gelf, sqlite")
	rootCmd.PersistentFlags().BoolVar(&config.addHostname, "add-hostname", false, "Include hostname with every log entry")
	rootCmd.PersistentFlags().BoolVar(&config.addIP, "add-ip", false, "Include host IP address with every log entry")
	rootCmd.PersistentFlags().StringVar(&config.dbPath, "dbfile", "./logs/bpfview.db", "SQLite database path (when using sqlite format)")

	// Performance optimization options
	rootCmd.Flags().Int64Var(&config.processCacheSize, "process-cache-size",
		10000, "Maximum number of processes to cache")
	rootCmd.Flags().DurationVar(&config.cacheTimeout, "cache-timeout",
		24*time.Hour, "Time after which cache entries expire (e.g., 1h, 30m)")

	rootCmd.SetUsageTemplate(`Usage:
  {{.CommandPath}} [flags]

Process Filters:
  --comm strings           Filter by command names (e.g., "nginx,php-fpm")
  --pid strings            Filter by process IDs (can specify multiple)
  --ppid strings          Filter by parent process IDs
  --binary-hash strings   Filter by MD5 hash of the executable (only if --hash-binaries enabled)
  --user strings          Filter by username (e.g., "www-data,nginx")
  --exe strings           Filter by executable path (exact match or prefix)
  --container-id strings  Filter by container ID (use '*' to match any container)
  --tree                  Track entire process tree when a match is found

Process Exclusions:
  --exclude-comm strings       Exclude processes by command name
  --exclude-exe-path strings   Exclude processes by executable path
  --exclude-user strings       Exclude processes by username
  --exclude-container strings  Exclude processes by container ID

Network Filters:
  --protocol strings      Filter by protocol (TCP, UDP, ICMP)
  --src-ip strings       Filter by source IP address 
  --dst-ip strings       Filter by destination IP address
  --sport strings        Filter by source port (e.g., "80,443")
  --dport strings        Filter by destination port (e.g., "80,443")

DNS Filters:
  --domain strings       Filter by domain name (supports wildcards like '*.example.com')
  --dns-type strings    Filter by DNS record type (A, AAAA, CNAME, MX, TXT, etc.)

TLS Filters:
  --tls-version strings Filter by TLS version (1.0, 1.1, 1.2, 1.3)
  --sni strings         Filter by SNI hostname (supports wildcards)
  
Optional Features:
  --hash-binaries      Calculate and log MD5 hashes of executables
                       Useful for threat hunting and malware detection
  --sigma <dir>        Directory containing Sigma rules for process and network detection
                       If not specified, Sigma detection is disabled
  --sigma-queue-size   Maximum number of events to queue for Sigma detection

Output Options:
  --format string       Select output format (default "text"):
                         text      - Separate log files in pipe-delimited format in logs:
                                   process.log, network.log, dns.log, tls.log
                         json      - Single JSON events file (logs/events.json)
                         json-ecs  - Elastic Common Schema format (logs/events.ecs.json)
                         gelf      - Graylog Extended Log Format (logs/events.gelf.json)
                         sqlite    - Structured database file (logs/bpfview.db)
  
  --log-level string   Control console output verbosity (default "info"):
                         error   - Only errors
                         warning - Warnings and errors
                         info    - Normal informational output
                         debug   - Detailed debugging info
                         trace   - Very verbose debugging
  
  --log-timestamp      Add timestamps to console messages
    
  --add-hostname       Add system hostname to all log entries
                       Recommended when collecting from multiple hosts
  
  --add-ip            Add host IP address to all log entries
                       Recommended when collecting from multiple hosts
  
  --dbfile string.    Name of database file to use when using sqlite format       
  
Performance Optimization Options:
  --process-cache-size int  Maximum number of processes to cache (default 10000)
  --cache-timeout string    Time after which cache entries expire (e.g., 1h, 30m)
  --process-level string    Process information collection level (default "full"):
                              minimal - Only BPF-provided data, minimal /proc reads
                              basic   - Core process attributes (exe, cmdline) 
                              full    - Complete information including env vars and container ID
                              
Examples:
  # Monitor all container activity
  bpfview --container-id "*"

  # Track DNS queries for specific domains
  bpfview --domain "*.example.com,*.google.com" --dns-type A,AAAA

  # Monitor specific processes and their children
  bpfview --comm nginx,php-fpm --tree
  
  # Monitor all except specific processes
  bpfview --exclude-comm "nginx,sshd" --exclude-user www-data

  # Full security monitoring with ECS output
  bpfview --format json-ecs --hash-binaries --add-hostname --add-ip
  
  # High-volume server optimization
  bpfview --exclude-comm "nginx,postgres" --exclude-port "80,443,5432" --tree

Global Flags:
  -h, --help           Show this help message

For more details and examples, visit: https://github.com/jnesss/bpfview`)

	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s-%d", time.Now().Format(time.RFC3339Nano), os.Getpid())))
	globalSessionUid = fmt.Sprintf("%x", h.Sum32())

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":2112", nil)
	}()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func setupBPF() (*bpfObjects, error) {
	// Remove memory lock for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memory lock: %w", err)
	}

	objs := &bpfObjects{}

	// Load all BPF programs
	objs.netmon = loadNetmonProgram()
	objs.dnsmon = loadDnsmonProgram()
	objs.execve = loadExecveProgram()
	objs.tlsmon = loadTlsmonProgram()
	objs.response = loadResponseProgram()

	return objs, nil
}

// Create readers for all ringbuffers
func setupRingbufReaders(netmonObjs netmonObjects, dnsmonObjs dnsmonObjects,
	execveObjs execveObjects, tlsmonObjs tlsmonObjects, responseObjs responseObjects,
) []readerContext {
	var readers []readerContext

	// Network events reader
	netReader, err := ringbuf.NewReader(netmonObjs.Events)
	if err != nil {
		log.Fatal(err)
	}
	readers = append(readers, readerContext{
		reader:     netReader,
		name:       "network",
		bpfObjects: netmonObjs,
	})

	// DNS events reader
	dnsReader, err := ringbuf.NewReader(dnsmonObjs.Events)
	if err != nil {
		log.Fatal(err)
	}
	readers = append(readers, readerContext{
		reader:     dnsReader,
		name:       "dns",
		bpfObjects: dnsmonObjs,
	})

	// Process events reader
	execReader, err := ringbuf.NewReader(execveObjs.Events)
	if err != nil {
		log.Fatal(err)
	}
	readers = append(readers, readerContext{
		reader:     execReader,
		name:       "process",
		bpfObjects: execveObjs,
	})

	// TLS/SNI events reader
	tlsReader, err := ringbuf.NewReader(tlsmonObjs.Events)
	if err != nil {
		log.Fatal(err)
	}
	readers = append(readers, readerContext{
		reader:     tlsReader,
		name:       "tls",
		bpfObjects: tlsmonObjs,
	})

	responseReader, err := ringbuf.NewReader(responseObjs.Events)
	if err != nil {
		log.Fatal(err)
	}
	readers = append(readers, readerContext{
		reader:     responseReader,
		name:       "response",
		bpfObjects: responseObjs,
	})

	return readers
}

func closeReaders(readers []readerContext) { // Changed parameter type
	for _, rd := range readers {
		rd.reader.Close()
	}
}

func processEvents(ctx context.Context, rc readerContext) error {
	log.Printf("Starting %s event reader...", rc.name)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			record, err := rc.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return nil
				}
				// Only return fatal errors
				if errors.Is(err, io.EOF) || errors.Is(err, syscall.EINTR) {
					continue
				}
				return fmt.Errorf("error reading from ringbuf: %v", err)
			}

			// Process the event
			if len(record.RawSample) > 0 {
				if err := handleEvent(record.RawSample, rc); err != nil {
					log.Printf("[%s] Error handling event: %v", rc.name, err)
				}
			}
		}
	}
}

func handleEvent(data []byte, rc readerContext) error {
	eventCounter.With(prometheus.Labels{
		"event_type": rc.name,
	}).Inc()

	// Read event type
	var header types.EventHeader
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("error reading event header: %w", err)
	}

	// Process based on event type
	switch header.EventType {
	case types.EVENT_PROCESS_EXEC, types.EVENT_PROCESS_EXIT, types.EVENT_PROCESS_FORK:
		var event types.ProcessEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			eventProcessingErrors.With(prometheus.Labels{
				"event_type": "process",
			}).Inc()
			return fmt.Errorf("error parsing process event: %w", err)
		}
		// Pass the execve objects to handleProcessEvent
		if execObjs, ok := rc.bpfObjects.(execveObjects); ok {
			// one goroutine per event since process create does /proc lookups and other long stuff
			go func(event types.ProcessEvent, execObjs execveObjects) {
				handleProcessEvent(&event, &execObjs)
			}(event, execObjs)
		}

	case types.EVENT_NET_CONNECT, types.EVENT_NET_ACCEPT, types.EVENT_NET_BIND:
		var event types.NetworkEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			eventProcessingErrors.With(prometheus.Labels{
				"event_type": "network",
			}).Inc()
			return fmt.Errorf("error parsing network event: %w", err)
		}
		go func(event types.NetworkEvent) {
			handleNetworkEvent(&event)
		}(event)

	case types.EVENT_DNS:
		var event types.BPFDNSRawEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			eventProcessingErrors.With(prometheus.Labels{
				"event_type": "dns",
			}).Inc()
			return fmt.Errorf("error parsing DNS event: %w", err)
		}
		go func(event types.BPFDNSRawEvent) {
			handleDNSEvent(&event)
		}(event)

	case types.EVENT_TLS:
		var event types.BPFTLSEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			eventProcessingErrors.With(prometheus.Labels{
				"event_type": "tls",
			}).Inc()
			return fmt.Errorf("error parsing TLS event: %w", err)
		}
		go func(event types.BPFTLSEvent) {
			handleTLSEvent(&event)
		}(event)

	case types.EVENT_RESPONSE:
		var event struct {
			EventType        uint32
			Pid              uint32
			Ppid             uint32
			Comm             [16]byte
			ActionTaken      uint32
			BlockedSyscall   uint32
			RestrictionFlags uint32
		}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			eventProcessingErrors.With(prometheus.Labels{
				"event_type": "response",
			}).Inc()
			return fmt.Errorf("error parsing response event: %w", err)
		}

		// Log the action taken
		action := "unknown"
		switch event.ActionTaken {
		case types.RESPONSE_ACTION_EXEC_BLOCKED:
			action = "blocked process execution"
		case types.RESPONSE_ACTION_NETWORK_BLOCKED:
			action = "blocked network access"
		case types.RESPONSE_ACTION_TASK_BLOCKED:
			action = "blocked task creation"

		}

		globalLogger.Info("response", "Action %s for PID %d (flags: 0x%x)",
			action, event.Pid, event.RestrictionFlags)

	default:
		eventProcessingErrors.With(prometheus.Labels{
			"event_type": "unknown",
		}).Inc()
		return fmt.Errorf("unknown event type: %d", header.EventType)
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findCgroupPath() string {
	paths := []string{
		"/sys/fs/cgroup",
		"/sys/fs/cgroup/unified",
		"/sys/fs/cgroup/system.slice",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	log.Fatal("Could not find cgroup path")
	return ""
}

func attachPrograms(netmonObjs netmonObjects, dnsmonObjs dnsmonObjects,
	execveObjs execveObjects, tlsmonObjs tlsmonObjects, responseObjs responseObjects,
) []link.Link {
	var links []link.Link

	// Find cgroup path for network attachments
	cgroupPath := findCgroupPath()

	// Attach network monitoring programs
	netLink1, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: netmonObjs.CgroupSockCreate,
	})
	if err != nil {
		log.Fatalf("attaching sock_create: %v", err)
	}
	links = append(links, netLink1)

	netLink2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: netmonObjs.CgroupSkbIngress,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching skb_ingress: %v", err)
	}
	links = append(links, netLink2)

	netLink3, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: netmonObjs.CgroupSkbEgress,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching skb_egress: %v", err)
	}
	links = append(links, netLink3)

	// Attach DNS monitoring programs
	dnsLink1, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: dnsmonObjs.CgroupSockCreate,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching dns sock_create: %v", err)
	}
	links = append(links, dnsLink1)

	dnsLink2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: dnsmonObjs.CgroupSkbIngress,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching dns ingress: %v", err)
	}
	links = append(links, dnsLink2)

	dnsLink3, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: dnsmonObjs.CgroupSkbEgress,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching dns egress: %v", err)
	}
	links = append(links, dnsLink3)

	// Attach TLS monitoring programs
	tlsLink1, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: tlsmonObjs.CgroupSockCreate,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching tls sock_create: %v", err)
	}
	links = append(links, tlsLink1)

	tlsLink2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: tlsmonObjs.CgroupSkbIngress,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching tls ingress: %v", err)
	}
	links = append(links, tlsLink2)

	tlsLink3, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: tlsmonObjs.CgroupSkbEgress,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching tls egress: %v", err)
	}
	links = append(links, tlsLink3)

	// Attach execve tracepoint programs
	execLink1, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.TraceEnterExecve, nil)
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching execve enter: %v", err)
	}
	links = append(links, execLink1)

	execLink2, err := link.Tracepoint("sched", "sched_process_exit", execveObjs.TraceSchedProcessExit, nil)
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching process exit: %v", err)
	}
	links = append(links, execLink2)

	forkLink, err := link.Tracepoint("sched", "sched_process_fork", execveObjs.TraceSchedProcessFork, nil)
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching process fork: %v", err)
	}
	links = append(links, forkLink)

	execLink, err := link.AttachLSM(link.LSMOptions{
		Program: responseObjs.CheckExec,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching exec LSM: %v", err)
	}
	links = append(links, execLink)

	taskAllocLink, err := link.AttachLSM(link.LSMOptions{
		Program: responseObjs.CheckTaskAlloc,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching task_alloc LSM: %v", err)
	}
	links = append(links, taskAllocLink)

	connectLink, err := link.AttachLSM(link.LSMOptions{
		Program: responseObjs.CheckConnect,
	})
	if err != nil {
		closeLinks(links)
		log.Fatalf("attaching connect LSM: %v", err)
	}
	links = append(links, connectLink)

	return links
}

func closeLinks(links []link.Link) {
	for _, link := range links {
		if link != nil {
			link.Close()
		}
	}
}

func calculateBootTime() time.Time {
	// For Linux systems, we can read /proc/uptime
	if runtime.GOOS == "linux" {
		content, err := ioutil.ReadFile("/proc/uptime")
		if err == nil {
			parts := strings.Split(string(content), " ")
			if len(parts) > 0 {
				uptime, err := strconv.ParseFloat(parts[0], 64)
				if err == nil {
					bootTime := time.Now().Add(-time.Duration(uptime * float64(time.Second)))
					fmt.Printf("System boot time: %s\n", bootTime.Format(time.RFC3339))
					return bootTime
				}
			}
		}
	}

	// Fallback: use start of BPF monitoring as reference point
	fmt.Printf("WARNING: Could not get boot time, using current time\n")
	return time.Now()
}

func BpfTimestampToTime(bpfTimestamp uint64) time.Time {
	return BootTime.Add(time.Duration(bpfTimestamp))
}

func getDefaultIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return ""
}

func loadResponseProgram() responseObjects {
	objs := responseObjects{}
	if err := loadResponseObjects(&objs, nil); err != nil {
		log.Fatalf("loading response objects: %v", err)
	}
	return objs
}

func getProcessInfoLevel(levelStr string) types.ProcessInfoLevel {
	switch strings.ToLower(levelStr) {
	case "minimal":
		return types.ProcessLevelMinimal
	case "basic":
		return types.ProcessLevelBasic
	default:
		return types.ProcessLevelFull
	}
}
