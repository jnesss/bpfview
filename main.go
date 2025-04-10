package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" netmon ./bpf/netmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" dnsmon ./bpf/dnsmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tlsmon ./bpf/tlsmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" execve ./bpf/execve.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
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
	"github.com/spf13/cobra"
)

type bpfObjects struct {
	netmon netmonObjects
	dnsmon dnsmonObjects
	execve execveObjects
	tlsmon tlsmonObjects
}

type readerContext struct {
	reader     *ringbuf.Reader
	name       string
	bpfObjects interface{} // This will hold netmonObjects, dnsmonObjects, etc.
}

var (
	globalLogger     *Logger
	globalEngine     *FilterEngine
	globalSessionUid string
)

var BootTime time.Time

func main() {
	var config struct {
		logLevel      string
		showTimestamp bool
		filterConfig  FilterConfig
		HashBinaries  bool
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

			// Initialize logger
			logger, err := NewLogger("./logs", consoleLevel, LogLevelInfo, config.showTimestamp)
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

			// Initialize process cache with existing processes
			log.Println("Initializing process cache...")
			initializeProcessCache()
			log.Println("Process cache initialized")

			log.Println("Initializing BPF programs...")
			objs, err := setupBPF()
			if err != nil {
				return fmt.Errorf("failed to setup BPF: %v", err)
			}

			// Ensure programs are closed on exit
			defer objs.netmon.Close()
			defer objs.dnsmon.Close()
			defer objs.execve.Close()
			defer objs.tlsmon.Close()

			// Attach all programs
			log.Println("Attaching BPF programs...")
			links := attachPrograms(objs.netmon, objs.dnsmon, objs.execve, objs.tlsmon)
			defer closeLinks(links)

			// Create readers for all ringbuffers
			log.Println("Setting up ringbuffer readers...")
			readers := setupRingbufReaders(objs.netmon, objs.dnsmon, objs.execve, objs.tlsmon)
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
	rootCmd.PersistentFlags().BoolVar(&config.HashBinaries, "hash-binaries", false, "Calculate MD5 hash of process executables")

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
	rootCmd.PersistentFlags().StringVar(&config.logLevel, "log-level", "info", "Log level (error, warning, info, debug, trace)")
	rootCmd.PersistentFlags().BoolVar(&config.showTimestamp, "log-timestamp", false, "Show timestamps in console logs")

	rootCmd.SetUsageTemplate(`Usage:
  {{.CommandPath}} [flags]

Process Filters:
  --comm strings           Filter by command names
  --pid strings            Filter by process IDs
  --ppid strings           Filter by parent process IDs
  --binary-hash strings    Filter by MD5 hash of the executable
  --user strings           Filter by username
  --exe strings            Filter by executable path (exact or prefix)
  --container-id strings   Filter by container ID (use '*' to match any container)
  --tree                   Track process tree

Network Filters:
  --protocol strings       Filter by protocol (TCP, UDP, ICMP)
  --src-ip strings         Filter by source IP address
  --dst-ip strings         Filter by destination IP address
  --sport strings          Filter by source port
  --dport strings          Filter by destination port

DNS Filters:
  --domain strings         Filter by domain name (supports wildcards like '*.example.com')
  --dns-type strings       Filter by DNS record type (A, AAAA, CNAME, etc.)

TLS Filters:
  --tls-version strings    Filter by TLS version (1.0, 1.1, 1.2, 1.3)
  --sni strings            Filter by SNI host (supports wildcards)

Output Options:
  --log-level string       Log level (error, warning, info, debug, trace) (default "info")
  --log-timestamp          Show timestamps in console logs
  --hash-binaries          Include MD5 hash of process executables in logs

Global Flags:
  -h, --help               Help for {{.CommandPath}}
`)

	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s-%d", time.Now().Format(time.RFC3339Nano), os.Getpid())))
	globalSessionUid = fmt.Sprintf("%x", h.Sum32())

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

	return objs, nil
}

// Create readers for all ringbuffers
func setupRingbufReaders(netmonObjs netmonObjects, dnsmonObjs dnsmonObjects,
	execveObjs execveObjects, tlsmonObjs tlsmonObjects,
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
	// Print raw data for debugging
	// fmt.Printf("\nRaw event data from %s (%d bytes): ", rc.name, len(data))
	//for i := 0; i < min(len(data), 32); i++ {
	//	fmt.Printf("%02x ", data[i])
	//}
	//fmt.Printf("\n")

	// Read event type
	var header EventHeader
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("error reading event header: %w", err)
	}

	// Process based on event type
	switch header.EventType {
	case EVENT_PROCESS_EXEC, EVENT_PROCESS_EXIT:
		var event ProcessEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("error parsing process event: %w", err)
		}
		// Pass the execve objects to handleProcessEvent
		if execObjs, ok := rc.bpfObjects.(execveObjects); ok {
			// one goroutine per event since process create does /proc lookups and other long stuff
			go func(event ProcessEvent, execObjs execveObjects) {
				handleProcessEvent(&event, &execObjs)
			}(event, execObjs)
		}

	case EVENT_NET_CONNECT, EVENT_NET_ACCEPT, EVENT_NET_BIND:
		var event NetworkEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("error parsing network event: %w", err)
		}
		handleNetworkEvent(&event)

	case EVENT_DNS:
		var event BPFDNSRawEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("error parsing DNS event: %w", err)
		}
		handleDNSEvent(&event)

	case EVENT_TLS:
		var event BPFTLSEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("error parsing TLS event: %w", err)
		}
		handleTLSEvent(&event)

	default:
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
	execveObjs execveObjects, tlsmonObjs tlsmonObjects,
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

	log.Printf("Successfully attached %d BPF programs", len(links))
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
