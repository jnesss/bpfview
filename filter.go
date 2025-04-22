package main

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"github.com/jnesss/bpfview/types"

	"github.com/prometheus/client_golang/prometheus"
)

type FilterConfig struct {
	// Process filters
	PIDs            []string
	PPIDs           []string
	CommandNames    []string
	CmdlineContains []string
	ExePaths        []string
	UserNames       []string
	ContainerIDs    []string
	BinaryHashes    []string
	TrackTree       bool
	HashBinaries    bool

	// Network filters
	SrcIPs    []string
	DstIPs    []string
	SrcPorts  []string
	DstPorts  []string
	Protocols []string

	// DNS filters
	Domains  []string
	DNSTypes []string

	// TLS filters
	TLSVersions []string
	SNIHosts    []string

	// Output config
	OutputFormat string
	OutputFile   string
}

type FilterEngine struct {
	config      FilterConfig
	processTree *ProcessTree

	// Filter flags
	hasProcessFilters bool
	hasNetworkFilters bool
	hasDNSFilters     bool
	hasTLSFilters     bool

	// Parse and store pids as ints so we dont have to convert them in the hot path
	pids  []uint32
	ppids []uint32

	// Parse and store network filter elements to do less work in hot path
	srcPorts  []uint16
	dstPorts  []uint16
	srcIPs    []net.IP
	dstIPs    []net.IP
	protocols []uint8

	// Pre-parsed DNS filters
	dnsTypes []uint16 // Store actual DNS type numbers
	domains  []string // Keep domains as strings but normalize them at init

	// Pre-parsed TLS filters
	tlsVersions []uint16 // Store version numbers
	sniHosts    []string // Normalized SNI patterns
}

func NewFilterEngine(config FilterConfig) *FilterEngine {
	e := &FilterEngine{
		config:      config,
		processTree: NewProcessTree(),
	}

	// Check process filters
	e.hasProcessFilters = len(config.PIDs) > 0 ||
		len(config.PPIDs) > 0 ||
		len(config.CommandNames) > 0 ||
		len(config.CmdlineContains) > 0 ||
		len(config.ExePaths) > 0 ||
		len(config.BinaryHashes) > 0 ||
		config.TrackTree

	// Check network-specific filters
	e.hasNetworkFilters = len(config.SrcPorts) > 0 ||
		len(config.DstPorts) > 0 ||
		len(config.SrcIPs) > 0 ||
		len(config.DstIPs) > 0 ||
		len(config.Protocols) > 0

	// Check DNS-specific filters
	e.hasDNSFilters = len(config.Domains) > 0 ||
		len(config.DNSTypes) > 0

	// Check TLS-specific filters
	e.hasTLSFilters = len(config.TLSVersions) > 0 ||
		len(config.SNIHosts) > 0

	// Convert pids to ints once at startup not in hot path
	if len(config.PIDs) > 0 {
		if pids, err := parseUint32Slice(config.PIDs); err == nil {
			e.pids = pids
		}
	}
	if len(config.PPIDs) > 0 {
		if ppids, err := parseUint32Slice(config.PPIDs); err == nil {
			e.ppids = ppids
		}
	}

	// Parse ports once
	if len(config.SrcPorts) > 0 {
		if ports, err := parseUint16Slice(config.SrcPorts); err == nil {
			e.srcPorts = ports
		}
	}
	if len(config.DstPorts) > 0 {
		if ports, err := parseUint16Slice(config.DstPorts); err == nil {
			e.dstPorts = ports
		}
	}

	// Parse IPs once
	for _, ipStr := range config.SrcIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			e.srcIPs = append(e.srcIPs, ip)
		}
	}
	for _, ipStr := range config.DstIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			e.dstIPs = append(e.dstIPs, ip)
		}
	}

	// Parse protocols once
	for _, proto := range config.Protocols {
		switch strings.ToUpper(proto) {
		case "TCP":
			e.protocols = append(e.protocols, 6)
		case "UDP":
			e.protocols = append(e.protocols, 17)
		case "ICMP":
			e.protocols = append(e.protocols, 1)
		case "ICMPV6":
			e.protocols = append(e.protocols, 58)
		}
	}

	// Parse DNS types once
	for _, typeStr := range config.DNSTypes {
		switch strings.ToUpper(typeStr) {
		case "A":
			e.dnsTypes = append(e.dnsTypes, 1)
		case "NS":
			e.dnsTypes = append(e.dnsTypes, 2)
		case "CNAME":
			e.dnsTypes = append(e.dnsTypes, 5)
		case "SOA":
			e.dnsTypes = append(e.dnsTypes, 6)
		case "PTR":
			e.dnsTypes = append(e.dnsTypes, 12)
		case "MX":
			e.dnsTypes = append(e.dnsTypes, 15)
		case "TXT":
			e.dnsTypes = append(e.dnsTypes, 16)
		case "AAAA":
			e.dnsTypes = append(e.dnsTypes, 28)
		}
	}

	// Normalize domains (lowercase, trim spaces)
	for _, domain := range config.Domains {
		if d := strings.ToLower(strings.TrimSpace(domain)); d != "" {
			e.domains = append(e.domains, d)
		}
	}

	// Parse TLS versions once
	for _, ver := range config.TLSVersions {
		switch strings.ToUpper(ver) {
		case "TLS1.0", "TLS 1.0":
			e.tlsVersions = append(e.tlsVersions, 0x0301)
		case "TLS1.1", "TLS 1.1":
			e.tlsVersions = append(e.tlsVersions, 0x0302)
		case "TLS1.2", "TLS 1.2":
			e.tlsVersions = append(e.tlsVersions, 0x0303)
		case "TLS1.3", "TLS 1.3":
			e.tlsVersions = append(e.tlsVersions, 0x0304)
		}
	}

	// Normalize SNI patterns
	for _, sni := range config.SNIHosts {
		if s := strings.ToLower(strings.TrimSpace(sni)); s != "" {
			e.sniHosts = append(e.sniHosts, s)
		}
	}

	return e
}

func (e *FilterEngine) ShouldLog(event interface{}) bool {
	switch evt := event.(type) {
	case *types.ProcessInfo:
		matched := e.matchProcess(evt)
		if !matched {
			excludedEventsTotal.With(prometheus.Labels{
				"filter_type": "process",
			}).Inc()
		}
		return matched
	case *types.NetworkEvent:
		matched := e.matchNetwork(evt)
		if !matched {
			excludedEventsTotal.With(prometheus.Labels{
				"filter_type": "network",
			}).Inc()
		}
		return matched
	case *types.UserSpaceDNSEvent:
		matched := e.matchDNS(evt)
		if !matched {
			excludedEventsTotal.With(prometheus.Labels{
				"filter_type": "dns",
			}).Inc()
		}
		return matched
	case *types.UserSpaceTLSEvent:
		matched := e.matchTLS(evt)
		if !matched {
			excludedEventsTotal.With(prometheus.Labels{
				"filter_type": "tls",
			}).Inc()
		}
		return matched
	default:
		// Unknown event type, log by default
		return true
	}
}

func parseUint32Slice(strings []string) ([]uint32, error) {
	var result []uint32
	for _, s := range strings {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, err
		}
		result = append(result, uint32(v))
	}
	return result, nil
}

func parseUint16Slice(strings []string) ([]uint16, error) {
	var result []uint16
	for _, s := range strings {
		v, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return nil, err
		}
		result = append(result, uint16(v))
	}
	return result, nil
}

// Matching options: PID, PPID, Comm, CmdLine, BinaryHash
func (e *FilterEngine) matchProcess(info *types.ProcessInfo) bool {
	// If no filters at all, fast path
	if !e.hasProcessFilters {
		return true
	}

	// If tree tracking is enabled and this process is in a tracked tree,
	// accept it regardless of other filters
	if e.config.TrackTree && e.processTree.IsInTree(info.PID) {
		return true
	}

	// PID matching
	if len(e.pids) > 0 {
		pidMatch := false
		for _, pid := range e.pids {
			if info.PID == pid {
				pidMatch = true
				// If we're tracking trees, add this as a root
				if e.config.TrackTree {
					e.processTree.AddRoot(info.PID)
				}
				break
			}
		}
		if !pidMatch {
			return false
		}
	}

	// PPID matching
	if len(e.ppids) > 0 {
		ppidMatch := false
		for _, ppid := range e.ppids {
			if info.PPID == ppid {
				ppidMatch = true
				// If we're tracking trees, add this as a root
				if e.config.TrackTree {
					e.processTree.AddRoot(info.PID)
				}
				break
			}
		}
		if !ppidMatch {
			return false
		}
	}

	// Command name matching
	if len(e.config.CommandNames) > 0 {
		commMatch := false
		comm := string(bytes.TrimRight([]byte(info.Comm), "\x00"))
		for _, name := range e.config.CommandNames {
			if strings.Contains(comm, name) {
				commMatch = true
				// If we're tracking trees, add this as a root
				if e.config.TrackTree {
					e.processTree.AddRoot(info.PID)
				}
				break
			}
		}
		if !commMatch {
			return false
		}
	}

	// Executable path matching
	if len(e.config.ExePaths) > 0 {
		exePathMatch := false
		for _, exePath := range e.config.ExePaths {
			// Check for both exact matches and path prefix matches for flexibility
			if strings.EqualFold(info.ExePath, exePath) || strings.HasPrefix(info.ExePath, exePath) {
				exePathMatch = true
				// If we're tracking trees, add this as a root
				if e.config.TrackTree {
					e.processTree.AddRoot(info.PID)
				}
				break
			}
		}
		if !exePathMatch {
			return false
		}
	}

	// Command line substring matching
	if len(e.config.CmdlineContains) > 0 {
		cmdlineMatch := false
		for _, substr := range e.config.CmdlineContains {
			if strings.Contains(info.CmdLine, substr) {
				cmdlineMatch = true
				// If we're tracking trees, add this as a root
				if e.config.TrackTree {
					e.processTree.AddRoot(info.PID)
				}
				break
			}
		}
		if !cmdlineMatch {
			return false
		}
	}

	// Binary hash matching
	if len(e.config.BinaryHashes) > 0 {
		hashMatch := false
		if info.BinaryHash != "" {
			for _, hash := range e.config.BinaryHashes {
				if strings.EqualFold(info.BinaryHash, hash) {
					hashMatch = true
					// If we're tracking trees, add this as a root
					if e.config.TrackTree {
						e.processTree.AddRoot(info.PID)
					}
					break
				}
			}
			if !hashMatch {
				return false
			}
		} else {
			// No hash available, can't match
			return false
		}
	}

	// Username matching
	if len(e.config.UserNames) > 0 {
		userMatch := false
		for _, username := range e.config.UserNames {
			if strings.EqualFold(info.Username, username) {
				userMatch = true
				// If we're tracking trees, add this as a root
				if e.config.TrackTree {
					e.processTree.AddRoot(info.PID)
				}
				break
			}
		}
		if !userMatch {
			return false
		}
	}

	// Container ID matching
	if len(e.config.ContainerIDs) > 0 {
		containerMatch := false
		for _, containerID := range e.config.ContainerIDs {
			if containerID == "*" || strings.EqualFold(info.ContainerID, containerID) {
				containerMatch = true
				if e.config.TrackTree {
					e.processTree.AddRoot(info.PID)
				}
				break
			}
		}
		if !containerMatch {
			return false
		}
	}

	return true
}

func (e *FilterEngine) matchNetwork(evt *types.NetworkEvent) bool {
	// If no filters at all, fast path
	if !e.hasProcessFilters && !e.hasNetworkFilters {
		return true
	}

	// If we have process filters, must check those
	if e.hasProcessFilters {
		if procInfo, exists := GetProcessFromCache(evt.Pid); exists {
			if !e.matchProcess(procInfo) {
				return false
			}
		} else {
			return false
		}
	}

	// Source port matching
	if len(e.srcPorts) > 0 {
		portMatch := false
		for _, port := range e.srcPorts {
			if evt.SrcPort == port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}

	// Destination port matching
	if len(e.dstPorts) > 0 {
		portMatch := false
		for _, port := range e.dstPorts {
			if evt.DstPort == port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}

	// Source IP matching
	if len(e.srcIPs) > 0 {
		ipMatch := false
		srcIP := uint32ToNetIP(evt.SrcIP)
		for _, ip := range e.srcIPs {
			if ip.Equal(srcIP) {
				ipMatch = true
				break
			}
		}
		if !ipMatch {
			return false
		}
	}

	// Destination IP matching
	if len(e.dstIPs) > 0 {
		ipMatch := false
		dstIP := uint32ToNetIP(evt.DstIP)
		for _, ip := range e.dstIPs {
			if ip.Equal(dstIP) {
				ipMatch = true
				break
			}
		}
		if !ipMatch {
			return false
		}
	}

	// Protocol matching
	if len(e.protocols) > 0 {
		protoMatch := false
		for _, proto := range e.protocols {
			if evt.Protocol == proto {
				protoMatch = true
				break
			}
		}
		if !protoMatch {
			return false
		}
	}

	return true
}

func (e *FilterEngine) matchDNS(evt *types.UserSpaceDNSEvent) bool {
	// If no filters at all, fast path
	if !e.hasProcessFilters && !e.hasDNSFilters {
		return true
	}

	// If we have process filters, must check those
	if e.hasProcessFilters {
		if procInfo, exists := GetProcessFromCache(evt.Pid); exists {
			if !e.matchProcess(procInfo) {
				return false
			}
		} else {
			return false
		}
	}

	// DNS type matching
	if len(e.dnsTypes) > 0 {
		typeMatch := false
		for _, q := range evt.Questions {
			for _, t := range e.dnsTypes {
				if q.Type == t {
					typeMatch = true
					break
				}
			}
			if typeMatch {
				break
			}
		}
		if !typeMatch {
			return false
		}
	}

	// Domain matching
	if len(e.domains) > 0 {
		domainMatch := false
		// Check questions
		for _, q := range evt.Questions {
			qName := strings.ToLower(q.Name)
			for _, pattern := range e.domains {
				if matchDomain(qName, pattern) {
					domainMatch = true
					break
				}
			}
			if domainMatch {
				break
			}
		}
		// Check answers if it's a response
		if !domainMatch && evt.IsResponse {
			for _, a := range evt.Answers {
				aName := strings.ToLower(a.Name)
				for _, pattern := range e.domains {
					if matchDomain(aName, pattern) {
						domainMatch = true
						break
					}
				}
				if domainMatch {
					break
				}
			}
		}
		if !domainMatch {
			return false
		}
	}

	return true
}

func (e *FilterEngine) matchTLS(evt *types.UserSpaceTLSEvent) bool {
	// If no filters at all, fast path
	if !e.hasProcessFilters && !e.hasTLSFilters {
		return true
	}

	// If we have process filters, must check those
	if e.hasProcessFilters {
		if procInfo, exists := GetProcessFromCache(evt.Pid); exists {
			if !e.matchProcess(procInfo) {
				return false
			}
		} else {
			return false
		}
	}

	// TLS version matching
	if len(e.tlsVersions) > 0 {
		versionMatch := false
		for _, ver := range e.tlsVersions {
			if evt.TLSVersion == ver {
				versionMatch = true
				break
			}
		}
		if !versionMatch {
			return false
		}
	}

	// SNI matching
	if len(e.sniHosts) > 0 {
		sniMatch := false
		sni := strings.ToLower(evt.SNI)
		for _, pattern := range e.sniHosts {
			if matchDomain(sni, pattern) {
				sniMatch = true
				break
			}
		}
		if !sniMatch {
			return false
		}
	}

	return true
}

// Helper function for domain matching that supports wildcards
func matchDomain(domain, pattern string) bool {
	if pattern == "" || domain == "" {
		return false
	}

	// Convert to lowercase for case-insensitive matching
	domain = strings.ToLower(domain)
	pattern = strings.ToLower(pattern)

	// Handle wildcard patterns
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Include the dot
		return strings.HasSuffix(domain, suffix)
	}

	// Exact match
	return domain == pattern
}
