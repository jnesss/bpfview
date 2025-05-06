package outputformats

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/tursodatabase/limbo"

	"github.com/jnesss/bpfview/fingerprint"
	"github.com/jnesss/bpfview/types"
)

// SQLiteFormatter implements the EventFormatter interface for SQLite storage
type SQLiteFormatter struct {
	db           *sql.DB
	sessionUID   string
	hostname     string
	hostIP       string
	sigmaEnabled bool
	mu           sync.RWMutex
}

// NewSQLiteFormatter creates a new SQLite formatter
func NewSQLiteFormatter(dbPath string, hostname, hostIP, sessionUID string, enableSigma bool) (*SQLiteFormatter, error) {
	// Create db directory if needed
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Limbo does not require WAL mode set
	//if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
	//	db.Close()
	//	return nil, fmt.Errorf("failed to enable WAL mode: %v", err)
	//}

	// Initialize schema
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	return &SQLiteFormatter{
		db:           db,
		sessionUID:   sessionUID,
		hostname:     hostname,
		hostIP:       hostIP,
		sigmaEnabled: enableSigma,
	}, nil
}

// Initialize schema
func initSchema(db *sql.DB) error {
	// Create tables separately with error checking
	tables := []string{
		`CREATE TABLE IF NOT EXISTS processes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_uid TEXT NOT NULL,
			process_uid TEXT NOT NULL,
			event_type TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			parent_uid TEXT,
			timestamp DATETIME NOT NULL,
			pid INTEGER NOT NULL,
			ppid INTEGER NOT NULL,
			comm TEXT NOT NULL,
			cmdline TEXT,
			exe_path TEXT,
			working_dir TEXT,
			username TEXT,
			parent_comm TEXT,
			container_id TEXT,
			uid INTEGER,
			gid INTEGER,
			binary_hash TEXT,
			environment TEXT,
			exit_code INTEGER,
			exit_time DATETIME,
			-- Vector embedding columns
			proc_embedding F32_BLOB(64),  -- Process behavior embedding
			context_embedding F32_BLOB(32) -- Contextual embedding
		);`,
		`CREATE TABLE IF NOT EXISTS network_connections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_uid TEXT NOT NULL,
			process_uid TEXT NOT NULL,
			network_uid TEXT NOT NULL,
			community_id TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			pid INTEGER NOT NULL,
			comm TEXT NOT NULL,
			ppid INTEGER,
			parent_comm TEXT,
			protocol TEXT,
			src_ip TEXT,
			src_port INTEGER,
			dst_ip TEXT,
			dst_port INTEGER,
			direction TEXT,
			bytes INTEGER,
			tcp_flags TEXT,
			-- Vector embedding columns
			net_embedding F32_BLOB(32)  -- Network behavior embedding
		);`,
		`CREATE TABLE IF NOT EXISTS dns_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_uid TEXT NOT NULL,
			process_uid TEXT NOT NULL,
			network_uid TEXT NOT NULL,
			community_id TEXT NOT NULL,
			conversation_uid TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			pid INTEGER NOT NULL,
			comm TEXT NOT NULL,
			ppid INTEGER,
			parent_comm TEXT,
			event_type TEXT NOT NULL,
			dns_flags INTEGER,
			query TEXT,
			record_type TEXT,
			transaction_id INTEGER,
			src_ip TEXT,
			src_port INTEGER,
			dst_ip TEXT,
			dst_port INTEGER,
			answers TEXT,
			ttl INTEGER,
			-- Vector embedding columns
			dns_embedding F32_BLOB(32)  -- DNS behavior embedding
		);`,
		`CREATE TABLE IF NOT EXISTS tls_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_uid TEXT NOT NULL,
			process_uid TEXT NOT NULL,
			network_uid TEXT NOT NULL,
			community_id TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			pid INTEGER NOT NULL,
			comm TEXT NOT NULL,
			ppid INTEGER,
			parent_comm TEXT,
			src_ip TEXT,
			src_port INTEGER,
			dst_ip TEXT,
			dst_port INTEGER,
			version TEXT,
			sni TEXT,
			cipher_suites TEXT,
			supported_groups TEXT,
			handshake_length INTEGER,
			ja4 TEXT,
			ja4_hash TEXT,
			-- Vector embedding columns
			tls_embedding F32_BLOB(32)  -- TLS behavior embedding
		);`,
		`CREATE TABLE IF NOT EXISTS sigma_matches (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_uid TEXT NOT NULL,
			process_uid TEXT NOT NULL,
			network_uid TEXT,
			community_id TEXT,
			conversation_uid TEXT,
			timestamp DATETIME NOT NULL,
			rule_id TEXT NOT NULL,
			rule_name TEXT NOT NULL,
			rule_level TEXT NOT NULL,
			rule_description TEXT,
			match_details TEXT,
			detection_source TEXT NOT NULL,
			event_data TEXT,
			rule_references TEXT,
			rule_tags TEXT,
			status TEXT DEFAULT 'new');`,
	}

	// Execute each table creation separately
	for i, table := range tables {
		if _, err := db.Exec(table); err != nil {
			return fmt.Errorf("failed to create table %d: %v", i+1, err)
		}
	}

	return nil
}

func (f *SQLiteFormatter) Initialize() error {
	return nil
}

func (f *SQLiteFormatter) Close() error {
	return f.db.Close()
}

func (f *SQLiteFormatter) FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo, parentInfo *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var eventType string
	if event.EventType == types.EVENT_PROCESS_EXIT {
		eventType = "exit"
	} else if event.EventType == types.EVENT_PROCESS_FORK {
		eventType = "fork"
	} else {
		eventType = "exec"
	}

	// Create process pattern for embedding generation
	pattern := fingerprint.NewProcessPattern(info, parentInfo)

	// Set parent pattern if available
	if parentInfo != nil && parentInfo.Fingerprint != "" {
		pattern.ParentPattern = parentInfo.Fingerprint
	}

	// Generate embeddings
	procEmbedding := createProcessEmbedding(pattern)
	contextEmbedding := createContextEmbedding(info)

	// Convert embeddings to SQL strings - format as [val1,val2,val3]
	procEmbeddingStr := vectorToSQLString(procEmbedding)
	contextEmbeddingStr := vectorToSQLString(contextEmbedding)

	// Get fingerprint
	var fingerprint string
	if info.Fingerprint != "" {
		if info.ParentFingerprint != "" {
			fingerprint = fmt.Sprintf("%v_%v", info.Fingerprint, info.ParentFingerprint)
		} else {
			fingerprint = info.Fingerprint
		}
	}

	// Convert environment to JSON if present
	var envJSON []byte
	var err error
	if len(info.Environment) > 0 {
		envJSON, err = json.Marshal(info.Environment)
		if err != nil {
			return fmt.Errorf("failed to marshal environment: %v", err)
		}
	}

	// Get parent UID
	var parentUID string
	if parentInfo != nil && parentInfo.ProcessUID != "" {
		parentUID = parentInfo.ProcessUID
	}

	// Determine exit code and time based on event type
	var exitCode interface{} = nil
	var exitTime interface{} = nil
	if eventType == "exit" {
		exitCode = info.ExitCode
		exitTime = BpfTimestampToTime(event.Timestamp)
	}

	// Insert process with both vector embeddings in a single statement
	_, err = f.db.Exec(`
        INSERT INTO processes (
            session_uid, process_uid, event_type, fingerprint, parent_uid, timestamp, 
            pid, ppid, comm, cmdline, exe_path, working_dir, username, 
            parent_comm, container_id, uid, gid, binary_hash,
            environment, exit_code, exit_time,
            proc_embedding, context_embedding
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, vector(?), vector(?))`,
		f.sessionUID, info.ProcessUID, eventType, fingerprint, parentUID, BpfTimestampToTime(event.Timestamp),
		info.PID, info.PPID, info.Comm, info.CmdLine, info.ExePath, info.WorkingDir, info.Username,
		info.ParentComm, info.ContainerID, info.UID, info.GID, info.BinaryHash,
		string(envJSON), exitCode, exitTime,
		procEmbeddingStr, contextEmbeddingStr)

	return err
}

func (f *SQLiteFormatter) FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Convert comm and parent_comm from [16]uint8 to string
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Convert direction to string
	direction := "egress"
	if event.Direction == types.FLOW_INGRESS {
		direction = "ingress"
	}

	// Generate network_uid
	networkUID := GenerateBidirectionalConnID(
		event.Pid, event.Ppid,
		uint32ToNetIP(event.SrcIP), uint32ToNetIP(event.DstIP),
		event.SrcPort, event.DstPort)
	communityID := GenerateCommunityID(
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort,
		event.DstPort,
		event.Protocol,
		0) // default seed

	// Insert into database
	_, err := f.db.Exec(`
        INSERT INTO network_connections (
            session_uid, process_uid, network_uid, community_id, 
            timestamp, pid, comm, ppid, parent_comm, protocol,
            src_ip, src_port, dst_ip, dst_port,
            direction, bytes, tcp_flags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, networkUID, communityID,
		BpfTimestampToTime(event.Timestamp),
		event.Pid, comm, event.Ppid, parentComm,
		protocolToString(event.Protocol),
		ipToString(event.SrcIP), event.SrcPort,
		ipToString(event.DstIP), event.DstPort,
		direction, event.BytesCount,
		FormatTCPFlags(event.TCPFlags))

	return err
}

func (f *SQLiteFormatter) FormatDNS(event *types.UserSpaceDNSEvent, info *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Convert answers to JSON
	var answersJSON []byte
	var err error
	if len(event.Answers) > 0 {
		answersJSON, err = json.Marshal(event.Answers)
		if err != nil {
			return fmt.Errorf("failed to marshal DNS answers: %v", err)
		}
	}

	// Generate network_uid
	networkUID := GenerateBidirectionalConnID(
		event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)
	communityID := GenerateCommunityID(
		event.SourceIP,
		event.DestIP,
		event.SourcePort,
		event.DestPort,
		17, // UDP
		0)  // default seed

	// Get query and type from first question
	var query, recordType string
	if len(event.Questions) > 0 {
		query = event.Questions[0].Name
		recordType = dnsTypeToString(event.Questions[0].Type)
	}

	// Insert into database
	_, err = f.db.Exec(`
		INSERT INTO dns_events (
			session_uid, process_uid, network_uid, community_id, conversation_uid,
			timestamp, pid, comm, ppid, parent_comm,
			event_type, dns_flags, query, record_type,
			transaction_id, src_ip, src_port, dst_ip, dst_port,
			answers, ttl
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, networkUID, communityID, event.ConversationID,
		BpfTimestampToTime(event.Timestamp),
		event.Pid, event.Comm, event.Ppid, event.ParentComm,
		map[bool]string{true: "response", false: "query"}[event.IsResponse],
		event.DNSFlags, query, recordType,
		event.TransactionID,
		event.SourceIP.String(), event.SourcePort,
		event.DestIP.String(), event.DestPort,
		string(answersJSON),
		0) // TTL currently not tracked

	return err
}

func (f *SQLiteFormatter) FormatTLS(event *types.UserSpaceTLSEvent, info *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Convert arrays to JSON
	cipherSuitesJSON, err := json.Marshal(event.CipherSuites)
	if err != nil {
		return fmt.Errorf("failed to marshal cipher suites: %v", err)
	}

	supportedGroupsJSON, err := json.Marshal(event.SupportedGroups)
	if err != nil {
		return fmt.Errorf("failed to marshal supported groups: %v", err)
	}

	// Generate network_uid
	networkUID := GenerateBidirectionalConnID(
		event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)
	communityID := GenerateCommunityID(
		event.SourceIP,
		event.DestIP,
		event.SourcePort,
		event.DestPort,
		event.Protocol,
		0) // default seed

	// Insert into database
	_, err = f.db.Exec(`
		INSERT INTO tls_events (
			session_uid, process_uid, network_uid, community_id,
            timestamp, pid, comm, ppid, parent_comm,
			src_ip, src_port, dst_ip, dst_port,
			version, sni, cipher_suites, supported_groups,
			handshake_length, ja4, ja4_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, networkUID, communityID,
		BpfTimestampToTime(event.Timestamp),
		event.Pid, event.Comm, event.Ppid, event.ParentComm,
		event.SourceIP.String(), event.SourcePort,
		event.DestIP.String(), event.DestPort,
		formatTlsVersion(event.TLSVersion), event.SNI,
		string(cipherSuitesJSON), string(supportedGroupsJSON),
		event.HandshakeLength, event.JA4, event.JA4Hash)

	return err
}

func (f *SQLiteFormatter) FormatSigmaMatch(match *types.SigmaMatch) error {
	if !f.sigmaEnabled {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Convert arrays to JSON
	referencesJSON, err := json.Marshal(match.RuleReferences)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %v", err)
	}

	tagsJSON, err := json.Marshal(match.RuleTags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %v", err)
	}

	eventDataJSON, err := json.Marshal(match.EventData)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %v", err)
	}

	// Insert into database
	_, err = f.db.Exec(`
		INSERT INTO sigma_matches (
			session_uid, process_uid, network_uid, 
            community_id, conversation_uid, timestamp, 
            rule_id, rule_name, rule_level, rule_description,
			match_details, detection_source, event_data,
			rule_references, rule_tags
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, match.ProcessUID, match.NetworkUID,
		match.CommunityID, match.ConversationID, match.Timestamp,
		match.RuleID, match.RuleName, match.RuleLevel,
		match.RuleDescription,
		match.MatchedFields["details"],
		match.DetectionSource,
		string(eventDataJSON),
		string(referencesJSON),
		string(tagsJSON))

	return err
}

// createProcessEmbedding generates a vector embedding from process information
func createProcessEmbedding(pattern *fingerprint.ProcessPattern) []float32 {
	// Create a 64-dimensional vector embedding
	embedding := make([]float32, 64)

	// 1. Basic process attributes (dimensions 0-9)
	// Event type mapping
	switch pattern.EventType {
	case "e": // exec
		embedding[0] = 1.0
	case "f": // fork
		embedding[1] = 1.0
	case "x": // exit
		embedding[2] = 1.0
	}

	// Container status
	if pattern.IsContainer {
		embedding[3] = 1.0
	}

	// User ID (normalized to 0-1 range)
	embedding[4] = float32(pattern.UID%1000) / 1000.0

	// 2. Command line features (dimensions 10-39)
	tokens := strings.Fields(pattern.NormalizedCommand)

	// Track feature counts
	var flagCount, filepathCount, valueCount, urlCount, ipCount int
	var hasRedirection, hasPipe bool

	for _, token := range tokens {
		// Flag analysis
		if strings.HasPrefix(token, "FLAG_") {
			flagCount++
			// Specific flag types
			if strings.Contains(token, "VERBOSE") || strings.Contains(token, "DEBUG") {
				embedding[10] = 1.0
			}
			if strings.Contains(token, "OUTPUT") || strings.Contains(token, "FILE") {
				embedding[11] = 1.0
			}
			if strings.Contains(token, "HELP") || strings.Contains(token, "VERSION") {
				embedding[12] = 1.0
			}
			if strings.Contains(token, "RECURSIVE") || strings.Contains(token, "ALL") {
				embedding[13] = 1.0
			}
		}

		// Filepath analysis
		if strings.HasPrefix(token, "FILEPATH") {
			filepathCount++
			// Specific path types
			if token == "FILEPATH_TEMP" {
				embedding[15] = 1.0
			}
			if token == "FILEPATH_HOME" {
				embedding[16] = 1.0
			}
			if token == "FILEPATH_SYS" {
				embedding[17] = 1.0
			}
			if token == "FILEPATH_ETC" || token == "FILEPATH_VAR" {
				embedding[18] = 1.0
			}
		}

		// URL and IP analysis
		if token == "URL" {
			urlCount++
			embedding[20] = 1.0
		}
		if token == "IP" {
			ipCount++
			embedding[21] = 1.0
		}

		// Shell operations
		if token == "PIPE" {
			hasPipe = true
			embedding[25] = 1.0
		}
		if token == "REDIRECT" {
			hasRedirection = true
			embedding[26] = 1.0
		}
		if token == "AND" || token == "OR" {
			embedding[27] = 1.0
		}

		// Generic values
		if token == "VALUE" || token == "NUM" || token == "DATE" {
			valueCount++
		}
	}

	// Command complexity features
	embedding[30] = min(float32(flagCount)/5.0, 1.0)     // Normalized flag count
	embedding[31] = min(float32(filepathCount)/5.0, 1.0) // Normalized filepath count
	embedding[32] = min(float32(valueCount)/10.0, 1.0)   // Normalized value count
	embedding[33] = min(float32(len(tokens))/20.0, 1.0)  // Normalized token count

	// Network related features
	embedding[35] = min(float32(urlCount)/3.0, 1.0) // Normalized URL count
	embedding[36] = min(float32(ipCount)/3.0, 1.0)  // Normalized IP count

	// Command syntax complexity
	if hasPipe && hasRedirection {
		embedding[38] = 1.0 // Complex shell pipeline
	} else if hasPipe || hasRedirection {
		embedding[39] = 1.0 // Simple shell operation
	}

	// 3. Parent relationship (dimensions 40-49)
	if pattern.ParentPattern != "" {
		// Extract features from parent fingerprint
		embedding[40] = 1.0 // Has known parent

		// We could hash the parent pattern and use the value for embedding dimensions
		h := fnv.New32a()
		h.Write([]byte(pattern.ParentPattern))
		hashVal := float32(h.Sum32()%1000) / 1000.0
		embedding[41] = hashVal
	}

	// 4. Working directory features (dimensions 50-59)
	switch pattern.WorkingDir {
	case "FILEPATH_HOME":
		embedding[50] = 1.0
	case "FILEPATH_TEMP":
		embedding[51] = 1.0
	case "FILEPATH_SYS":
		embedding[52] = 1.0
	case "FILEPATH_VAR":
		embedding[53] = 1.0
	case "FILEPATH_ETC":
		embedding[54] = 1.0
	default:
		embedding[55] = 1.0 // Other directories
	}

	// 5. Reserved for future features (dimensions 60-63)

	return embedding
}

// createContextEmbedding generates an embedding capturing context (time, system state)
func createContextEmbedding(info *types.ProcessInfo) []float32 {
	// Create a 32-dimensional context embedding
	embedding := make([]float32, 32)

	// Time-based features
	hour := float32(info.StartTime.Hour())
	// Normalize hour of day (0-23) to 0-1 range
	embedding[0] = hour / 23.0

	// Day of week (0=Sunday, 6=Saturday)
	dayOfWeek := float32(info.StartTime.Weekday())
	embedding[1] = dayOfWeek / 6.0

	// Business hours feature (8am-6pm = 1.0, otherwise scaled to zero)
	if hour >= 8 && hour <= 18 {
		embedding[2] = 1.0
	} else if hour < 8 {
		// Scale from midnight (0) to 8am (near 1.0)
		embedding[2] = hour / 8.0
	} else {
		// Scale from 6pm (near 1.0) to midnight (0)
		embedding[2] = (24.0 - hour) / 6.0
	}

	// Weekend feature
	if dayOfWeek == 0 || dayOfWeek == 6 {
		embedding[3] = 1.0
	}

	// User context
	if info.UID == 0 {
		// Root user
		embedding[4] = 1.0
	} else if info.UID < 1000 {
		// System user
		embedding[5] = 1.0
	} else {
		// Regular user
		embedding[6] = 1.0
	}

	// Container context
	if info.ContainerID != "" && info.ContainerID != "-" {
		embedding[7] = 1.0
	}

	// Parse username for specific user types
	username := strings.ToLower(info.Username)
	if strings.Contains(username, "admin") || strings.Contains(username, "root") {
		embedding[8] = 1.0
	} else if strings.Contains(username, "service") || strings.Contains(username, "daemon") {
		embedding[9] = 1.0
	}

	// Reserved for additional context features

	return embedding
}

// vectorToSQLString converts a float32 slice to a proper string format for Limbo's vector function
func vectorToSQLString(embedding []float32) string {
	values := make([]string, len(embedding))
	for i, val := range embedding {
		values[i] = fmt.Sprintf("%f", val)
	}
	return fmt.Sprintf("[%s]", strings.Join(values, ","))
}

// Utility function to get the minimum of two float32 values
func min(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}
