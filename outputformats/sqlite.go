package outputformats

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"

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

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %v", err)
	}

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
	schema := `
	-- Process events
	CREATE TABLE IF NOT EXISTS processes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_uid TEXT NOT NULL,
		process_uid TEXT NOT NULL,
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
		cpu_usage REAL,
		memory_usage INTEGER,
		memory_percent REAL,
		thread_count INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
	CREATE INDEX IF NOT EXISTS idx_processes_ppid ON processes(ppid);
	CREATE INDEX IF NOT EXISTS idx_processes_session ON processes(session_uid);
	CREATE INDEX IF NOT EXISTS idx_processes_uid ON processes(process_uid);
	CREATE INDEX IF NOT EXISTS idx_processes_parent_uid ON processes(parent_uid);
	CREATE INDEX IF NOT EXISTS idx_processes_timestamp ON processes(timestamp);

	-- Network connections
	CREATE TABLE IF NOT EXISTS network_connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_uid TEXT NOT NULL,
		process_uid TEXT NOT NULL,
		network_uid TEXT NOT NULL,
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
		tcp_flags TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_network_session ON network_connections(session_uid);
	CREATE INDEX IF NOT EXISTS idx_network_process ON network_connections(process_uid);
	CREATE INDEX IF NOT EXISTS idx_network_connection ON network_connections(network_uid);
	CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_connections(timestamp);

	-- DNS events
	CREATE TABLE IF NOT EXISTS dns_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_uid TEXT NOT NULL,
		process_uid TEXT NOT NULL,
		network_uid TEXT NOT NULL,
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
		ttl INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_dns_session ON dns_events(session_uid);
	CREATE INDEX IF NOT EXISTS idx_dns_process ON dns_events(process_uid);
	CREATE INDEX IF NOT EXISTS idx_dns_network ON dns_events(network_uid);
	CREATE INDEX IF NOT EXISTS idx_dns_conversation ON dns_events(conversation_uid);
	CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_events(timestamp);

	-- TLS events
	CREATE TABLE IF NOT EXISTS tls_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_uid TEXT NOT NULL,
		process_uid TEXT NOT NULL,
		network_uid TEXT NOT NULL,
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
		ja4_hash TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_tls_session ON tls_events(session_uid);
	CREATE INDEX IF NOT EXISTS idx_tls_process ON tls_events(process_uid);
	CREATE INDEX IF NOT EXISTS idx_tls_network ON tls_events(network_uid);
	CREATE INDEX IF NOT EXISTS idx_tls_timestamp ON tls_events(timestamp);

	-- Sigma matches
	CREATE TABLE IF NOT EXISTS sigma_matches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_uid TEXT NOT NULL,
		process_uid TEXT NOT NULL,
		network_uid TEXT,
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
		status TEXT DEFAULT 'new'
	);

	CREATE INDEX IF NOT EXISTS idx_sigma_session ON sigma_matches(session_uid);
	CREATE INDEX IF NOT EXISTS idx_sigma_process ON sigma_matches(process_uid);
	CREATE INDEX IF NOT EXISTS idx_sigma_network ON sigma_matches(network_uid);
	CREATE INDEX IF NOT EXISTS idx_sigma_timestamp ON sigma_matches(timestamp);
	CREATE INDEX IF NOT EXISTS idx_sigma_rule ON sigma_matches(rule_id);
	CREATE INDEX IF NOT EXISTS idx_sigma_status ON sigma_matches(status);
	`

	_, err := db.Exec(schema)
	return err
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

	// Handle process exit event by updating existing entry
	if event.EventType == types.EVENT_PROCESS_EXIT {
		_, err := f.db.Exec(`
            UPDATE processes 
            SET exit_code = ?,
                exit_time = ?
            WHERE pid = ? 
                AND exit_time IS NULL
                AND session_uid = ?`,
			info.ExitCode,
			BpfTimestampToTime(event.Timestamp),
			info.PID,
			f.sessionUID)
		return err
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

	// Determine parent UID
	parentUID := ""
	if parentInfo != nil {
		parentUID = parentInfo.ProcessUID
	}

	// Insert into database
	_, err = f.db.Exec(`
        INSERT INTO processes (
            session_uid, process_uid, parent_uid, timestamp, pid, ppid,
            comm, cmdline, exe_path, working_dir, username, parent_comm,
            container_id, uid, gid, binary_hash, environment,
            exit_code, exit_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, parentUID,
		BpfTimestampToTime(event.Timestamp), info.PID, info.PPID,
		info.Comm, info.CmdLine, info.ExePath, info.WorkingDir,
		info.Username, parentInfo.Comm, info.ContainerID,
		info.UID, info.GID, info.BinaryHash, string(envJSON),
		nil, nil) // exit_code and exit_time will be updated later

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

	// Insert into database
	_, err := f.db.Exec(`
        INSERT INTO network_connections (
            session_uid, process_uid, network_uid, timestamp,
            pid, comm, ppid, parent_comm, protocol,
            src_ip, src_port, dst_ip, dst_port,
            direction, bytes, tcp_flags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, networkUID,
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

	// Get query and type from first question
	var query, recordType string
	if len(event.Questions) > 0 {
		query = event.Questions[0].Name
		recordType = dnsTypeToString(event.Questions[0].Type)
	}

	// Insert into database
	_, err = f.db.Exec(`
		INSERT INTO dns_events (
			session_uid, process_uid, network_uid, conversation_uid,
			timestamp, pid, comm, ppid, parent_comm,
			event_type, dns_flags, query, record_type,
			transaction_id, src_ip, src_port, dst_ip, dst_port,
			answers, ttl
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, networkUID, event.ConversationID,
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

	// Insert into database
	_, err = f.db.Exec(`
		INSERT INTO tls_events (
			session_uid, process_uid, network_uid, timestamp,
			pid, comm, ppid, parent_comm,
			src_ip, src_port, dst_ip, dst_port,
			version, sni, cipher_suites, supported_groups,
			handshake_length, ja4, ja4_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, networkUID,
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
			session_uid, process_uid, network_uid, timestamp,
			rule_id, rule_name, rule_level, rule_description,
			match_details, detection_source, event_data,
			rule_references, rule_tags
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, match.ProcessUID, match.NetworkUID,
		match.Timestamp,
		match.RuleID, match.RuleName, match.RuleLevel,
		match.RuleDescription,
		match.MatchedFields["details"],
		match.DetectionSource,
		string(eventDataJSON),
		string(referencesJSON),
		string(tagsJSON))

	return err
}
