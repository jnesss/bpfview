package outputformats

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/tursodatabase/limbo"

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
			exit_time DATETIME);`,
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
			tcp_flags TEXT);`,
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
			ttl INTEGER);`,
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
			ja4_hash TEXT);`,
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

	if eventType == "exit" {
		_, err := f.db.Exec(`
            INSERT INTO processes (
                session_uid, process_uid, event_type, parent_uid, timestamp, 
                pid, ppid, comm, cmdline, exe_path, working_dir, username, 
                parent_comm, container_id, uid, gid, binary_hash,
                exit_code, exit_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.sessionUID, info.ProcessUID, eventType, parentInfo.ProcessUID, BpfTimestampToTime(event.Timestamp),
			info.PID, info.PPID, info.Comm, info.CmdLine, info.ExePath, info.WorkingDir, info.Username,
			info.ParentComm, info.ContainerID, info.UID, info.GID, info.BinaryHash,
			info.ExitCode, BpfTimestampToTime(event.Timestamp))

		// EXIT is done
		return err
	}

	var fingerprint string
	if info.Fingerprint != "" {
		if info.ParentFingerprint != "" {
			fingerprint = fmt.Sprintf("%v_%v", info.Fingerprint, info.ParentFingerprint)
		} else {
			fingerprint = info.Fingerprint
		}
	}

	// if eventType == "exec" || eventType == "fork"
	_, err := f.db.Exec(`
            INSERT INTO processes (
                session_uid, process_uid, event_type, fingerprint, parent_uid, timestamp,
                pid, ppid, comm, cmdline, exe_path, working_dir, username, 
                parent_comm, container_id, uid, gid, binary_hash,
                exit_code, exit_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionUID, info.ProcessUID, eventType, fingerprint, parentInfo.ProcessUID, BpfTimestampToTime(event.Timestamp),
		info.PID, info.PPID, info.Comm, info.CmdLine, info.ExePath, info.WorkingDir, info.Username,
		info.ParentComm, info.ContainerID, info.UID, info.GID, info.BinaryHash, nil, nil)
	if err != nil {
		return err
	}

	// Convert environment to JSON if present
	//  Might put env vars in a separate table eventually..
	var envJSON []byte
	if len(info.Environment) > 0 {
		envJSON, err = json.Marshal(info.Environment)
		if err != nil {
			return fmt.Errorf("failed to marshal environment: %v", err)
		}
	}

	// Insert into database
	_, err = f.db.Exec(`UPDATE processes set environment = ? where session_uid = ? and process_uid = ?`,
		string(envJSON), f.sessionUID, info.ProcessUID)

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
