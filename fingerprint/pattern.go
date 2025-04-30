// fingerprint/pattern.go
package fingerprint

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/jnesss/bpfview/types"
)

// ProcessPattern represents a normalized process execution pattern
type ProcessPattern struct {
	// Human-readable components
	Comm         string
	EventType    string // "f" for fork, "e" for exec, "x" for exit
	IsContainer  bool
	UID          uint32
	BinaryPrefix string // First 6 chars of binary hash or "000000"

	// Components for hash generation
	NormalizedCommand string
	WorkingDir        string
	ParentComm        string
	ParentPattern     string // Full parent fingerprint

	// Original command info for reference
	OriginalCmd string
}

// Compile patterns once at init
var (
	// Path patterns
	tempPathPattern   = regexp.MustCompile(`^/tmp(/.*)?$`)
	homePathPattern   = regexp.MustCompile(`^/home/[^/]+(/.*)?$`)
	systemPathPattern = regexp.MustCompile(`^/(bin|sbin|usr(/[^/]+)?|usr/local(/[^/]+)?)(/.*)?$`)
	procPathPattern   = regexp.MustCompile(`^/proc(/.*)?$`)
	etcPathPattern    = regexp.MustCompile(`^/etc(/.*)?$`)
	varPathPattern    = regexp.MustCompile(`^/var(/.*)?$`)
	devPathPattern    = regexp.MustCompile(`^/dev(/.*)?$`)
	optPathPattern    = regexp.MustCompile(`^/opt(/.*)?$`)

	// Data type patterns
	ipPattern     = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$`)
	urlPattern    = regexp.MustCompile(`^(https?|ftp|file)://[^\s]+$`)
	numberPattern = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	emailPattern  = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	hashPattern   = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)
	hexPattern    = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	datePattern   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z?)?$`)

	// Flag patterns
	longFlagPattern  = regexp.MustCompile(`^--[a-zA-Z0-9][-a-zA-Z0-9_]*$`)
	shortFlagPattern = regexp.MustCompile(`^-[a-zA-Z0-9]+$`)
	envVarPattern    = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*=.*$`)

	// Redirection and pipe patterns
	logicalOperatorPattern = regexp.MustCompile(`^(&&|\|\|)$`)
	redirectionPattern     = regexp.MustCompile(`^[><]{1,2}$`)
	pipePattern            = regexp.MustCompile(`^\|$`)

	// Special flag patterns
	plusFlagPattern = regexp.MustCompile(`^\+[a-zA-Z0-9]+$`)
)

// NewProcessPattern creates a pattern from process information
func NewProcessPattern(info *types.ProcessInfo, parentInfo *types.ProcessInfo) *ProcessPattern {
	pattern := &ProcessPattern{
		Comm:        info.Comm,
		EventType:   eventTypeToChar(info.EventType),
		UID:         info.UID,
		IsContainer: info.ContainerID != "" && info.ContainerID != "-",
		WorkingDir:  normalizePath(info.WorkingDir),
		OriginalCmd: info.CmdLine,
	}

	// Set binary prefix
	if info.BinaryHash != "" && len(info.BinaryHash) >= 6 {
		pattern.BinaryPrefix = info.BinaryHash[:6]
	} else {
		pattern.BinaryPrefix = "000000"
	}

	// Set parent info
	if parentInfo != nil {
		pattern.ParentComm = parentInfo.Comm
		// Parent pattern will be set externally
	}

	// Generate normalized command representation
	pattern.NormalizedCommand = normalizeCommandLine(info.CmdLine)

	return pattern
}

// GenerateFingerprint creates the human-readable fingerprint
func (p *ProcessPattern) GenerateFingerprint() string {
	// Create human-readable prefix
	prefix := fmt.Sprintf("%s_%s_%s_u%d_b%s",
		normalizeString(p.Comm),
		p.EventType,
		map[bool]string{true: "c", false: "h"}[p.IsContainer],
		p.UID,
		p.BinaryPrefix)

	// Generate hash portion
	hashID := p.generateHashID()
	return fmt.Sprintf("%s_%x", prefix, hashID)
}

func (p *ProcessPattern) generateHashID() uint32 {
	h := fnv.New32a()

	// Hash stable attributes
	h.Write([]byte(p.NormalizedCommand))
	h.Write([]byte(p.WorkingDir))
	h.Write([]byte(p.ParentComm))

	return h.Sum32()
}

// tokenizeCommandLine splits a command line into tokens
// tokenizeCommandLine splits a command line into tokens
func tokenizeCommandLine(cmdLine string) []string {
	var tokens []string
	var currentToken strings.Builder
	inQuotes := false
	quoteChar := rune(0)
	escapeNext := false

	for i := 0; i < len(cmdLine); i++ {
		char := rune(cmdLine[i])

		// Handle escape sequences
		if escapeNext {
			// Simplified escaping - just include the character
			if char == 'n' || char == 't' || char == 'r' {
				// Handle common escape sequences by removing the backslash
				currentToken.WriteRune(char)
			} else {
				currentToken.WriteRune(char)
			}
			escapeNext = false
			continue
		}

		// Check for escape character
		if char == '\\' && !escapeNext {
			escapeNext = true
			continue
		}

		switch {
		case (char == '"' || char == '\'') && !inQuotes:
			inQuotes = true
			quoteChar = char
		case char == quoteChar && inQuotes:
			inQuotes = false
			quoteChar = rune(0)
		case char == ' ' && !inQuotes:
			if currentToken.Len() > 0 {
				tokens = append(tokens, currentToken.String())
				currentToken.Reset()
			}
		case (char == '|' || char == '>' || char == '<') && !inQuotes:
			// Handle special shell operators
			if currentToken.Len() > 0 {
				// Check if this is a numeric redirection (like 2>)
				if isNumericPrefix(currentToken.String()) {
					token := currentToken.String() + string(char)
					tokens = append(tokens, token)
					currentToken.Reset()
				} else {
					tokens = append(tokens, currentToken.String())
					currentToken.Reset()

					// Check for multi-character operators (<<, >>, etc.)
					if i+1 < len(cmdLine) &&
						(cmdLine[i+1] == '>' || cmdLine[i+1] == '<') {
						// Add the two-character operator as a single token
						tokens = append(tokens, string(char)+string(cmdLine[i+1]))
						i++ // Skip the next character
					} else {
						tokens = append(tokens, string(char))
					}
				}
			} else {
				// Check for multi-character operators (<<, >>, etc.)
				if i+1 < len(cmdLine) &&
					(cmdLine[i+1] == '>' || cmdLine[i+1] == '<') {
					// Add the two-character operator as a single token
					tokens = append(tokens, string(char)+string(cmdLine[i+1]))
					i++ // Skip the next character
				} else {
					tokens = append(tokens, string(char))
				}
			}
		default:
			currentToken.WriteRune(char)
		}
	}

	// Add the last token if any
	if currentToken.Len() > 0 {
		tokens = append(tokens, currentToken.String())
	}

	// Process combined redirection tokens like 2>&1
	for i := 0; i < len(tokens)-1; i++ {
		if (tokens[i] == "2>" || tokens[i] == "1>" ||
			tokens[i] == ">" || tokens[i] == "<") &&
			i+1 < len(tokens) && tokens[i+1] == "&1" {
			tokens[i] = tokens[i] + tokens[i+1]
			tokens = append(tokens[:i+1], tokens[i+2:]...)
		}
	}

	return tokens
}

// isNumericPrefix checks if a token is a numeric prefix (like 2 in 2>)
func isNumericPrefix(token string) bool {
	if len(token) == 0 {
		return false
	}
	return token == "1" || token == "2" || token == "0" ||
		numberPattern.MatchString(token)
}

// eventTypeToChar converts event type to a single character
func eventTypeToChar(eventType string) string {
	switch eventType {
	case "fork":
		return "f"
	case "exec":
		return "e"
	case "exit":
		return "x"
	default:
		return "u" // unknown
	}
}

// normalizeString creates a consistent string representation
func normalizeString(s string) string {
	// Remove extra whitespace
	s = strings.Join(strings.Fields(s), "_")

	// Remove special characters
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", r) {
			return r
		}
		return '_'
	}, s)

	return s
}

// isRedirection checks if a token is a redirection
func isRedirection(token string) bool {
	return redirectionPattern.MatchString(token) ||
		strings.HasPrefix(token, ">") ||
		strings.HasPrefix(token, "<") ||
		strings.HasPrefix(token, "2>") ||
		strings.HasPrefix(token, "&>")
}

// normalizeFlagName extracts and formats a flag name
func normalizeFlagName(token string) string {
	var flagName string

	// Handle environment variables
	if envVarPattern.MatchString(token) {
		parts := strings.SplitN(token, "=", 2)
		return strings.ToUpper(parts[0])
	}

	// Handle flags with equals
	if strings.Contains(token, "=") && (strings.HasPrefix(token, "--") || strings.HasPrefix(token, "-")) {
		parts := strings.SplitN(token, "=", 2)
		if strings.HasPrefix(parts[0], "--") {
			flagName = strings.ToUpper(parts[0][2:])
		} else {
			flagName = strings.ToUpper(parts[0][1:])
		}
		return strings.ReplaceAll(flagName, "-", "_")
	}

	if strings.HasPrefix(token, "--") {
		flagName = strings.ToUpper(token[2:])
	} else if strings.HasPrefix(token, "-") {
		flagName = strings.ToUpper(token[1:])
	} else if strings.HasPrefix(token, "+") {
		flagName = strings.ToUpper(token)
	}

	return strings.ReplaceAll(flagName, "-", "_")
}

// normalizeCommandLine creates a generalized representation of a command line
func normalizeCommandLine(cmdLine string) string {
	// Tokenize the command line
	tokens := tokenizeCommandLine(cmdLine)
	if len(tokens) == 0 {
		return ""
	}

	normalizedTokens := []string{}
	isPrevTokenFlag := false

	// Check if command starts with env vars
	startsWithEnvVar := false
	if len(tokens) > 0 && envVarPattern.MatchString(tokens[0]) {
		startsWithEnvVar = true
	}

	// Find the first non-env var token
	commandIndex := -1
	for i := range tokens {
		if !envVarPattern.MatchString(tokens[i]) {
			commandIndex = i
			break
		}
	}

	// Process each token
	for i, token := range tokens {
		// Skip the command name ONLY if it's the first token and not preceded by env vars
		if i == commandIndex && !startsWithEnvVar {
			continue
		}

		// Check if it's an environment variable
		if envVarPattern.MatchString(token) {
			parts := strings.SplitN(token, "=", 2)
			flagName := strings.ToUpper(parts[0])
			valueType := determineValueType(parts[1])
			normalizedTokens = append(normalizedTokens, "FLAG_"+flagName+"="+valueType)
			isPrevTokenFlag = false
			continue
		}

		// Check if it's the special double dash separator
		if token == "--" {
			normalizedTokens = append(normalizedTokens, "FLAG_-")
			isPrevTokenFlag = false
			continue
		}

		// Check if current token is a logical operator
		if logicalOperatorPattern.MatchString(token) {
			if token == "&&" {
				normalizedTokens = append(normalizedTokens, "AND")
			} else if token == "||" {
				normalizedTokens = append(normalizedTokens, "OR")
			}
			isPrevTokenFlag = false
			continue
		}

		// Check if current token is a redirection or pipe
		if isRedirection(token) {
			normalizedTokens = append(normalizedTokens, "REDIRECT")
			isPrevTokenFlag = false
			continue
		}

		if token == "|" {
			normalizedTokens = append(normalizedTokens, "PIPE")
			isPrevTokenFlag = false
			continue
		}

		// Check if it's a flag with value (--flag=value)
		if strings.Contains(token, "=") && (strings.HasPrefix(token, "--") || strings.HasPrefix(token, "-")) {
			parts := strings.SplitN(token, "=", 2)
			var flagName string
			if strings.HasPrefix(parts[0], "--") {
				flagName = strings.ToUpper(parts[0][2:])
			} else {
				flagName = strings.ToUpper(parts[0][1:])
			}
			flagName = strings.ReplaceAll(flagName, "-", "_")
			valueType := determineValueType(parts[1])
			normalizedTokens = append(normalizedTokens, "FLAG_"+flagName+"="+valueType)
			isPrevTokenFlag = false
			continue
		}

		// Check if it's a regular flag
		if longFlagPattern.MatchString(token) || shortFlagPattern.MatchString(token) ||
			plusFlagPattern.MatchString(token) {
			flagName := normalizeFlagName(token)
			normalizedTokens = append(normalizedTokens, "FLAG_"+flagName)
			isPrevTokenFlag = true
			continue
		}

		// If previous token was a flag, this is its value
		if isPrevTokenFlag {
			valueType := determineValueType(token)
			// Append to the previous flag
			lastIdx := len(normalizedTokens) - 1
			normalizedTokens[lastIdx] = normalizedTokens[lastIdx] + "=" + valueType
			isPrevTokenFlag = false
		} else {
			// Just a regular value
			valueType := determineValueType(token)
			normalizedTokens = append(normalizedTokens, valueType)
		}
	}

	return strings.Join(normalizedTokens, " ")
}

// determineValueType analyzes a token to determine its value type
func determineValueType(token string) string {
	// 1. Check for empty or special tokens
	if token == "" {
		return "VALUE"
	}
	if token == "." {
		return "FILEPATH"
	}

	// 2. Check standard file path patterns - using prefixes first (faster than regex)

	// Absolute paths - check prefix first before regex
	if strings.HasPrefix(token, "/") {
		// Now check specific system directories
		if tempPathPattern.MatchString(token) {
			return "FILEPATH_TEMP"
		}
		if homePathPattern.MatchString(token) {
			return "FILEPATH_HOME"
		}
		if systemPathPattern.MatchString(token) {
			return "FILEPATH_SYS"
		}
		if procPathPattern.MatchString(token) {
			return "FILEPATH_PROC"
		}
		if etcPathPattern.MatchString(token) {
			return "FILEPATH_ETC"
		}
		if varPathPattern.MatchString(token) {
			return "FILEPATH_VAR"
		}
		if devPathPattern.MatchString(token) {
			return "FILEPATH_DEV"
		}
		if optPathPattern.MatchString(token) {
			return "FILEPATH_OPT"
		}
		// Generic absolute path
		return "FILEPATH"
	}

	// 3. Home directory shortcuts
	if token == "~" || strings.HasPrefix(token, "~/") || strings.HasPrefix(token, "~") {
		return "FILEPATH"
	}

	// 4. Relative paths
	if strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") {
		return "FILEPATH"
	}

	// 5. Environment variable paths
	if strings.HasPrefix(token, "$HOME") || strings.HasPrefix(token, "${HOME}") ||
		strings.HasPrefix(token, "$PWD") {
		return "FILEPATH"
	}
	if strings.HasPrefix(token, "$PATH") || strings.HasPrefix(token, "${PATH}") {
		return "FILEPATH_SYS"
	}

	// 6. Docker volume mounts and command substitutions
	if strings.HasPrefix(token, "$(") && strings.Contains(token, ":") {
		return "FILEPATH"
	}
	if strings.Contains(token, ":") &&
		!strings.Contains(token, "://") &&
		(strings.HasPrefix(token, "/") || strings.HasPrefix(token, "~") || strings.HasPrefix(token, ".")) {
		return "FILEPATH"
	}

	// 7. Check for special data types (using regex)
	if urlPattern.MatchString(token) {
		return "URL"
	}
	if ipPattern.MatchString(token) {
		return "IP"
	}
	if numberPattern.MatchString(token) {
		return "NUM"
	}
	if emailPattern.MatchString(token) {
		return "EMAIL"
	}
	if hashPattern.MatchString(token) {
		return "HASH"
	}
	if hexPattern.MatchString(token) {
		return "HEX"
	}
	if uuidPattern.MatchString(token) {
		return "UUID"
	}
	if datePattern.MatchString(token) {
		return "DATE"
	}

	// 8. Check for file extensions
	if strings.Contains(token, ".") {
		ext := token[strings.LastIndex(token, ".")+1:]
		fileExts := []string{"txt", "log", "sh", "py", "rb", "js", "conf", "cfg", "bak"}
		for _, fileExt := range fileExts {
			if ext == fileExt {
				return "FILEPATH"
			}
		}
	}

	// 9. Special patterns
	if strings.Contains(token, "*") {
		return "VALUE"
	}

	// Default case
	return "VALUE"
}

// normalizePath processes paths consistently with categorizeValue
func normalizePath(path string) string {
	return determineValueType(path)
}
