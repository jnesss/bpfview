package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarning
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

type Logger struct {
	formatter     EventFormatter
	consoleLevel  LogLevel
	showTimestamp bool
	lock          sync.Mutex
}

func NewLogger(logDir string, consoleLevel, fileLevel LogLevel, showTimestamp bool) (*Logger, error) {
	formatter, err := NewTextFormatter(logDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create formatter: %v", err)
	}

	if err := formatter.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize formatter: %v", err)
	}

	return &Logger{
		formatter:     formatter,
		consoleLevel:  consoleLevel,
		showTimestamp: showTimestamp,
	}, nil
}

func (l *Logger) Close() {
	if l.formatter != nil {
		l.formatter.Close()
	}
}

// Console logging methods
func (l *Logger) Error(component string, format string, args ...interface{}) {
	l.log(LogLevelError, component, format, args...)
}

func (l *Logger) Warning(component string, format string, args ...interface{}) {
	l.log(LogLevelWarning, component, format, args...)
}

func (l *Logger) Info(component string, format string, args ...interface{}) {
	l.log(LogLevelInfo, component, format, args...)
}

func (l *Logger) Debug(component string, format string, args ...interface{}) {
	l.log(LogLevelDebug, component, format, args...)
}

func (l *Logger) Trace(component string, format string, args ...interface{}) {
	l.log(LogLevelTrace, component, format, args...)
}

// Console output handler
func (l *Logger) log(level LogLevel, component string, format string, args ...interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if level <= l.consoleLevel {
		prefix := ""
		if l.showTimestamp {
			prefix = time.Now().Format("2006-01-02 15:04:05.000") + " "
		}

		// For INFO level, just show component
		if level == LogLevelInfo {
			// Convert component to uppercase for consistency with previous format
			fmt.Printf("%s[%s] %s\n", prefix, strings.ToUpper(component), fmt.Sprintf(format, args...))
		} else {
			// For other levels (ERROR, WARNING), show both
			levelStr := [...]string{"ERROR", "WARNING", "INFO", "DEBUG", "TRACE"}[level]
			fmt.Printf("%s[%s][%s] %s\n", prefix, levelStr, component, fmt.Sprintf(format, args...))
		}
	}
}

// Event logging methods that use the formatter
func (l *Logger) LogProcess(event *ProcessEvent, info *ProcessInfo) error {
	return l.formatter.FormatProcess(event, info)
}

func (l *Logger) LogNetwork(event *NetworkEvent, info *ProcessInfo) error {
	return l.formatter.FormatNetwork(event, info)
}

func (l *Logger) LogDNS(event *UserSpaceDNSEvent, info *ProcessInfo) error {
	return l.formatter.FormatDNS(event, info)
}

func (l *Logger) LogTLS(event *UserSpaceTLSEvent, info *ProcessInfo) error {
	return l.formatter.FormatTLS(event, info)
}
