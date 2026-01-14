// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the logging verbosity level
type LogLevel int

const (
	LogLevelSilent LogLevel = iota // No logging
	LogLevelError                  // Only errors
	LogLevelWarn                   // Warnings and errors
	LogLevelInfo                   // Info, warnings, and errors
	LogLevelDebug                  // All logs including debug
)

// Logger provides production-ready logging with level controls
type Logger struct {
	level      LogLevel
	mutex      sync.RWMutex
	component  string
	timeFormat string
}

// Global logger instance
var globalLogger *Logger
var loggerOnce sync.Once

// InitLogger initializes the global logger with environment-based configuration
func InitLogger() *Logger {
	loggerOnce.Do(func() {
		level := LogLevelInfo // Default to Info level

		// Check environment variables for log level
		if envLevel := os.Getenv("GOVERNANCE_PROOF_LOG_LEVEL"); envLevel != "" {
			switch strings.ToUpper(envLevel) {
			case "SILENT":
				level = LogLevelSilent
			case "ERROR":
				level = LogLevelError
			case "WARN", "WARNING":
				level = LogLevelWarn
			case "INFO":
				level = LogLevelInfo
			case "DEBUG":
				level = LogLevelDebug
			}
		}

		// For production environments, default to WARN
		if env := os.Getenv("ENVIRONMENT"); env == "production" || env == "prod" {
			if level > LogLevelWarn {
				level = LogLevelWarn
			}
		}

		globalLogger = &Logger{
			level:      level,
			component:  "GOVPROOF",
			timeFormat: "2006-01-02T15:04:05.000Z",
		}
	})
	return globalLogger
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		return InitLogger()
	}
	return globalLogger
}

// SetLogLevel sets the current log level (thread-safe)
func (l *Logger) SetLogLevel(level LogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.level = level
}

// GetLogLevel returns the current log level (thread-safe)
func (l *Logger) GetLogLevel() LogLevel {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.level
}

// IsDebugEnabled returns true if debug logging is enabled
func (l *Logger) IsDebugEnabled() bool {
	return l.GetLogLevel() >= LogLevelDebug
}

// IsInfoEnabled returns true if info logging is enabled
func (l *Logger) IsInfoEnabled() bool {
	return l.GetLogLevel() >= LogLevelInfo
}

// logf formats and prints a log message with level check
func (l *Logger) logf(level LogLevel, levelName, component, format string, args ...interface{}) {
	if l.GetLogLevel() < level {
		return // Skip logging if level is too low
	}

	timestamp := time.Now().UTC().Format(l.timeFormat)
	message := fmt.Sprintf(format, args...)

	fmt.Printf("[%s] [%s] [%s] %s\n", timestamp, levelName, component, message)
}

// Debug logs debug-level messages (only if debug is enabled)
func (l *Logger) Debug(component, format string, args ...interface{}) {
	l.logf(LogLevelDebug, "DEBUG", component, format, args...)
}

// Info logs info-level messages
func (l *Logger) Info(component, format string, args ...interface{}) {
	l.logf(LogLevelInfo, "INFO", component, format, args...)
}

// Warn logs warning-level messages
func (l *Logger) Warn(component, format string, args ...interface{}) {
	l.logf(LogLevelWarn, "WARN", component, format, args...)
}

// Error logs error-level messages
func (l *Logger) Error(component, format string, args ...interface{}) {
	l.logf(LogLevelError, "ERROR", component, format, args...)
}

// Convenience functions for global logger
func LogDebug(component, format string, args ...interface{}) {
	GetLogger().Debug(component, format, args...)
}

func LogInfo(component, format string, args ...interface{}) {
	GetLogger().Info(component, format, args...)
}

func LogWarn(component, format string, args ...interface{}) {
	GetLogger().Warn(component, format, args...)
}

func LogError(component, format string, args ...interface{}) {
	GetLogger().Error(component, format, args...)
}

// IsDebugEnabled returns true if debug logging is enabled globally
func IsDebugEnabled() bool {
	return GetLogger().IsDebugEnabled()
}

// IsInfoEnabled returns true if info logging is enabled globally
func IsInfoEnabled() bool {
	return GetLogger().IsInfoEnabled()
}