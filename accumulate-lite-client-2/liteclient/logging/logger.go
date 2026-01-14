// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package logging provides structured logging and observability for the Accumulate lite client.
// It supports multiple output formats, log levels, and integrates with tracing systems.
package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/errors"
)

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
	config *Config
}

// Config represents logging configuration
type Config struct {
	Level      slog.Level `json:"level"`
	Format     string     `json:"format"`     // "json" or "text"
	Output     string     `json:"output"`     // "stdout", "stderr", or file path
	Structured bool       `json:"structured"`
	AddSource  bool       `json:"add_source"`
	TimeFormat string     `json:"time_format"`
}

// Field represents a structured log field
type Field struct {
	Key   string
	Value interface{}
}

// NewLogger creates a new logger with the given configuration
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Determine output destination
	var output io.Writer
	switch config.Output {
	case "stdout", "":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// File output
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		output = file
	}

	// Create handler based on format
	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{
		Level:     config.Level,
		AddSource: config.AddSource,
	}

	if config.Format == "json" || config.Structured {
		handler = slog.NewJSONHandler(output, handlerOpts)
	} else {
		handler = slog.NewTextHandler(output, handlerOpts)
	}

	return &Logger{
		Logger: slog.New(handler),
		config: config,
	}, nil
}

// DefaultConfig returns a default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      slog.LevelInfo,
		Format:     "text",
		Output:     "stdout",
		Structured: false,
		AddSource:  false,
		TimeFormat: time.RFC3339,
	}
}

// WithContext returns a logger with context values added
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Extract common context values
	fields := extractContextFields(ctx)
	if len(fields) == 0 {
		return l
	}

	args := make([]any, len(fields)*2)
	for i, field := range fields {
		args[i*2] = field.Key
		args[i*2+1] = field.Value
	}

	return &Logger{
		Logger: l.Logger.With(args...),
		config: l.config,
	}
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields ...Field) *Logger {
	if len(fields) == 0 {
		return l
	}

	args := make([]any, len(fields)*2)
	for i, field := range fields {
		args[i*2] = field.Key
		args[i*2+1] = field.Value
	}

	return &Logger{
		Logger: l.Logger.With(args...),
		config: l.config,
	}
}

// WithError returns a logger with error information
func (l *Logger) WithError(err error) *Logger {
	if err == nil {
		return l
	}

	args := []any{"error", err.Error()}

	// Add structured error information if it's a LiteClientError
	if lce, ok := errors.AsLiteClientError(err); ok {
		args = append(args,
			"error_code", string(lce.Code),
			"error_timestamp", lce.Timestamp,
		)

		if lce.Details != "" {
			args = append(args, "error_details", lce.Details)
		}

		if len(lce.Context) > 0 {
			for k, v := range lce.Context {
				args = append(args, fmt.Sprintf("error_context_%s", k), v)
			}
		}
	}

	return &Logger{
		Logger: l.Logger.With(args...),
		config: l.config,
	}
}

// WithComponent returns a logger with component information
func (l *Logger) WithComponent(component string) *Logger {
	return l.WithFields(Field{Key: "component", Value: component})
}

// WithRequestID returns a logger with request ID
func (l *Logger) WithRequestID(requestID string) *Logger {
	return l.WithFields(Field{Key: "request_id", Value: requestID})
}

// WithOperation returns a logger with operation information
func (l *Logger) WithOperation(operation string) *Logger {
	return l.WithFields(Field{Key: "operation", Value: operation})
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...Field) {
	l.log(slog.LevelDebug, msg, fields...)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...Field) {
	l.log(slog.LevelInfo, msg, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...Field) {
	l.log(slog.LevelWarn, msg, fields...)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...Field) {
	l.log(slog.LevelError, msg, fields...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, fields ...Field) {
	l.log(slog.LevelError, msg, fields...)
	os.Exit(1)
}

// log is the internal logging method
func (l *Logger) log(level slog.Level, msg string, fields ...Field) {
	if !l.Logger.Enabled(context.Background(), level) {
		return
	}

	attrs := make([]slog.Attr, len(fields))
	for i, field := range fields {
		attrs[i] = slog.Any(field.Key, field.Value)
	}

	// Add caller information if enabled
	if l.config.AddSource {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			attrs = append(attrs, slog.Group("source",
				slog.String("file", file),
				slog.Int("line", line),
			))
		}
	}

	l.Logger.LogAttrs(context.Background(), level, msg, attrs...)
}

// LogRequest logs an HTTP request
func (l *Logger) LogRequest(method, path string, statusCode int, duration time.Duration, fields ...Field) {
	allFields := append([]Field{
		{Key: "method", Value: method},
		{Key: "path", Value: path},
		{Key: "status_code", Value: statusCode},
		{Key: "duration_ms", Value: duration.Milliseconds()},
		{Key: "type", Value: "http_request"},
	}, fields...)

	level := slog.LevelInfo
	if statusCode >= 400 {
		level = slog.LevelWarn
	}
	if statusCode >= 500 {
		level = slog.LevelError
	}

	l.log(level, "HTTP request", allFields...)
}

// LogProofOperation logs a proof-related operation
func (l *Logger) LogProofOperation(operation, accountURL string, success bool, duration time.Duration, fields ...Field) {
	allFields := append([]Field{
		{Key: "operation", Value: operation},
		{Key: "account_url", Value: accountURL},
		{Key: "success", Value: success},
		{Key: "duration_ms", Value: duration.Milliseconds()},
		{Key: "type", Value: "proof_operation"},
	}, fields...)

	level := slog.LevelInfo
	if !success {
		level = slog.LevelError
	}

	l.log(level, "Proof operation", allFields...)
}

// LogNetworkOperation logs a network operation
func (l *Logger) LogNetworkOperation(endpoint, operation string, success bool, duration time.Duration, fields ...Field) {
	allFields := append([]Field{
		{Key: "endpoint", Value: endpoint},
		{Key: "operation", Value: operation},
		{Key: "success", Value: success},
		{Key: "duration_ms", Value: duration.Milliseconds()},
		{Key: "type", Value: "network_operation"},
	}, fields...)

	level := slog.LevelInfo
	if !success {
		level = slog.LevelWarn
	}

	l.log(level, "Network operation", allFields...)
}

// LogMetric logs a metric value
func (l *Logger) LogMetric(name string, value interface{}, tags map[string]string) {
	fields := []Field{
		{Key: "metric_name", Value: name},
		{Key: "metric_value", Value: value},
		{Key: "type", Value: "metric"},
	}

	for k, v := range tags {
		fields = append(fields, Field{Key: fmt.Sprintf("tag_%s", k), Value: v})
	}

	l.log(slog.LevelInfo, "Metric", fields...)
}

// extractContextFields extracts logging fields from context
func extractContextFields(ctx context.Context) []Field {
	var fields []Field

	// Extract common context values
	if requestID := ctx.Value("request_id"); requestID != nil {
		if id, ok := requestID.(string); ok {
			fields = append(fields, Field{Key: "request_id", Value: id})
		}
	}

	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			fields = append(fields, Field{Key: "user_id", Value: id})
		}
	}

	if traceID := ctx.Value("trace_id"); traceID != nil {
		if id, ok := traceID.(string); ok {
			fields = append(fields, Field{Key: "trace_id", Value: id})
		}
	}

	return fields
}

// ParseLevel parses a log level string
func ParseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}

// SetGlobalLogger sets the global logger instance
var globalLogger *Logger

func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// Create a default logger if none is set
		logger, _ := NewLogger(DefaultConfig())
		globalLogger = logger
	}
	return globalLogger
}

// Global logging functions for convenience
func Debug(msg string, fields ...Field) {
	GetGlobalLogger().Debug(msg, fields...)
}

func Info(msg string, fields ...Field) {
	GetGlobalLogger().Info(msg, fields...)
}

func Warn(msg string, fields ...Field) {
	GetGlobalLogger().Warn(msg, fields...)
}

func Error(msg string, fields ...Field) {
	GetGlobalLogger().Error(msg, fields...)
}

func Fatal(msg string, fields ...Field) {
	GetGlobalLogger().Fatal(msg, fields...)
}

// Middleware for HTTP request logging
type RequestLogger struct {
	logger *Logger
}

func NewRequestLogger(logger *Logger) *RequestLogger {
	return &RequestLogger{logger: logger}
}

// MiddlewareFunc returns an HTTP middleware function
func (rl *RequestLogger) MiddlewareFunc() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Create a response writer wrapper to capture status code
			wrapper := &responseWriter{ResponseWriter: w, statusCode: 200}
			
			// Process request
			next.ServeHTTP(wrapper, r)
			
			// Log the request
			duration := time.Since(start)
			rl.logger.LogRequest(
				r.Method,
				r.URL.Path,
				wrapper.statusCode,
				duration,
				Field{Key: "remote_addr", Value: r.RemoteAddr},
				Field{Key: "user_agent", Value: r.UserAgent()},
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// JSON marshaling for Field
func (f Field) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"key":   f.Key,
		"value": f.Value,
	})
}