package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// LogLevel represents different logging levels for client operations
type LogLevel int

const (
	LogLevelTrace LogLevel = iota
	LogLevelDebug
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

// String returns the string representation of the log level
func (ll LogLevel) String() string {
	switch ll {
	case LogLevelTrace:
		return "TRACE"
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger provides enhanced logging capabilities for RADIUS client operations
type Logger struct {
	logger     log.Logger
	level      LogLevel
	logPackets bool
	logMetrics bool
	mu         sync.RWMutex
}

// NewLogger creates a new enhanced client logger
func NewLogger(logger log.Logger, level LogLevel) *Logger {
	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	return &Logger{
		logger:     logger,
		level:      level,
		logPackets: false,
		logMetrics: false,
	}
}

// SetLogLevel sets the logging level
func (cl *Logger) SetLogLevel(level LogLevel) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.level = level
}

// SetPacketLogging enables/disables packet logging
func (cl *Logger) SetPacketLogging(enabled bool) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.logPackets = enabled
}

// SetMetricsLogging enables/disables metrics logging
func (cl *Logger) SetMetricsLogging(enabled bool) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.logMetrics = enabled
}

// LogPacket logs a RADIUS packet with detailed information
func (cl *Logger) LogPacket(direction string, packet *packet.Packet, server string) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if !cl.logPackets || cl.level > LogLevelDebug {
		return
	}

	cl.logger.Debugf("RADIUS Packet [%s] Server: %s", direction, server)
	cl.logger.Debugf("  Code: %s (%d)", packet.Code.String(), packet.Code)
	cl.logger.Debugf("  Identifier: %d", packet.Identifier)
	cl.logger.Debugf("  Length: %d", packet.Length)
	cl.logger.Debugf("  Authenticator: %x", packet.Authenticator)

	if len(packet.Attributes) > 0 {
		cl.logger.Debugf("  Attributes (%d):", len(packet.Attributes))
		for i, attr := range packet.Attributes {
			cl.logger.Debugf("    [%d] Type: %d, Length: %d, Value: %x",
				i, attr.Type, len(attr.Value), attr.Value)
		}
	}
}

// LogAuthentication logs authentication attempts with detailed information
func (cl *Logger) LogAuthentication(username string, method string, success bool, duration time.Duration, server string) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelInfo {
		return
	}

	status := "FAILED"
	if success {
		status = "SUCCESS"
	}

	cl.logger.Infof("Authentication [%s] User: %s, Method: %s, Duration: %v, Server: %s",
		status, username, method, duration, server)
}

// LogAccounting logs accounting operations
func (cl *Logger) LogAccounting(sessionID string, operation string, success bool, duration time.Duration, server string) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelInfo {
		return
	}

	status := "FAILED"
	if success {
		status = "SUCCESS"
	}

	cl.logger.Infof("Accounting [%s] Session: %s, Operation: %s, Duration: %v, Server: %s",
		status, sessionID, operation, duration, server)
}

// LogError logs error messages
func (cl *Logger) LogError(operation string, err error, context map[string]interface{}) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelError {
		return
	}

	contextStr := ""
	if context != nil {
		contextStr = fmt.Sprintf(" Context: %+v", context)
	}

	cl.logger.Errorf("Operation [%s] Error: %v%s", operation, err, contextStr)
}

// LogMetrics logs performance metrics
func (cl *Logger) LogMetrics(operation string, metrics map[string]interface{}) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if !cl.logMetrics || cl.level > LogLevelInfo {
		return
	}

	cl.logger.Infof("Metrics [%s] %+v", operation, metrics)
}

// Trace logs trace-level messages
func (cl *Logger) Trace(message string, args ...interface{}) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelTrace {
		return
	}

	cl.logger.Debugf("[TRACE] "+message, args...)
}

// Debug logs debug-level messages
func (cl *Logger) Debug(message string, args ...interface{}) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelDebug {
		return
	}

	cl.logger.Debugf(message, args...)
}

// Info logs info-level messages
func (cl *Logger) Info(message string, args ...interface{}) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelInfo {
		return
	}

	cl.logger.Infof(message, args...)
}

// Warn logs warning-level messages
func (cl *Logger) Warn(message string, args ...interface{}) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelWarn {
		return
	}

	cl.logger.Warnf(message, args...)
}

// Error logs error-level messages
func (cl *Logger) Error(message string, args ...interface{}) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if cl.level > LogLevelError {
		return
	}

	cl.logger.Errorf(message, args...)
}

// DebugHelper provides debugging utilities for RADIUS client operations
type DebugHelper struct {
	logger         *Logger
	packetDumper   *PacketDumper
	metricsTracker *MetricsTracker
}

// NewDebugHelper creates a new debug helper
func NewDebugHelper(logger *Logger) *DebugHelper {
	return &DebugHelper{
		logger:         logger,
		packetDumper:   NewPacketDumper(logger),
		metricsTracker: NewMetricsTracker(logger),
	}
}

// DumpPacket dumps a packet for debugging
func (dh *DebugHelper) DumpPacket(packet *packet.Packet, direction string, server string) {
	dh.packetDumper.DumpPacket(packet, direction, server)
}

// TrackMetrics tracks operation metrics
func (dh *DebugHelper) TrackMetrics(operation string, duration time.Duration, success bool, server string) {
	dh.metricsTracker.Track(operation, duration, success, server)
}

// GetMetrics returns current metrics
func (dh *DebugHelper) GetMetrics() map[string]interface{} {
	return dh.metricsTracker.GetMetrics()
}

// ResetMetrics resets all metrics
func (dh *DebugHelper) ResetMetrics() {
	dh.metricsTracker.Reset()
}

// PacketDumper provides packet dumping capabilities
type PacketDumper struct {
	logger *Logger
}

// NewPacketDumper creates a new packet dumper
func NewPacketDumper(logger *Logger) *PacketDumper {
	return &PacketDumper{
		logger: logger,
	}
}

// DumpPacket dumps a packet with detailed information
func (pd *PacketDumper) DumpPacket(packet *packet.Packet, direction string, server string) {
	pd.logger.LogPacket(direction, packet, server)
}

// DumpPacketHex dumps a packet in hexadecimal format
func (pd *PacketDumper) DumpPacketHex(packet *packet.Packet, direction string, server string) {
	pd.logger.Debug("Packet Hex Dump [%s] Server: %s", direction, server)
	// Convert packet to raw data
	if rawData, err := packet.Encode(); err == nil {
		pd.logger.Debug("Raw Data: %x", rawData)
	} else {
		pd.logger.Debug("Failed to encode packet: %v", err)
	}
}

// DumpPacketBinary dumps a packet in binary format
func (pd *PacketDumper) DumpPacketBinary(packet *packet.Packet, direction string, server string) {
	pd.logger.Debug("Packet Binary Dump [%s] Server: %s", direction, server)

	// Convert packet to raw data for binary dump
	if rawData, err := packet.Encode(); err == nil {
		for i, b := range rawData {
			if i%16 == 0 {
				pd.logger.Debug("%04x: ", i)
			}
			pd.logger.Debug("%02x ", b)
			if i%16 == 15 {
				pd.logger.Debug("")
			}
		}
		pd.logger.Debug("")
	} else {
		pd.logger.Debug("Failed to encode packet for binary dump: %v", err)
	}
}

// MetricsTracker tracks and reports client metrics
type MetricsTracker struct {
	logger  *Logger
	metrics map[string]*OperationMetrics
	mu      sync.RWMutex
}

// OperationMetrics holds metrics for a specific operation
type OperationMetrics struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	TotalDuration      time.Duration
	MinDuration        time.Duration
	MaxDuration        time.Duration
	AverageDuration    time.Duration
	LastRequest        time.Time
}

// NewMetricsTracker creates a new metrics tracker
func NewMetricsTracker(logger *Logger) *MetricsTracker {
	return &MetricsTracker{
		logger:  logger,
		metrics: make(map[string]*OperationMetrics),
	}
}

// Track tracks an operation
func (mt *MetricsTracker) Track(operation string, duration time.Duration, success bool, server string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	key := fmt.Sprintf("%s_%s", operation, server)

	metric, exists := mt.metrics[key]
	if !exists {
		metric = &OperationMetrics{
			MinDuration: duration,
			MaxDuration: duration,
		}
		mt.metrics[key] = metric
	}

	metric.TotalRequests++
	metric.TotalDuration += duration
	metric.LastRequest = time.Now()

	if success {
		metric.SuccessfulRequests++
	} else {
		metric.FailedRequests++
	}

	if duration < metric.MinDuration {
		metric.MinDuration = duration
	}
	if duration > metric.MaxDuration {
		metric.MaxDuration = duration
	}

	metric.AverageDuration = time.Duration(int64(metric.TotalDuration) / metric.TotalRequests)

	// Log metrics periodically
	if mt.logger.logMetrics && metric.TotalRequests%100 == 0 {
		mt.logger.LogMetrics(operation, map[string]interface{}{
			"server":              server,
			"total_requests":      metric.TotalRequests,
			"successful_requests": metric.SuccessfulRequests,
			"failed_requests":     metric.FailedRequests,
			"success_rate":        float64(metric.SuccessfulRequests) / float64(metric.TotalRequests) * 100,
			"average_duration":    metric.AverageDuration,
			"min_duration":        metric.MinDuration,
			"max_duration":        metric.MaxDuration,
		})
	}
}

// GetMetrics returns current metrics
func (mt *MetricsTracker) GetMetrics() map[string]interface{} {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	result := make(map[string]interface{})

	for key, metric := range mt.metrics {
		result[key] = map[string]interface{}{
			"total_requests":      metric.TotalRequests,
			"successful_requests": metric.SuccessfulRequests,
			"failed_requests":     metric.FailedRequests,
			"success_rate":        float64(metric.SuccessfulRequests) / float64(metric.TotalRequests) * 100,
			"average_duration":    metric.AverageDuration,
			"min_duration":        metric.MinDuration,
			"max_duration":        metric.MaxDuration,
			"total_duration":      metric.TotalDuration,
			"last_request":        metric.LastRequest,
		}
	}

	return result
}

// Reset resets all metrics
func (mt *MetricsTracker) Reset() {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.metrics = make(map[string]*OperationMetrics)
	mt.logger.Info("Metrics reset")
}

// GetOperationMetrics returns metrics for a specific operation
func (mt *MetricsTracker) GetOperationMetrics(operation string, server string) *OperationMetrics {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	key := fmt.Sprintf("%s_%s", operation, server)
	metric, exists := mt.metrics[key]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modification
	return &OperationMetrics{
		TotalRequests:      metric.TotalRequests,
		SuccessfulRequests: metric.SuccessfulRequests,
		FailedRequests:     metric.FailedRequests,
		TotalDuration:      metric.TotalDuration,
		MinDuration:        metric.MinDuration,
		MaxDuration:        metric.MaxDuration,
		AverageDuration:    metric.AverageDuration,
		LastRequest:        metric.LastRequest,
	}
}

// DebugContext provides debugging context for operations
type DebugContext struct {
	RequestID string
	Username  string
	Operation string
	Server    string
	StartTime time.Time
	Logger    *Logger
}

// NewDebugContext creates a new debug context
func NewDebugContext(requestID, username, operation, server string, logger *Logger) *DebugContext {
	ctx := &DebugContext{
		RequestID: requestID,
		Username:  username,
		Operation: operation,
		Server:    server,
		StartTime: time.Now(),
		Logger:    logger,
	}

	return ctx
}

// LogPacket logs a packet with context
func (dc *DebugContext) LogPacket(direction string, packet *packet.Packet) {
	if dc.Logger != nil {
		dc.Logger.LogPacket(direction, packet, dc.Server)
	}
}

// LogError logs an error with context
func (dc *DebugContext) LogError(err error, context map[string]interface{}) {
	if dc.Logger != nil {
		if context == nil {
			context = make(map[string]interface{})
		}
		context["request_id"] = dc.RequestID
		context["username"] = dc.Username
		context["server"] = dc.Server
		dc.Logger.LogError(dc.Operation, err, context)
	}
}

// SetAttribute sets a trace attribute (deprecated - no-op)
func (dc *DebugContext) SetAttribute(key string, value interface{}) {
	// No-op: trace functionality removed
}

// Finish finishes the debug context (deprecated - no-op)
func (dc *DebugContext) Finish(success bool, err error) {
	// No-op: trace functionality removed
}

// debugContextKey is a custom type for context keys to avoid collisions
type debugContextKey struct{}

// WithContext creates a new context with debugging enabled
func WithContext(ctx context.Context, debugCtx *DebugContext) context.Context {
	return context.WithValue(ctx, debugContextKey{}, debugCtx)
}

// FromContext retrieves the debug context from a context
func FromContext(ctx context.Context) *DebugContext {
	if debugCtx, ok := ctx.Value(debugContextKey{}).(*DebugContext); ok {
		return debugCtx
	}
	return nil
}
