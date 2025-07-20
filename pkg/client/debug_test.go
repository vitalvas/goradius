package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger(nil, LogLevelInfo)
	assert.NotNil(t, logger)
}

func TestLogger_LogPacket(t *testing.T) {
	logger := NewLogger(nil, LogLevelTrace)

	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewStringAttribute(packet.AttrUserName, "testuser"))

	// Should not panic
	assert.NotPanics(t, func() {
		logger.LogPacket("outgoing", pkt, "192.168.1.1:1812")
	})
}

func TestLogger_LogError(t *testing.T) {
	logger := NewLogger(nil, LogLevelTrace)

	err := assert.AnError
	context := map[string]interface{}{
		"operation": "test",
		"server":    "192.168.1.1:1812",
	}

	// Should not panic
	assert.NotPanics(t, func() {
		logger.LogError("authentication", err, context)
	})
}

func TestLogger_LogMetrics(t *testing.T) {
	logger := NewLogger(nil, LogLevelTrace)

	metrics := map[string]interface{}{
		"requests":  100,
		"responses": 95,
		"errors":    5,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		logger.LogMetrics("authentication", metrics)
	})
}

func TestNewDebugContext(t *testing.T) {
	clientLogger := NewLogger(nil, LogLevelTrace)

	debugCtx := NewDebugContext("req123", "testuser", "authentication", "192.168.1.1:1812", clientLogger)

	assert.Equal(t, "req123", debugCtx.RequestID)
	assert.Equal(t, "testuser", debugCtx.Username)
	assert.Equal(t, "authentication", debugCtx.Operation)
	assert.Equal(t, "192.168.1.1:1812", debugCtx.Server)
	assert.Equal(t, clientLogger, debugCtx.Logger)
	assert.NotZero(t, debugCtx.StartTime)
}

func TestDebugContext_LogPacket(t *testing.T) {
	clientLogger := NewLogger(nil, LogLevelTrace)
	debugCtx := NewDebugContext("req123", "testuser", "authentication", "192.168.1.1:1812", clientLogger)

	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewStringAttribute(packet.AttrUserName, "testuser"))

	// Should not panic
	assert.NotPanics(t, func() {
		debugCtx.LogPacket("outgoing", pkt)
	})
}

func TestDebugContext_LogError(t *testing.T) {
	clientLogger := NewLogger(nil, LogLevelTrace)
	debugCtx := NewDebugContext("req123", "testuser", "authentication", "192.168.1.1:1812", clientLogger)

	err := assert.AnError
	context := map[string]interface{}{
		"operation": "test",
	}

	// Should not panic
	assert.NotPanics(t, func() {
		debugCtx.LogError(err, context)
	})
}

func TestDebugContext_SetAttribute(t *testing.T) {
	clientLogger := NewLogger(nil, LogLevelTrace)
	debugCtx := NewDebugContext("req123", "testuser", "authentication", "192.168.1.1:1812", clientLogger)

	// Should not panic (it's a no-op now)
	assert.NotPanics(t, func() {
		debugCtx.SetAttribute("key", "value")
	})
}

func TestDebugContext_Finish(t *testing.T) {
	clientLogger := NewLogger(nil, LogLevelTrace)
	debugCtx := NewDebugContext("req123", "testuser", "authentication", "192.168.1.1:1812", clientLogger)

	// Should not panic (it's a no-op now)
	assert.NotPanics(t, func() {
		debugCtx.Finish(true, nil)
	})
}

func TestWithContext_FromContext(t *testing.T) {
	clientLogger := NewLogger(nil, LogLevelTrace)
	debugCtx := NewDebugContext("req123", "testuser", "authentication", "192.168.1.1:1812", clientLogger)

	ctx := WithContext(context.Background(), debugCtx)
	retrieved := FromContext(ctx)

	assert.Equal(t, debugCtx, retrieved)
}

func TestFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	retrieved := FromContext(ctx)

	assert.Nil(t, retrieved)
}
