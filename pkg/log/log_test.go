package log

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultLogger(t *testing.T) {
	logger := NewDefaultLogger()
	require.NotNil(t, logger)
	assert.NotNil(t, logger.logger)
}

func TestNewLoggerWithLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected string
	}{
		{"debug level", "debug", "debug"},
		{"info level", "info", "info"},
		{"warn level", "warn", "warning"},
		{"error level", "error", "error"},
		{"invalid level", "invalid", "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLoggerWithLevel(tt.level)
			require.NotNil(t, logger)
			assert.NotNil(t, logger.logger)
		})
	}
}

func TestDefaultLoggerInterface(t *testing.T) {
	logger := NewDefaultLogger()

	// Test that DefaultLogger implements Logger interface
	var _ Logger = logger

	// Test all logging methods don't panic
	assert.NotPanics(t, func() {
		logger.Debug("test debug")
		logger.Debugf("test debug %s", "formatted")
		logger.Info("test info")
		logger.Infof("test info %s", "formatted")
		logger.Warn("test warn")
		logger.Warnf("test warn %s", "formatted")
		logger.Error("test error")
		logger.Errorf("test error %s", "formatted")
	})
}

func TestSetLevel(t *testing.T) {
	logger := NewDefaultLogger()

	assert.NotPanics(t, func() {
		logger.SetLevel("debug")
		logger.SetLevel("info")
		logger.SetLevel("warn")
		logger.SetLevel("error")
		logger.SetLevel("invalid")
	})
}

func TestGetLogrus(t *testing.T) {
	logger := NewDefaultLogger()
	logrusLogger := logger.GetLogrus()

	assert.NotNil(t, logrusLogger)
	assert.Equal(t, logger.logger, logrusLogger)
}
