package log

import (
	"github.com/sirupsen/logrus"
)

// Logger defines the logging interface used throughout the RADIUS library.
type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

// DefaultLogger provides a default logger implementation using logrus.
type DefaultLogger struct {
	logger *logrus.Logger
}

// NewDefaultLogger creates a new default logger with standard configuration.
func NewDefaultLogger() *DefaultLogger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: false,
	})
	logger.SetLevel(logrus.InfoLevel)

	return &DefaultLogger{
		logger: logger,
	}
}

// NewLoggerWithLevel creates a new logger with specified log level.
func NewLoggerWithLevel(level string) *DefaultLogger {
	logger := NewDefaultLogger()

	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		lvl = logrus.InfoLevel
	}
	logger.logger.SetLevel(lvl)

	return logger
}

// Debug logs a message at debug level.
func (l *DefaultLogger) Debug(args ...interface{}) {
	l.logger.Debug(args...)
}

// Debugf logs a formatted message at debug level.
func (l *DefaultLogger) Debugf(format string, args ...interface{}) {
	l.logger.Debugf(format, args...)
}

// Info logs a message at info level.
func (l *DefaultLogger) Info(args ...interface{}) {
	l.logger.Info(args...)
}

// Infof logs a formatted message at info level.
func (l *DefaultLogger) Infof(format string, args ...interface{}) {
	l.logger.Infof(format, args...)
}

// Warn logs a message at warning level.
func (l *DefaultLogger) Warn(args ...interface{}) {
	l.logger.Warn(args...)
}

// Warnf logs a formatted message at warning level.
func (l *DefaultLogger) Warnf(format string, args ...interface{}) {
	l.logger.Warnf(format, args...)
}

// Error logs a message at error level.
func (l *DefaultLogger) Error(args ...interface{}) {
	l.logger.Error(args...)
}

// Errorf logs a formatted message at error level.
func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	l.logger.Errorf(format, args...)
}

// Fatal logs a message at fatal level and exits.
func (l *DefaultLogger) Fatal(args ...interface{}) {
	l.logger.Fatal(args...)
}

// Fatalf logs a formatted message at fatal level and exits.
func (l *DefaultLogger) Fatalf(format string, args ...interface{}) {
	l.logger.Fatalf(format, args...)
}

// SetLevel sets the log level for the logger.
func (l *DefaultLogger) SetLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return
	}
	l.logger.SetLevel(lvl)
}

// GetLogrus returns the underlying logrus logger for advanced configuration.
func (l *DefaultLogger) GetLogrus() *logrus.Logger {
	return l.logger
}
