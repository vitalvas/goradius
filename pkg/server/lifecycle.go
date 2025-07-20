package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
)

// State represents the current state of the server
type State int32

const (
	// StateStopped indicates the server is stopped
	StateStopped State = iota
	// StateStarting indicates the server is starting up
	StateStarting
	// StateRunning indicates the server is running normally
	StateRunning
	// StateStopping indicates the server is shutting down
	StateStopping
	// StateError indicates the server encountered an error
	StateError
)

// String returns a string representation of the server state
func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// LifecycleManager manages server lifecycle events
type LifecycleManager struct {
	server *Server
	state  int32 // atomic access to State
	logger log.Logger

	// Shutdown configuration
	shutdownTimeout time.Duration
	signalChan      chan os.Signal

	// Callbacks
	onStateChange func(oldState, newState State)
	onShutdown    func()
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(server *Server) *LifecycleManager {
	return &LifecycleManager{
		server:          server,
		state:           int32(StateStopped),
		logger:          server.logger,
		shutdownTimeout: 30 * time.Second,
		signalChan:      make(chan os.Signal, 1),
	}
}

// GetState returns the current server state
func (lm *LifecycleManager) GetState() State {
	return State(atomic.LoadInt32(&lm.state))
}

// setState atomically sets the server state and calls the callback
func (lm *LifecycleManager) setState(newState State) {
	oldState := State(atomic.SwapInt32(&lm.state, int32(newState)))

	if oldState != newState {
		lm.logger.Infof("Server state changed: %s -> %s", oldState, newState)

		if lm.onStateChange != nil {
			lm.onStateChange(oldState, newState)
		}
	}
}

// SetShutdownTimeout sets the timeout for graceful shutdown
func (lm *LifecycleManager) SetShutdownTimeout(timeout time.Duration) {
	lm.shutdownTimeout = timeout
}

// SetStateChangeCallback sets a callback for state changes
func (lm *LifecycleManager) SetStateChangeCallback(callback func(oldState, newState State)) {
	lm.onStateChange = callback
}

// SetShutdownCallback sets a callback for shutdown events
func (lm *LifecycleManager) SetShutdownCallback(callback func()) {
	lm.onShutdown = callback
}

// Start starts the server with lifecycle management
func (lm *LifecycleManager) Start() error {
	if !lm.compareAndSwapState(StateStopped, StateStarting) {
		return fmt.Errorf("server is not in stopped state (current: %s)", lm.GetState())
	}

	lm.logger.Info("Starting server lifecycle manager")

	// Start the actual server
	if err := lm.server.Start(); err != nil {
		lm.setState(StateError)
		return fmt.Errorf("failed to start server: %w", err)
	}

	lm.setState(StateRunning)
	return nil
}

// StartWithSignalHandling starts the server and sets up signal handling for graceful shutdown
func (lm *LifecycleManager) StartWithSignalHandling() error {
	// Setup signal handling for graceful shutdown
	signal.Notify(lm.signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the server
	if err := lm.Start(); err != nil {
		return err
	}

	// Handle signals in a separate goroutine
	go lm.handleSignals()

	lm.logger.Info("Server started with signal handling (SIGINT, SIGTERM)")
	return nil
}

// Stop stops the server gracefully
func (lm *LifecycleManager) Stop() error {
	return lm.StopWithTimeout(lm.shutdownTimeout)
}

// StopWithTimeout stops the server gracefully with a specified timeout
func (lm *LifecycleManager) StopWithTimeout(timeout time.Duration) error {
	currentState := lm.GetState()
	if currentState == StateStopped || currentState == StateStopping {
		lm.logger.Infof("Server already stopping or stopped (state: %s)", currentState)
		return nil
	}

	if !lm.compareAndSwapState(StateRunning, StateStopping) &&
		!lm.compareAndSwapState(StateError, StateStopping) {
		return fmt.Errorf("cannot stop server in current state: %s", currentState)
	}

	lm.logger.Infof("Stopping server with timeout %v", timeout)

	// Call shutdown callback if set
	if lm.onShutdown != nil {
		lm.onShutdown()
	}

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Channel to signal completion
	done := make(chan error, 1)

	// Stop the server in a goroutine
	go func() {
		done <- lm.server.Stop()
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		if err != nil {
			lm.setState(StateError)
			return fmt.Errorf("error during server shutdown: %w", err)
		}
		lm.setState(StateStopped)
		lm.logger.Info("Server stopped successfully")
		return nil

	case <-ctx.Done():
		lm.setState(StateError)
		return fmt.Errorf("server shutdown timed out after %v", timeout)
	}
}

// WaitForShutdown waits for a shutdown signal
func (lm *LifecycleManager) WaitForShutdown() error {
	if lm.GetState() != StateRunning {
		return fmt.Errorf("server is not running")
	}

	// Wait for signal
	sig := <-lm.signalChan
	lm.logger.Infof("Received signal %v, initiating graceful shutdown", sig)

	return lm.Stop()
}

// Run starts the server and waits for shutdown signals
func (lm *LifecycleManager) Run() error {
	// Start server with signal handling
	if err := lm.StartWithSignalHandling(); err != nil {
		return err
	}

	// Wait for shutdown
	return lm.WaitForShutdown()
}

// IsRunning returns true if the server is running
func (lm *LifecycleManager) IsRunning() bool {
	return lm.GetState() == StateRunning
}

// IsStopped returns true if the server is stopped
func (lm *LifecycleManager) IsStopped() bool {
	return lm.GetState() == StateStopped
}

// IsShuttingDown returns true if the server is shutting down
func (lm *LifecycleManager) IsShuttingDown() bool {
	return lm.GetState() == StateStopping
}

// GetUptime returns how long the server has been running
func (lm *LifecycleManager) GetUptime() time.Duration {
	if lm.GetState() != StateRunning {
		return 0
	}
	return time.Since(lm.server.stats.StartTime)
}

// compareAndSwapState atomically compares and swaps the state
func (lm *LifecycleManager) compareAndSwapState(oldState, newState State) bool {
	success := atomic.CompareAndSwapInt32(&lm.state, int32(oldState), int32(newState))
	if success && oldState != newState {
		lm.logger.Infof("Server state changed: %s -> %s", oldState, newState)

		if lm.onStateChange != nil {
			lm.onStateChange(oldState, newState)
		}
	}
	return success
}

// handleSignals handles OS signals for graceful shutdown
func (lm *LifecycleManager) handleSignals() {
	for {
		select {
		case sig := <-lm.signalChan:
			lm.logger.Infof("Received signal %v", sig)

			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				lm.logger.Info("Initiating graceful shutdown due to signal")
				if err := lm.Stop(); err != nil {
					lm.logger.Errorf("Error during signal-triggered shutdown: %v", err)
				}
				return
			default:
				lm.logger.Warnf("Ignoring signal %v", sig)
			}

		case <-lm.server.ctx.Done():
			// Server context cancelled, exit signal handler
			return
		}
	}
}

// HealthCheck performs a basic health check on the server
func (lm *LifecycleManager) HealthCheck() error {
	state := lm.GetState()

	switch state {
	case StateRunning:
		// Check if listeners are still active
		lm.server.mu.RLock()
		listenerCount := len(lm.server.udpListeners) + len(lm.server.tcpListeners)
		lm.server.mu.RUnlock()

		if listenerCount == 0 {
			return fmt.Errorf("server running but no listeners active")
		}

		return nil

	case StateStopped:
		return fmt.Errorf("server is stopped")

	case StateStarting:
		return fmt.Errorf("server is still starting")

	case StateStopping:
		return fmt.Errorf("server is shutting down")

	case StateError:
		return fmt.Errorf("server is in error state")

	default:
		return fmt.Errorf("server is in unknown state: %s", state)
	}
}

// GetServerInfo returns information about the server
func (lm *LifecycleManager) GetServerInfo() map[string]interface{} {
	lm.server.mu.RLock()
	listenerCount := len(lm.server.udpListeners) + len(lm.server.tcpListeners)
	lm.server.mu.RUnlock()

	stats := lm.server.GetStatistics()

	info := map[string]interface{}{
		"state":       lm.GetState().String(),
		"uptime":      lm.GetUptime().String(),
		"listeners":   listenerCount,
		"requests":    stats.TotalRequests,
		"responses":   stats.TotalResponses,
		"errors":      stats.InvalidRequests + stats.DroppedRequests + stats.TimeoutRequests,
		"start_time":  stats.StartTime.Format(time.RFC3339),
		"max_latency": stats.MaxLatency.String(),
	}

	return info
}
