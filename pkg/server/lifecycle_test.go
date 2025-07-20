package server

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
)

func TestState_String(t *testing.T) {
	testCases := []struct {
		state    State
		expected string
	}{
		{StateStopped, "stopped"},
		{StateStarting, "starting"},
		{StateRunning, "running"},
		{StateStopping, "stopping"},
		{StateError, "error"},
		{State(999), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.state.String())
		})
	}
}

func TestNewLifecycleManager(t *testing.T) {
	config := &Config{
		Bindings: []Binding{
			{
				Address:   "127.0.0.1",
				Port:      0,
				IPVersion: 4,
				Transport: TransportUDP,
			},
		},
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxRequestSize: 4096,
		Workers:        2,
		Logger:         log.NewDefaultLogger(),
	}

	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	assert.NotNil(t, lm)
	assert.Equal(t, server, lm.server)
	assert.Equal(t, StateStopped, lm.GetState())
	assert.Equal(t, 30*time.Second, lm.shutdownTimeout)
	assert.NotNil(t, lm.signalChan)
}

func TestLifecycleManager_StateManagement(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Test initial state
	assert.Equal(t, StateStopped, lm.GetState())
	assert.True(t, lm.IsStopped())
	assert.False(t, lm.IsRunning())
	assert.False(t, lm.IsShuttingDown())

	// Test state change callback
	var stateChanges []StateChange
	lm.SetStateChangeCallback(func(oldState, newState State) {
		stateChanges = append(stateChanges, StateChange{oldState, newState})
	})

	// Start server
	err = lm.Start()
	require.NoError(t, err)

	assert.Equal(t, StateRunning, lm.GetState())
	assert.False(t, lm.IsStopped())
	assert.True(t, lm.IsRunning())
	assert.False(t, lm.IsShuttingDown())

	// Stop server
	err = lm.Stop()
	require.NoError(t, err)

	assert.Equal(t, StateStopped, lm.GetState())
	assert.True(t, lm.IsStopped())
	assert.False(t, lm.IsRunning())
	assert.False(t, lm.IsShuttingDown())

	// Verify state changes
	require.Len(t, stateChanges, 4) // stopped->starting->running->stopping->stopped
	assert.Equal(t, StateStopped, stateChanges[0].Old)
	assert.Equal(t, StateStarting, stateChanges[0].New)
	assert.Equal(t, StateStarting, stateChanges[1].Old)
	assert.Equal(t, StateRunning, stateChanges[1].New)
	assert.Equal(t, StateRunning, stateChanges[2].Old)
	assert.Equal(t, StateStopping, stateChanges[2].New)
	assert.Equal(t, StateStopping, stateChanges[3].Old)
	assert.Equal(t, StateStopped, stateChanges[3].New)
}

func TestLifecycleManager_StartErrors(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Start successfully first
	err = lm.Start()
	require.NoError(t, err)

	// Try to start again (should fail)
	err = lm.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server is not in stopped state")

	// Stop and try starting with invalid config
	err = lm.Stop()
	require.NoError(t, err)
}

func TestLifecycleManager_StopStates(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Try to stop when already stopped
	err = lm.Stop()
	assert.NoError(t, err) // Should not error, just log

	// Start and stop normally
	err = lm.Start()
	require.NoError(t, err)

	err = lm.Stop()
	require.NoError(t, err)

	// Try to stop again
	err = lm.Stop()
	assert.NoError(t, err) // Should not error
}

func TestLifecycleManager_ShutdownTimeout(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Test custom shutdown timeout
	customTimeout := 5 * time.Second
	lm.SetShutdownTimeout(customTimeout)
	assert.Equal(t, customTimeout, lm.shutdownTimeout)

	// Start and stop with custom timeout
	err = lm.Start()
	require.NoError(t, err)

	start := time.Now()
	err = lm.StopWithTimeout(2 * time.Second)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.Less(t, duration, 3*time.Second) // Should complete within 3 seconds
}

func TestLifecycleManager_ShutdownCallback(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	shutdownCalled := false
	lm.SetShutdownCallback(func() {
		shutdownCalled = true
	})

	err = lm.Start()
	require.NoError(t, err)

	err = lm.Stop()
	require.NoError(t, err)

	assert.True(t, shutdownCalled)
}

func TestLifecycleManager_HealthCheck(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Health check when stopped
	err = lm.HealthCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server is stopped")

	// Health check when running
	err = lm.Start()
	require.NoError(t, err)

	err = lm.HealthCheck()
	assert.NoError(t, err)

	// Cleanup
	err = lm.Stop()
	require.NoError(t, err)
}

func TestLifecycleManager_GetUptime(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Uptime when stopped should be 0
	assert.Equal(t, time.Duration(0), lm.GetUptime())

	// Start and check uptime
	err = lm.Start()
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	uptime := lm.GetUptime()
	assert.Greater(t, uptime, 5*time.Millisecond)
	assert.Less(t, uptime, 50*time.Millisecond)

	// Cleanup
	err = lm.Stop()
	require.NoError(t, err)

	// Uptime after stop should be 0 again
	assert.Equal(t, time.Duration(0), lm.GetUptime())
}

func TestLifecycleManager_GetServerInfo(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Get info when stopped
	info := lm.GetServerInfo()
	assert.Equal(t, "stopped", info["state"])
	assert.Equal(t, "0s", info["uptime"])
	assert.Equal(t, 0, info["listeners"])

	// Start and get info
	err = lm.Start()
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	info = lm.GetServerInfo()
	assert.Equal(t, "running", info["state"])
	assert.NotEqual(t, "0s", info["uptime"])
	assert.Greater(t, info["listeners"], 0)
	assert.NotNil(t, info["start_time"])

	// Cleanup
	err = lm.Stop()
	require.NoError(t, err)
}

func TestLifecycleManager_SignalHandling(t *testing.T) {
	// Skip this test in CI environments or when running as non-interactive
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping signal test in CI environment")
	}

	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Start with signal handling
	err = lm.StartWithSignalHandling()
	require.NoError(t, err)

	// Send SIGTERM to ourselves (simulate external signal)
	time.Sleep(10 * time.Millisecond) // Give time for signal handler to start

	// We can't easily test the actual signal handling in unit tests
	// because it involves process signals, but we can test the setup
	assert.True(t, lm.IsRunning())

	// Manual stop for cleanup
	err = lm.Stop()
	require.NoError(t, err)
}

func TestLifecycleManager_CompareAndSwap(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Test successful compare and swap
	success := lm.compareAndSwapState(StateStopped, StateStarting)
	assert.True(t, success)
	assert.Equal(t, StateStarting, lm.GetState())

	// Test failed compare and swap
	success = lm.compareAndSwapState(StateStopped, StateRunning)
	assert.False(t, success)
	assert.Equal(t, StateStarting, lm.GetState()) // Should remain unchanged
}

func TestLifecycleManager_Concurrency(t *testing.T) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	lm := NewLifecycleManager(server)

	// Test concurrent state reads
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			state := lm.GetState()
			assert.NotNil(t, state)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Helper types and functions for testing

type StateChange struct {
	Old, New State
}

func createTestConfig() *Config {
	return &Config{
		Bindings: []Binding{
			{
				Address:   "127.0.0.1",
				Port:      0, // Let system choose
				IPVersion: 4,
				Transport: TransportUDP,
				Clients: []ClientConfig{
					{
						Networks: []string{"127.0.0.1"},
						Secret:   "testing123",
					},
				},
			},
		},
		ReadTimeout:    100 * time.Millisecond,
		WriteTimeout:   100 * time.Millisecond,
		MaxRequestSize: 4096,
		Workers:        2,
		Logger:         log.NewDefaultLogger(),
	}
}

// Benchmark lifecycle operations
func BenchmarkLifecycleStateGet(b *testing.B) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	if err != nil {
		b.Fatal(err)
	}

	lm := NewLifecycleManager(server)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lm.GetState()
	}
}

func BenchmarkLifecycleHealthCheck(b *testing.B) {
	config := createTestConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	if err != nil {
		b.Fatal(err)
	}

	lm := NewLifecycleManager(server)
	err = lm.Start()
	if err != nil {
		b.Fatal(err)
	}
	defer lm.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := lm.HealthCheck()
		if err != nil {
			b.Fatal(err)
		}
	}
}
