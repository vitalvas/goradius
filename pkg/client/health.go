package client

import (
	"context"
	"fmt"
	"time"

	"github.com/vitalvas/goradius/pkg/packet"
)

// HealthChecker specific implementation for the client package

// NewHealthChecker creates a new health checker
func NewHealthChecker(client *RADIUSClient, interval, timeout time.Duration) *HealthChecker {
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthChecker{
		client:   client,
		interval: interval,
		timeout:  timeout,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start starts the health checker
func (h *HealthChecker) Start() error {
	// Start health check routine
	h.wg.Add(1)
	go h.healthCheckRoutine()

	return nil
}

// Stop stops the health checker
func (h *HealthChecker) Stop() error {
	h.cancel()
	h.wg.Wait()

	return nil
}

// healthCheckRoutine performs periodic health checks
func (h *HealthChecker) healthCheckRoutine() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	// Perform initial health check
	h.performHealthChecks()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all servers
func (h *HealthChecker) performHealthChecks() {
	h.client.mu.RLock()
	servers := make([]ServerConfig, len(h.client.servers))
	copy(servers, h.client.servers)
	h.client.mu.RUnlock()

	for _, server := range servers {
		serverAddr := fmt.Sprintf("%s:%d", server.Address, server.Port)
		h.checkServerHealth(serverAddr, server)
	}
}

// checkServerHealth performs a health check on a single server
func (h *HealthChecker) checkServerHealth(serverAddr string, server ServerConfig) {
	// Create health check context with timeout
	ctx, cancel := context.WithTimeout(h.ctx, h.timeout)
	defer cancel()

	// Create a Status-Server request for health check
	req := packet.New(packet.CodeStatusServer, h.client.generateRequestID())

	// Get server state
	state, exists := h.client.serverStates[serverAddr]
	if !exists {
		return
	}

	// Update last health check time
	state.mu.Lock()
	state.lastCheck = time.Now()
	state.mu.Unlock()

	// Send health check request
	start := time.Now()
	response, err := h.sendHealthCheckRequest(ctx, req, serverAddr, server)

	// Update server state based on health check result
	state.mu.Lock()
	defer state.mu.Unlock()

	if err != nil {
		// Health check failed
		state.failureCount++

		if state.healthy {
			state.healthy = false
			h.client.logger.Warnf("Server %s marked as unhealthy: %v", serverAddr, err)
		}

		// Update server statistics
		if h.client.stats.ServerStatistics != nil {
			if serverStats, exists := h.client.stats.ServerStatistics[serverAddr]; exists {
				serverStats.Healthy = false
				serverStats.FailureCount++
				serverStats.LastHealthCheck = time.Now()
			}
		}
	} else {
		// Health check succeeded
		wasUnhealthy := !state.healthy
		state.healthy = true
		state.failureCount = 0

		if wasUnhealthy {
			h.client.logger.Infof("Server %s marked as healthy", serverAddr)
		}

		// Update server statistics
		if h.client.stats.ServerStatistics != nil {
			if serverStats, exists := h.client.stats.ServerStatistics[serverAddr]; exists {
				serverStats.Healthy = true
				serverStats.RecoveryCount++
				serverStats.LastHealthCheck = time.Now()

				// Update RTT if we got a response
				if response != nil {
					rtt := time.Since(start)
					if serverStats.AverageRTT == 0 {
						serverStats.AverageRTT = rtt
					} else {
						serverStats.AverageRTT = (serverStats.AverageRTT + rtt) / 2
					}
				}
			}
		}
	}
}

// sendHealthCheckRequest sends a health check request to a server
func (h *HealthChecker) sendHealthCheckRequest(ctx context.Context, req *packet.Packet, serverAddr string, _ ServerConfig) (*packet.Packet, error) {
	// Get the appropriate client for the transport
	switch h.client.config.Transport {
	case TransportUDP:
		if client, exists := h.client.udpClients[serverAddr]; exists {
			return client.SendRequest(ctx, req)
		}
	case TransportTCP:
		if client, exists := h.client.tcpClients[serverAddr]; exists {
			return client.SendRequest(ctx, req)
		}
	}

	return nil, fmt.Errorf("no client available for server %s", serverAddr)
}

// GetHealthStatus returns the health status of all servers
func (h *HealthChecker) GetHealthStatus() map[string]HealthStatus {
	h.client.mu.RLock()
	defer h.client.mu.RUnlock()

	result := make(map[string]HealthStatus)

	for serverAddr, state := range h.client.serverStates {
		state.mu.RLock()
		result[serverAddr] = HealthStatus{
			Address:      serverAddr,
			Healthy:      state.healthy,
			LastCheck:    state.lastCheck,
			FailureCount: state.failureCount,
		}
		state.mu.RUnlock()
	}

	return result
}

// HealthStatus represents the health status of a server
type HealthStatus struct {
	Address      string
	Healthy      bool
	LastCheck    time.Time
	FailureCount int64
}

// IsHealthy returns true if the server is healthy
func (h HealthStatus) IsHealthy() bool {
	return h.Healthy
}

// GetFailureCount returns the number of consecutive failures
func (h HealthStatus) GetFailureCount() int64 {
	return h.FailureCount
}

// GetLastCheckTime returns the time of the last health check
func (h HealthStatus) GetLastCheckTime() time.Time {
	return h.LastCheck
}

// String returns a string representation of the health status
func (h HealthStatus) String() string {
	status := "unhealthy"
	if h.Healthy {
		status = "healthy"
	}

	return fmt.Sprintf("Server %s is %s (failures: %d, last check: %v)",
		h.Address, status, h.FailureCount, h.LastCheck)
}
