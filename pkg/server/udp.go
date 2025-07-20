package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vitalvas/goradius/pkg/packet"
)

// Listen starts the UDP listener and begins processing requests
func (l *UDPListener) Listen() error {
	l.logger.Infof("UDP listener starting on %s", l.conn.LocalAddr())

	defer func() {
		l.conn.Close()
		l.logger.Infof("UDP listener stopped on %s", l.conn.LocalAddr())
	}()

	// Buffer for incoming packets
	buffer := make([]byte, l.config.MaxRequestSize)

	for {
		select {
		case <-l.ctx.Done():
			return nil
		default:
			// Set read timeout
			if l.config.ReadTimeout > 0 {
				l.conn.SetReadDeadline(time.Now().Add(l.config.ReadTimeout))
			}

			// Read packet
			n, clientAddr, err := l.conn.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout is expected, continue listening
					continue
				}
				if l.ctx.Err() != nil {
					// Context cancelled, shutdown in progress
					return nil
				}
				l.logger.Errorf("Error reading from UDP connection: %v", err)
				continue
			}

			// Update statistics
			l.stats.UpdateRequestStats(uint64(n), 0, false)

			// Get a worker from the pool
			select {
			case <-l.workers:
				// Process request in goroutine
				l.wg.Add(1)
				go func(data []byte, addr net.Addr, received time.Time) {
					defer l.wg.Done()
					defer func() {
						// Return worker to pool
						l.workers <- struct{}{}
					}()

					l.processRequest(data, addr, received)
				}(append([]byte(nil), buffer[:n]...), clientAddr, time.Now())

			default:
				// No workers available, drop request
				l.logger.Warnf("No workers available, dropping request from %s", clientAddr)
				l.stats.mu.Lock()
				l.stats.Errors++
				l.stats.mu.Unlock()
			}
		}
	}
}

// Stop stops the UDP listener
func (l *UDPListener) Stop() {
	l.logger.Infof("Stopping UDP listener on %s", l.conn.LocalAddr())
	l.cancel()
	l.wg.Wait()
}

// processRequest processes an incoming RADIUS request
func (l *UDPListener) processRequest(data []byte, clientAddr net.Addr, receivedAt time.Time) {
	defer func() {
		if r := recover(); r != nil {
			l.logger.Errorf("Panic processing request from %s: %v", clientAddr, r)
		}
	}()

	startTime := time.Now()

	// Validate client
	clientConfig, err := l.validateClient(clientAddr)
	if err != nil {
		l.logger.Warnf("Client validation failed for %s: %v", clientAddr, err)
		return
	}

	// Parse RADIUS packet
	radiusPacket, err := packet.Decode(data)
	if err != nil {
		l.logger.Warnf("Failed to parse RADIUS packet from %s: %v", clientAddr, err)
		l.stats.mu.Lock()
		l.stats.Errors++
		l.stats.mu.Unlock()
		return
	}

	// Create request context with timeout
	ctx, cancel := context.WithTimeout(l.ctx, l.config.ReadTimeout)
	defer cancel()

	// Create request
	request := &Request{
		ClientAddr: clientAddr,
		ServerAddr: l.conn.LocalAddr(),
		Packet:     radiusPacket,
		Client:     clientConfig,
		ReceivedAt: receivedAt,
	}

	// Process request through handler
	response, err := l.handler.HandleRequest(ctx, request)
	if err != nil {
		l.logger.Errorf("Error handling request from %s: %v", clientAddr, err)
		l.stats.mu.Lock()
		l.stats.Errors++
		l.stats.mu.Unlock()
		return
	}

	// Send response if required
	if response != nil && response.Send && response.Packet != nil {
		err = l.sendResponse(response.Packet, clientAddr)
		if err != nil {
			l.logger.Errorf("Error sending response to %s: %v", clientAddr, err)
			l.stats.mu.Lock()
			l.stats.Errors++
			l.stats.mu.Unlock()
			return
		}
	}

	// Update statistics
	latency := time.Since(startTime)
	l.stats.UpdateRequestStats(0, uint64(len(data)), true)

	l.logger.Debugf("Processed request from %s in %v", clientAddr, latency)
}

// validateClient validates that the client is allowed to connect
func (l *UDPListener) validateClient(clientAddr net.Addr) (*ClientConfig, error) {
	// Extract IP address
	var clientIP net.IP
	switch addr := clientAddr.(type) {
	case *net.UDPAddr:
		clientIP = addr.IP
	case *net.IPAddr:
		clientIP = addr.IP
	default:
		return nil, fmt.Errorf("unsupported address type: %T", clientAddr)
	}

	// Check against configured clients
	for _, client := range l.binding.Clients {
		for _, network := range client.Networks {
			if isIPInNetwork(clientIP, network) {
				return &client, nil
			}
		}
	}

	return nil, fmt.Errorf("client %s not authorized", clientIP)
}

// sendResponse sends a RADIUS response packet
func (l *UDPListener) sendResponse(responsePacket *packet.Packet, clientAddr net.Addr) error {
	// Encode response packet
	data, err := responsePacket.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode response packet: %w", err)
	}

	// Set write timeout
	if l.config.WriteTimeout > 0 {
		l.conn.SetWriteDeadline(time.Now().Add(l.config.WriteTimeout))
	}

	// Send response
	_, err = l.conn.WriteTo(data, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	// Update statistics
	l.stats.mu.Lock()
	l.stats.BytesSent += uint64(len(data))
	l.stats.Responses++
	l.stats.mu.Unlock()

	return nil
}

// GetListenerAddress returns the listener's local address
func (l *UDPListener) GetListenerAddress() net.Addr {
	return l.conn.LocalAddr()
}

// GetStatistics returns listener statistics
func (l *UDPListener) GetStatistics() *ListenerStatistics {
	return l.stats
}
