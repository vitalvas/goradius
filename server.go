package goradius

import (
	"context"
	"net"
	"sync"
	"time"
)

// Server is a RADIUS server supporting UDP, TCP, and TLS transports
type Server struct {
	transport          Transport
	handler            Handler
	dict               *Dictionary
	middlewares        []Middleware
	mu                 sync.RWMutex
	ready              chan struct{}
	requireMessageAuth bool
	useMessageAuth     bool
	requireRequestAuth bool
	requestTimeout     time.Duration // 0 means no timeout
}

func NewServer(opts ...ServerOption) (*Server, error) {
	s := &Server{
		ready:              make(chan struct{}),
		requireMessageAuth: true,
		useMessageAuth:     true,
		requireRequestAuth: false,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.dict == nil {
		var err error
		s.dict, err = NewDefault()
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Serve starts the server using the provided transport.
// Supports UDP, TCP, and TLS transports.
func (s *Server) Serve(transport Transport) error {
	s.mu.Lock()
	s.transport = transport
	close(s.ready)
	s.mu.Unlock()

	return transport.Serve(s.handlePacket)
}

// Addr returns the local address the server is listening on.
// Blocks until the server is ready.
func (s *Server) Addr() net.Addr {
	<-s.ready
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.transport == nil {
		return nil
	}
	return s.transport.LocalAddr()
}

// Close stops the server and waits for in-flight requests to complete.
func (s *Server) Close() error {
	s.mu.Lock()
	transport := s.transport
	s.mu.Unlock()

	if transport == nil {
		return nil
	}

	return transport.Close()
}

// Use adds middleware to the server
// Middlewares are applied in the order they are added
func (s *Server) Use(middleware Middleware) {
	s.middlewares = append(s.middlewares, middleware)
}

// buildHandler wraps the handler with all middlewares
func (s *Server) buildHandler() Handler {
	handler := s.handler

	// Apply middlewares in reverse order (last added is outermost)
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		handler = s.middlewares[i](handler)
	}

	return handler
}

// handlePacket processes a single RADIUS
// Called by the transport for each received
func (s *Server) handlePacket(data []byte, remoteAddr net.Addr, respond ResponderFunc) {
	pkt, err := Decode(data)
	if err != nil {
		return
	}

	// Set dictionary on decoded packet
	if s.dict != nil {
		pkt.Dict = s.dict
	}

	if s.handler == nil {
		return
	}

	// Create context with optional timeout
	var ctx context.Context
	var cancel context.CancelFunc
	if s.requestTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), s.requestTimeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	// Get local address from transport
	s.mu.RLock()
	transport := s.transport
	s.mu.RUnlock()

	var localAddr net.Addr
	if transport != nil {
		localAddr = transport.LocalAddr()
	}

	// Get secret (attempt 0)
	secretReq := SecretRequest{
		Context:    ctx,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Attempt:    0,
	}

	secretResp, err := s.handler.ServeSecret(secretReq)
	if err != nil {
		return
	}

	totalAttempts := max(secretResp.Attempts, 1)

	// Validate packet with secret rotation support
	if totalAttempts <= 1 {
		// Fast path: single secret
		if !s.validatePacketSecret(pkt, secretResp.Secret) {
			return
		}
	} else {
		// Rotation path: try multiple secrets
		secretResp = s.resolveSecret(ctx, localAddr, remoteAddr, pkt, secretResp, totalAttempts)
		if secretResp.Secret == nil {
			return
		}
	}

	// Handle RADIUS request
	req := &Request{
		Context:    ctx,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		packet:     pkt,
		Secret:     secretResp,
	}

	// Build handler with middlewares
	handler := s.buildHandler()

	resp, err := handler.ServeRADIUS(req)
	if err != nil || resp.packet == nil {
		return
	}

	if s.useMessageAuth {
		resp.packet.AddMessageAuthenticator(secretResp.Secret, pkt.Authenticator)
	}

	// Calculate response authenticator per RFC 2865 Section 3
	resp.packet.SetAuthenticator(resp.packet.CalculateResponseAuthenticator(secretResp.Secret, pkt.Authenticator))

	respData, err := resp.packet.Encode()
	if err != nil {
		return
	}

	// Send response via transport responder
	_ = respond(respData)
}

// validatePacketSecret validates the packet against the given secret
// using Message-Authenticator and/or Request Authenticator checks.
func (s *Server) validatePacketSecret(pkt *Packet, secret []byte) bool {
	if s.requireRequestAuth && pkt.Code != CodeAccessRequest {
		expectedAuth := pkt.CalculateRequestAuthenticator(secret)
		if pkt.Authenticator != expectedAuth {
			return false
		}
	}

	if s.requireMessageAuth {
		if !pkt.VerifyMessageAuthenticator(secret, pkt.Authenticator) {
			return false
		}
	}

	return true
}

// resolveSecret tries each secret in order until one validates the packet.
// Returns the SecretResponse with the resolved secret, or one with nil Secret
// if all attempts fail.
func (s *Server) resolveSecret(ctx context.Context, localAddr, remoteAddr net.Addr, pkt *Packet, firstResp SecretResponse, totalAttempts int) SecretResponse {
	// Try first secret (already fetched)
	if s.validatePacketSecret(pkt, firstResp.Secret) {
		return firstResp
	}

	// Try remaining secrets
	for i := 1; i < totalAttempts; i++ {
		resp, err := s.handler.ServeSecret(SecretRequest{
			Context:    ctx,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			Attempt:    i,
		})
		if err != nil {
			continue
		}

		if s.validatePacketSecret(pkt, resp.Secret) {
			return resp
		}
	}

	// All secrets failed
	return SecretResponse{}
}
