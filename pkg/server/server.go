package server

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/packet"
)

// Server is a RADIUS server supporting UDP, TCP, and TLS transports
type Server struct {
	transport          Transport
	handler            Handler
	dict               *dictionary.Dictionary
	middlewares        []Middleware
	mu                 sync.RWMutex
	ready              chan struct{}
	requireMessageAuth bool
	useMessageAuth     bool
	requireRequestAuth bool
	requestTimeout     time.Duration // 0 means no timeout
}

func New(cfg Config) (*Server, error) {
	dict := cfg.Dictionary
	if dict == nil {
		var err error
		dict, err = dictionaries.NewDefault()
		if err != nil {
			return nil, err
		}
	}

	requireMessageAuth := true
	if cfg.RequireMessageAuthenticator != nil {
		requireMessageAuth = *cfg.RequireMessageAuthenticator
	}

	useMessageAuth := true
	if cfg.UseMessageAuthenticator != nil {
		useMessageAuth = *cfg.UseMessageAuthenticator
	}

	requireRequestAuth := false
	if cfg.RequireRequestAuthenticator != nil {
		requireRequestAuth = *cfg.RequireRequestAuthenticator
	}

	var requestTimeout time.Duration
	if cfg.RequestTimeout != nil {
		requestTimeout = *cfg.RequestTimeout
	}

	return &Server{
		handler:            cfg.Handler,
		dict:               dict,
		ready:              make(chan struct{}),
		requireMessageAuth: requireMessageAuth,
		useMessageAuth:     useMessageAuth,
		requireRequestAuth: requireRequestAuth,
		requestTimeout:     requestTimeout,
	}, nil
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

// handlePacket processes a single RADIUS packet.
// Called by the transport for each received packet.
func (s *Server) handlePacket(data []byte, remoteAddr net.Addr, respond ResponderFunc) {
	pkt, err := packet.Decode(data)
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

	// Get secret
	secretReq := SecretRequest{
		Context:    ctx,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
	}

	secretResp, err := s.handler.ServeSecret(secretReq)
	if err != nil {
		return
	}

	// Optionally validate Request Authenticator for non-Access-Request packets (RFC 2866, RFC 5176)
	// Access-Request uses random authenticator, others use computed MD5
	if s.requireRequestAuth && pkt.Code != packet.CodeAccessRequest {
		expectedAuth := pkt.CalculateRequestAuthenticator(secretResp.Secret)
		if !bytes.Equal(pkt.Authenticator[:], expectedAuth[:]) {
			return
		}
	}

	// Verify Message-Authenticator per RFC 2869 Section 5.14
	if s.requireMessageAuth {
		if !pkt.VerifyMessageAuthenticator(secretResp.Secret, pkt.Authenticator) {
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
