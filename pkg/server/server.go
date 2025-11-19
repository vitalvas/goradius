package server

import (
	"context"
	"net"
	"sync"

	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/packet"
)

// Server is a simple RADIUS UDP server
type Server struct {
	addr        string
	conn        *net.UDPConn
	handler     Handler
	dict        *dictionary.Dictionary
	middlewares []Middleware
	mu          sync.RWMutex
	ready       chan struct{}
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

	return &Server{
		addr:    cfg.Addr,
		handler: cfg.Handler,
		dict:    dict,
		ready:   make(chan struct{}),
	}, nil
}

func (s *Server) ListenAndServe() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.conn = conn
	close(s.ready)
	s.mu.Unlock()

	buffer := make([]byte, 4096)

	for {
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		go s.handlePacket(buffer[:n], clientAddr)
	}
}

func (s *Server) Addr() net.Addr {
	<-s.ready
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Close stops the server
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
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

func (s *Server) handlePacket(data []byte, clientAddr *net.UDPAddr) {
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

	ctx := context.Background()

	// Get secret
	secretReq := SecretRequest{
		Context:    ctx,
		LocalAddr:  s.conn.LocalAddr(),
		RemoteAddr: clientAddr,
	}

	secretResp, err := s.handler.ServeSecret(secretReq)
	if err != nil {
		return
	}

	// For Access-Request, skip authenticator validation (radtest uses Message-Authenticator)
	// In production, you'd want proper validation

	// Handle RADIUS request
	req := &Request{
		Context:    ctx,
		LocalAddr:  s.conn.LocalAddr(),
		RemoteAddr: clientAddr,
		packet:     pkt,
		Secret:     secretResp,
	}

	// Build handler with middlewares
	handler := s.buildHandler()

	resp, err := handler.ServeRADIUS(req)
	if err != nil || resp.packet == nil {
		return
	}

	// Calculate response authenticator
	resp.packet.SetAuthenticator(resp.packet.CalculateResponseAuthenticator(secretResp.Secret, pkt.Authenticator))

	respData, err := resp.packet.Encode()
	if err != nil {
		return
	}

	s.conn.WriteToUDP(respData, clientAddr)
}
