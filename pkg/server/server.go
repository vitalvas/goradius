package server

import (
	"context"
	"net"

	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/packet"
)

// Server is a simple RADIUS UDP server
type Server struct {
	conn        *net.UDPConn
	handler     Handler
	dict        *dictionary.Dictionary
	middlewares []Middleware
}

// New creates a new RADIUS server
func New(addr string, handler Handler, dict *dictionary.Dictionary) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	return &Server{
		conn:    conn,
		handler: handler,
		dict:    dict,
	}, nil
}

// Serve starts the server
func (s *Server) Serve() error {
	buffer := make([]byte, 4096)

	for {
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		go s.handlePacket(buffer[:n], clientAddr)
	}
}

// Close stops the server
func (s *Server) Close() error {
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
	if err != nil || resp.Packet == nil {
		return
	}

	// Calculate response authenticator
	resp.Packet.SetAuthenticator(resp.Packet.CalculateResponseAuthenticator(secretResp.Secret, pkt.Authenticator))

	respData, err := resp.Packet.Encode()
	if err != nil {
		return
	}

	s.conn.WriteToUDP(respData, clientAddr)
}
