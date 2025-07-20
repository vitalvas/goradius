package server

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// DefaultHandler provides a basic implementation of the Handler interface
type DefaultHandler struct {
	// Client configurations
	clients map[string]*ClientConfig
	mu      sync.RWMutex

	// Logger
	logger log.Logger

	// Authentication callback (optional)
	AuthCallback func(username, password string) bool

	// Accounting callback (optional)
	AccountingCallback func(req *Request) error
}

// NewDefaultHandler creates a new default handler
func NewDefaultHandler(logger log.Logger) *DefaultHandler {
	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	return &DefaultHandler{
		clients: make(map[string]*ClientConfig),
		logger:  logger,
	}
}

// AddClient adds a client configuration
func (h *DefaultHandler) AddClient(clientConfig *ClientConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, network := range clientConfig.Networks {
		h.clients[network] = clientConfig
	}
}

// SetAuthCallback sets the authentication callback function
func (h *DefaultHandler) SetAuthCallback(callback func(username, password string) bool) {
	h.AuthCallback = callback
}

// SetAccountingCallback sets the accounting callback function
func (h *DefaultHandler) SetAccountingCallback(callback func(req *Request) error) {
	h.AccountingCallback = callback
}

// HandleRequest processes a RADIUS request and returns a response
func (h *DefaultHandler) HandleRequest(ctx context.Context, req *Request) (*Response, error) {
	h.logger.Debugf("Handling request code %d from %s", req.Packet.Code, req.ClientAddr)

	switch req.Packet.Code {
	case packet.CodeAccessRequest:
		return h.handleAuthRequest(ctx, req)
	case packet.CodeAccountingRequest:
		return h.handleAccountingRequest(ctx, req)
	case packet.CodeCoARequest, packet.CodeDisconnectRequest:
		return h.handleCoARequest(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported packet code: %d", req.Packet.Code)
	}
}

// GetSharedSecret returns the shared secret for a client
func (h *DefaultHandler) GetSharedSecret(clientAddr net.Addr) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

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

	// Find matching client configuration
	for network, client := range h.clients {
		if isIPInNetwork(clientIP, network) {
			return []byte(client.Secret), nil
		}
	}

	return nil, fmt.Errorf("no shared secret found for client %s", clientIP)
}

// handleAuthRequest handles authentication requests
func (h *DefaultHandler) handleAuthRequest(ctx context.Context, req *Request) (*Response, error) {
	switch req.Packet.Code {
	case packet.CodeAccessRequest:
		return h.handleAccessRequest(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported authentication packet type: %d", req.Packet.Code)
	}
}

// handleAccountingRequest handles accounting requests
func (h *DefaultHandler) handleAccountingRequest(ctx context.Context, req *Request) (*Response, error) {
	switch req.Packet.Code {
	case packet.CodeAccountingRequest:
		return h.handleAccountingRequestPacket(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported accounting packet type: %d", req.Packet.Code)
	}
}

// handleCoARequest handles Change of Authorization requests
func (h *DefaultHandler) handleCoARequest(ctx context.Context, req *Request) (*Response, error) {
	switch req.Packet.Code {
	case packet.CodeCoARequest:
		return h.handleCoARequestPacket(ctx, req)
	case packet.CodeDisconnectRequest:
		return h.handleDisconnectRequest(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported CoA packet type: %d", req.Packet.Code)
	}
}

// handleAccessRequest handles Access-Request packets
func (h *DefaultHandler) handleAccessRequest(_ context.Context, req *Request) (*Response, error) {
	// Extract username
	userNameAttr, found := req.Packet.GetAttribute(packet.AttrUserName)
	if !found {
		h.logger.Warnf("Access-Request without username from %s", req.ClientAddr)
		return h.createAccessReject(req, "Missing username"), nil
	}
	username := userNameAttr.GetString()

	// For now, create a simple Accept response
	// In a real implementation, this would perform actual authentication
	if h.AuthCallback != nil {
		// Get password (this is simplified - real implementations would handle different auth methods)
		var password string
		if passwordAttr, found := req.Packet.GetAttribute(packet.AttrUserPassword); found {
			password = passwordAttr.GetString()
		}

		if !h.AuthCallback(username, password) {
			h.logger.Infof("Authentication failed for user %s from %s", username, req.ClientAddr)
			return h.createAccessReject(req, "Authentication failed"), nil
		}
	}

	h.logger.Infof("Authentication successful for user %s from %s", username, req.ClientAddr)
	return h.createAccessAccept(req), nil
}

// handleAccountingRequestPacket handles Accounting-Request packets
func (h *DefaultHandler) handleAccountingRequestPacket(_ context.Context, req *Request) (*Response, error) {
	if h.AccountingCallback != nil {
		if err := h.AccountingCallback(req); err != nil {
			h.logger.Errorf("Accounting callback failed: %v", err)
			return nil, err
		}
	}

	h.logger.Debugf("Accounting request processed from %s", req.ClientAddr)
	return h.createAccountingResponse(req), nil
}

// handleCoARequestPacket handles CoA-Request packets
func (h *DefaultHandler) handleCoARequestPacket(_ context.Context, req *Request) (*Response, error) {
	h.logger.Debugf("CoA request from %s", req.ClientAddr)
	return h.createCoAAck(req), nil
}

// handleDisconnectRequest handles Disconnect-Request packets
func (h *DefaultHandler) handleDisconnectRequest(_ context.Context, req *Request) (*Response, error) {
	h.logger.Debugf("Disconnect request from %s", req.ClientAddr)
	return h.createDisconnectAck(req), nil
}

// createAccessAccept creates an Access-Accept response
func (h *DefaultHandler) createAccessAccept(req *Request) *Response {
	responsePacket := &packet.Packet{
		Code:       packet.CodeAccessAccept,
		Identifier: req.Packet.Identifier,
		Length:     packet.PacketHeaderLength,
		Attributes: make([]packet.Attribute, 0),
	}

	return &Response{
		Packet: responsePacket,
		Send:   true,
	}
}

// createAccessReject creates an Access-Reject response
func (h *DefaultHandler) createAccessReject(req *Request, message string) *Response {
	responsePacket := &packet.Packet{
		Code:       packet.CodeAccessReject,
		Identifier: req.Packet.Identifier,
		Length:     packet.PacketHeaderLength,
		Attributes: make([]packet.Attribute, 0),
	}

	// Add Reply-Message if provided
	if message != "" {
		replyMsg := packet.NewStringAttribute(packet.AttrReplyMessage, message)
		responsePacket.AddAttribute(replyMsg)
	}

	return &Response{
		Packet: responsePacket,
		Send:   true,
	}
}

// createAccountingResponse creates an Accounting-Response
func (h *DefaultHandler) createAccountingResponse(req *Request) *Response {
	responsePacket := &packet.Packet{
		Code:       packet.CodeAccountingResponse,
		Identifier: req.Packet.Identifier,
		Length:     packet.PacketHeaderLength,
		Attributes: make([]packet.Attribute, 0),
	}

	return &Response{
		Packet: responsePacket,
		Send:   true,
	}
}

// createCoAAck creates a CoA-ACK response
func (h *DefaultHandler) createCoAAck(req *Request) *Response {
	responsePacket := &packet.Packet{
		Code:       packet.CodeCoAAck,
		Identifier: req.Packet.Identifier,
		Length:     packet.PacketHeaderLength,
		Attributes: make([]packet.Attribute, 0),
	}

	return &Response{
		Packet: responsePacket,
		Send:   true,
	}
}

// createDisconnectAck creates a Disconnect-ACK response
func (h *DefaultHandler) createDisconnectAck(req *Request) *Response {
	responsePacket := &packet.Packet{
		Code:       packet.CodeDisconnectACK,
		Identifier: req.Packet.Identifier,
		Length:     packet.PacketHeaderLength,
		Attributes: make([]packet.Attribute, 0),
	}

	return &Response{
		Packet: responsePacket,
		Send:   true,
	}
}
