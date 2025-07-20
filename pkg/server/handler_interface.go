package server

import (
	"context"
	"net"
	"time"

	"github.com/vitalvas/goradius/pkg/packet"
)

// ClientContext represents client metadata and request context information
type ClientContext struct {
	// Client identification
	Addr   net.Addr
	Config *ClientConfig

	// Transport information
	Transport  TransportType
	LocalAddr  net.Addr
	RemoteAddr net.Addr

	// Request metadata
	ReceivedAt time.Time
	RequestID  uint64

	// Session information
	SessionID string
	UserName  string
	NASInfo   *NASInfo

	// Security context
	SharedSecret []byte
	TLSPeerCerts [][]byte // For RADSEC

	// Custom attributes for extensions
	Attributes map[string]interface{}
}

// NASInfo represents Network Access Server information
type NASInfo struct {
	Identifier string
	IPAddress  net.IP
	Port       *uint32
	PortType   *uint32
}

// TransportType represents the transport protocol used
type TransportType string

const (
	TransportUDP TransportType = "udp"
	TransportTCP TransportType = "tcp"
)

// HandlerResult represents the result of request processing
type HandlerResult struct {
	// Response packet to send
	Response *packet.Packet

	// Whether to send the response
	Send bool

	// Custom response attributes
	Attributes map[string]interface{}

	// Processing metadata
	ProcessingTime time.Duration
	HandlerName    string

	// Error information (for logging/monitoring)
	Error error
}

// EnhancedHandler provides an extended interface for RADIUS request processing
type EnhancedHandler interface {
	// Core handler methods
	Handler

	// HandleRequestWithContext processes a request with enhanced context
	HandleRequestWithContext(ctx context.Context, clientCtx *ClientContext, req *packet.Packet) (*HandlerResult, error)

	// GetClientContext builds client context from network information
	GetClientContext(clientAddr, serverAddr net.Addr, transport TransportType) (*ClientContext, error)

	// PreProcessRequest allows preprocessing before main handling
	PreProcessRequest(ctx context.Context, clientCtx *ClientContext, req *packet.Packet) error

	// PostProcessResponse allows post-processing of responses
	PostProcessResponse(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, result *HandlerResult) error

	// Lifecycle methods
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// MiddlewareHandler represents a middleware function for request processing
type MiddlewareHandler func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error)

// HandlerFunc represents a handler function signature
type HandlerFunc func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet) (*HandlerResult, error)

// HandlerChain represents a chain of middleware handlers
type HandlerChain struct {
	middlewares  []MiddlewareHandler
	finalHandler HandlerFunc
}

// NewHandlerChain creates a new handler chain
func NewHandlerChain(finalHandler HandlerFunc, middlewares ...MiddlewareHandler) *HandlerChain {
	return &HandlerChain{
		middlewares:  middlewares,
		finalHandler: finalHandler,
	}
}

// Execute executes the handler chain
func (hc *HandlerChain) Execute(ctx context.Context, clientCtx *ClientContext, req *packet.Packet) (*HandlerResult, error) {
	return hc.executeChain(ctx, clientCtx, req, 0)
}

// executeChain recursively executes the middleware chain
func (hc *HandlerChain) executeChain(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, index int) (*HandlerResult, error) {
	if index >= len(hc.middlewares) {
		// Execute final handler
		return hc.finalHandler(ctx, clientCtx, req)
	}

	// Execute current middleware
	middleware := hc.middlewares[index]
	next := func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet) (*HandlerResult, error) {
		return hc.executeChain(ctx, clientCtx, req, index+1)
	}

	return middleware(ctx, clientCtx, req, next)
}

// ResponseBuilder helps build RADIUS responses
type ResponseBuilder struct {
	code       uint8
	identifier uint8
	attributes []packet.Attribute
}

// NewResponseBuilder creates a new response builder
func NewResponseBuilder(code, identifier uint8) *ResponseBuilder {
	return &ResponseBuilder{
		code:       code,
		identifier: identifier,
		attributes: make([]packet.Attribute, 0),
	}
}

// AddAttribute adds an attribute to the response
func (rb *ResponseBuilder) AddAttribute(attr packet.Attribute) *ResponseBuilder {
	rb.attributes = append(rb.attributes, attr)
	return rb
}

// AddStringAttribute adds a string attribute to the response
func (rb *ResponseBuilder) AddStringAttribute(attrType uint8, value string) *ResponseBuilder {
	attr := packet.NewStringAttribute(attrType, value)
	return rb.AddAttribute(attr)
}

// AddIntegerAttribute adds an integer attribute to the response
func (rb *ResponseBuilder) AddIntegerAttribute(attrType uint8, value uint32) *ResponseBuilder {
	attr := packet.NewIntegerAttribute(attrType, value)
	return rb.AddAttribute(attr)
}

// AddIPAddressAttribute adds an IP address attribute to the response
func (rb *ResponseBuilder) AddIPAddressAttribute(attrType uint8, ip net.IP) *ResponseBuilder {
	var ipBytes [4]byte
	copy(ipBytes[:], ip.To4())
	attr := packet.NewIPAddressAttribute(attrType, ipBytes)
	return rb.AddAttribute(attr)
}

// Build creates the final packet
func (rb *ResponseBuilder) Build() *packet.Packet {
	pkt := &packet.Packet{
		Code:       packet.Code(rb.code),
		Identifier: rb.identifier,
		Length:     packet.PacketHeaderLength,
		Attributes: rb.attributes,
	}

	// Update packet length
	for _, attr := range rb.attributes {
		encoded, err := attr.Encode()
		if err == nil {
			pkt.Length += uint16(len(encoded))
		}
	}

	return pkt
}

// HandlerError represents an error that occurred during request handling
type HandlerError struct {
	Code    HandlerErrorCode
	Message string
	Cause   error
	Context map[string]interface{}
}

// Error implements the error interface
func (he *HandlerError) Error() string {
	if he.Cause != nil {
		return he.Message + ": " + he.Cause.Error()
	}
	return he.Message
}

// Unwrap returns the underlying error
func (he *HandlerError) Unwrap() error {
	return he.Cause
}

// HandlerErrorCode represents different types of handler errors
type HandlerErrorCode int

const (
	ErrorCodeUnknown HandlerErrorCode = iota
	ErrorCodeInvalidRequest
	ErrorCodeAuthenticationFailed
	ErrorCodeAuthorizationFailed
	ErrorCodeInvalidClient
	ErrorCodeInvalidSharedSecret
	ErrorCodeSecurityViolation
	ErrorCodeInternalError
	ErrorCodeTimeout
	ErrorCodeRateLimited
	ErrorCodeUnsupportedRequest
)

// String returns the string representation of the error code
func (code HandlerErrorCode) String() string {
	switch code {
	case ErrorCodeInvalidRequest:
		return "invalid_request"
	case ErrorCodeAuthenticationFailed:
		return "authentication_failed"
	case ErrorCodeAuthorizationFailed:
		return "authorization_failed"
	case ErrorCodeInvalidClient:
		return "invalid_client"
	case ErrorCodeInvalidSharedSecret:
		return "invalid_shared_secret"
	case ErrorCodeSecurityViolation:
		return "security_violation"
	case ErrorCodeInternalError:
		return "internal_error"
	case ErrorCodeTimeout:
		return "timeout"
	case ErrorCodeRateLimited:
		return "rate_limited"
	case ErrorCodeUnsupportedRequest:
		return "unsupported_request"
	default:
		return "unknown"
	}
}

// NewHandlerError creates a new handler error
func NewHandlerError(code HandlerErrorCode, message string, cause error) *HandlerError {
	return &HandlerError{
		Code:    code,
		Message: message,
		Cause:   cause,
		Context: make(map[string]interface{}),
	}
}

// WithContext adds context information to the error
func (he *HandlerError) WithContext(key string, value interface{}) *HandlerError {
	he.Context[key] = value
	return he
}
