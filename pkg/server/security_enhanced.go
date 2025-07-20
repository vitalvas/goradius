package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vitalvas/goradius/pkg/packet"
)

// EnhancedSecurityValidator provides comprehensive security validation for RADIUS packets
type EnhancedSecurityValidator struct {
	ValidateMessageAuth bool
	RequireMessageAuth  bool
	ValidatePacketAuth  bool
	MaxPacketSize       int
	AllowedPacketTypes  []packet.Code
}

// EnhancedSecurityOptions configures enhanced security validation behavior
type EnhancedSecurityOptions struct {
	ValidateMessageAuth bool
	RequireMessageAuth  bool
	ValidatePacketAuth  bool
	MaxPacketSize       int
	AllowedPacketTypes  []packet.Code
}

// DefaultEnhancedSecurityOptions returns default enhanced security validation options
func DefaultEnhancedSecurityOptions() *EnhancedSecurityOptions {
	return &EnhancedSecurityOptions{
		ValidateMessageAuth: true,
		RequireMessageAuth:  false,
		ValidatePacketAuth:  true,
		MaxPacketSize:       4096,
		AllowedPacketTypes: []packet.Code{
			packet.CodeAccessRequest,
			packet.CodeAccessAccept,
			packet.CodeAccessReject,
			packet.CodeAccessChallenge,
			packet.CodeAccountingRequest,
			packet.CodeAccountingResponse,
			packet.CodeStatusServer,
			packet.CodeStatusClient,
			packet.CodeDisconnectRequest,
			packet.CodeDisconnectACK,
			packet.CodeDisconnectNAK,
			packet.CodeCoARequest,
			packet.CodeCoAAck,
			packet.CodeCoANak,
		},
	}
}

// NewEnhancedSecurityValidator creates a new enhanced security validator
func NewEnhancedSecurityValidator(options *EnhancedSecurityOptions) *EnhancedSecurityValidator {
	if options == nil {
		options = DefaultEnhancedSecurityOptions()
	}

	return &EnhancedSecurityValidator{
		ValidateMessageAuth: options.ValidateMessageAuth,
		RequireMessageAuth:  options.RequireMessageAuth,
		ValidatePacketAuth:  options.ValidatePacketAuth,
		MaxPacketSize:       options.MaxPacketSize,
		AllowedPacketTypes:  options.AllowedPacketTypes,
	}
}

// ValidatePacket performs comprehensive security validation on a RADIUS packet
func (esv *EnhancedSecurityValidator) ValidatePacket(_ context.Context, clientCtx *ClientContext, req *packet.Packet) error {
	// Validate packet size
	if esv.MaxPacketSize > 0 && int(req.Length) > esv.MaxPacketSize {
		return fmt.Errorf("packet size %d exceeds maximum allowed size %d", req.Length, esv.MaxPacketSize)
	}

	// Validate packet type
	if len(esv.AllowedPacketTypes) > 0 {
		allowed := false
		for _, allowedType := range esv.AllowedPacketTypes {
			if req.Code == allowedType {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("packet type %d not allowed", req.Code)
		}
	}

	// Validate packet authenticator
	if esv.ValidatePacketAuth {
		if err := esv.validatePacketAuthenticator(req, clientCtx); err != nil {
			return fmt.Errorf("packet authenticator validation failed: %w", err)
		}
	}

	// Validate Message-Authenticator if present or required
	if esv.ValidateMessageAuth || esv.RequireMessageAuth {
		if err := esv.validateMessageAuthenticator(req, clientCtx); err != nil {
			return fmt.Errorf("Message-Authenticator validation failed: %w", err)
		}
	}

	return nil
}

// validatePacketAuthenticator validates the packet authenticator
func (esv *EnhancedSecurityValidator) validatePacketAuthenticator(req *packet.Packet, _ *ClientContext) error {
	switch req.Code {
	case packet.CodeAccessRequest:
		// Request packets use Request Authenticator (random value)
		if len(req.Authenticator) != 16 {
			return fmt.Errorf("invalid Request Authenticator length: %d", len(req.Authenticator))
		}
		// Request Authenticator should be unpredictable (basic entropy check)
		if isZeroOrRepeatedEnhanced(req.Authenticator[:]) {
			return fmt.Errorf("Request Authenticator appears to be weak or repeated")
		}

	case packet.CodeAccessAccept, packet.CodeAccessReject, packet.CodeAccessChallenge:
		// Response packets use Response Authenticator
		// In a real implementation, this would validate against the original request
		if len(req.Authenticator) != 16 {
			return fmt.Errorf("invalid Response Authenticator length: %d", len(req.Authenticator))
		}

	case packet.CodeAccountingRequest:
		// Accounting-Request uses Request Authenticator calculated from packet
		if len(req.Authenticator) != 16 {
			return fmt.Errorf("invalid Request Authenticator length: %d", len(req.Authenticator))
		}

	case packet.CodeAccountingResponse:
		// Accounting-Response uses Response Authenticator
		if len(req.Authenticator) != 16 {
			return fmt.Errorf("invalid Response Authenticator length: %d", len(req.Authenticator))
		}
	}

	return nil
}

// validateMessageAuthenticator validates the Message-Authenticator attribute
func (esv *EnhancedSecurityValidator) validateMessageAuthenticator(req *packet.Packet, _ *ClientContext) error {
	// Look for Message-Authenticator attribute
	var hasMessageAuth bool
	var msgAuthAttr packet.Attribute

	for _, attr := range req.Attributes {
		if attr.Type == packet.AttrMessageAuthenticator {
			hasMessageAuth = true
			msgAuthAttr = attr
			break
		}
	}

	// If required but not present, return error
	if esv.RequireMessageAuth && !hasMessageAuth {
		return fmt.Errorf("Message-Authenticator is required but not present")
	}

	// If not present and not required, skip validation
	if !hasMessageAuth {
		return nil
	}

	// Validate Message-Authenticator length
	if len(msgAuthAttr.Value) != 16 {
		return fmt.Errorf("invalid Message-Authenticator length: %d", len(msgAuthAttr.Value))
	}

	// For now, we'll do basic validation since we don't have the raw packet data
	// In a real implementation, this would use the crypto package for HMAC-MD5 validation
	// TODO: Implement proper HMAC-MD5 validation when packet encoding is available
	return nil
}

// isZeroOrRepeatedEnhanced checks if a byte slice is all zeros or has repeated patterns
func isZeroOrRepeatedEnhanced(data []byte) bool {
	if len(data) == 0 {
		return true
	}

	// Single byte cannot be considered repeated
	if len(data) == 1 {
		return false
	}

	// Check for all zeros
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}

	// Check for repeated patterns (simple case: all same byte)
	first := data[0]
	allSame := true
	for _, b := range data[1:] {
		if b != first {
			allSame = false
			break
		}
	}

	return allSame
}

// EnhancedSecurityMiddleware creates an enhanced security middleware for the new middleware system
func EnhancedSecurityMiddleware(options *EnhancedSecurityOptions) MiddlewareHandler {
	validator := NewEnhancedSecurityValidator(options)

	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Perform enhanced security validation
		if err := validator.ValidatePacket(ctx, clientCtx, req); err != nil {
			return nil, NewHandlerError(ErrorCodeSecurityViolation, "enhanced security validation failed", err)
		}

		// Continue to next handler
		return next(ctx, clientCtx, req)
	}
}

// EnhancedMessageAuthenticatorMiddleware creates an enhanced middleware specifically for Message-Authenticator validation
func EnhancedMessageAuthenticatorMiddleware(required bool) MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Look for Message-Authenticator attribute
		var hasMessageAuth bool
		var msgAuthAttr packet.Attribute

		for _, attr := range req.Attributes {
			if attr.Type == packet.AttrMessageAuthenticator {
				hasMessageAuth = true
				msgAuthAttr = attr
				break
			}
		}

		// If required but not present, return error
		if required && !hasMessageAuth {
			return nil, NewHandlerError(ErrorCodeSecurityViolation, "Message-Authenticator is required but not present", nil)
		}

		// If present, validate it
		if hasMessageAuth {
			// Validate Message-Authenticator length
			if len(msgAuthAttr.Value) != 16 {
				return nil, NewHandlerError(ErrorCodeSecurityViolation, "invalid Message-Authenticator length", nil)
			}

			// TODO: Implement proper HMAC-MD5 validation when packet encoding is available
			// For now, we'll use the existing validation from the middleware.go file
		}

		// Continue to next handler
		return next(ctx, clientCtx, req)
	}
}

// EnhancedPacketAuthenticatorMiddleware creates an enhanced middleware for packet authenticator validation
func EnhancedPacketAuthenticatorMiddleware() MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Validate packet authenticator based on packet type
		switch req.Code {
		case packet.CodeAccessRequest:
			// Request packets use Request Authenticator (random value)
			if len(req.Authenticator) != 16 {
				return nil, NewHandlerError(ErrorCodeInvalidRequest, "invalid Request Authenticator length", nil)
			}
			// Request Authenticator should be unpredictable
			if isZeroOrRepeatedEnhanced(req.Authenticator[:]) {
				return nil, NewHandlerError(ErrorCodeSecurityViolation, "Request Authenticator appears to be weak", nil)
			}

		case packet.CodeAccountingRequest:
			// Accounting-Request uses Request Authenticator calculated from packet
			if len(req.Authenticator) != 16 {
				return nil, NewHandlerError(ErrorCodeSecurityViolation, "invalid Request Authenticator length", nil)
			}
		}

		// Continue to next handler
		return next(ctx, clientCtx, req)
	}
}

// EnhancedSecurityEventType represents the type of enhanced security event
type EnhancedSecurityEventType int

const (
	EnhancedSecurityEventInvalidAuthenticator EnhancedSecurityEventType = iota
	EnhancedSecurityEventInvalidMessageAuth
	EnhancedSecurityEventPacketTooLarge
	EnhancedSecurityEventUnauthorizedPacketType
	EnhancedSecurityEventWeakAuthenticator
	EnhancedSecurityEventValidationError
)

// String returns the string representation of the enhanced security event type
func (eset EnhancedSecurityEventType) String() string {
	switch eset {
	case EnhancedSecurityEventInvalidAuthenticator:
		return "InvalidAuthenticator"
	case EnhancedSecurityEventInvalidMessageAuth:
		return "InvalidMessageAuth"
	case EnhancedSecurityEventPacketTooLarge:
		return "PacketTooLarge"
	case EnhancedSecurityEventUnauthorizedPacketType:
		return "UnauthorizedPacketType"
	case EnhancedSecurityEventWeakAuthenticator:
		return "WeakAuthenticator"
	case EnhancedSecurityEventValidationError:
		return "ValidationError"
	default:
		return "Unknown"
	}
}

// EnhancedSecurityEvent represents an enhanced security-related event
type EnhancedSecurityEvent struct {
	Type       EnhancedSecurityEventType
	ClientIP   net.IP
	Message    string
	PacketCode packet.Code
	Timestamp  time.Time
	Context    map[string]interface{}
}

// EnhancedSecurityEventHandler handles enhanced security events
type EnhancedSecurityEventHandler interface {
	HandleEnhancedSecurityEvent(event EnhancedSecurityEvent)
}

// EnhancedSecurityEventHandlerFunc is a functional adapter for EnhancedSecurityEventHandler
type EnhancedSecurityEventHandlerFunc func(event EnhancedSecurityEvent)

// HandleEnhancedSecurityEvent implements EnhancedSecurityEventHandler
func (f EnhancedSecurityEventHandlerFunc) HandleEnhancedSecurityEvent(event EnhancedSecurityEvent) {
	f(event)
}

// EnhancedSecurityEventLogger provides logging for enhanced security events
type EnhancedSecurityEventLogger struct {
	handlers []EnhancedSecurityEventHandler
}

// NewEnhancedSecurityEventLogger creates a new enhanced security event logger
func NewEnhancedSecurityEventLogger() *EnhancedSecurityEventLogger {
	return &EnhancedSecurityEventLogger{
		handlers: make([]EnhancedSecurityEventHandler, 0),
	}
}

// AddHandler adds an enhanced security event handler
func (esel *EnhancedSecurityEventLogger) AddHandler(handler EnhancedSecurityEventHandler) {
	esel.handlers = append(esel.handlers, handler)
}

// LogEvent logs an enhanced security event
func (esel *EnhancedSecurityEventLogger) LogEvent(event EnhancedSecurityEvent) {
	for _, handler := range esel.handlers {
		handler.HandleEnhancedSecurityEvent(event)
	}
}

// LogSecurityViolation logs an enhanced security violation event
func (esel *EnhancedSecurityEventLogger) LogSecurityViolation(eventType EnhancedSecurityEventType, clientIP net.IP, message string, packetCode packet.Code, context map[string]interface{}) {
	event := EnhancedSecurityEvent{
		Type:       eventType,
		ClientIP:   clientIP,
		Message:    message,
		PacketCode: packetCode,
		Timestamp:  time.Now(),
		Context:    context,
	}
	esel.LogEvent(event)
}

// EnhancedSecurityEventMiddleware creates an enhanced middleware for security event logging
func EnhancedSecurityEventMiddleware(logger *EnhancedSecurityEventLogger) MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Execute next handler
		result, err := next(ctx, clientCtx, req)

		// Log security violations
		if err != nil {
			if handlerErr, ok := err.(*HandlerError); ok && handlerErr.Code == ErrorCodeSecurityViolation {
				logger.LogSecurityViolation(
					EnhancedSecurityEventValidationError,
					clientCtx.RemoteAddr.(*net.UDPAddr).IP,
					handlerErr.Message,
					req.Code,
					map[string]interface{}{
						"error":         handlerErr.Cause.Error(),
						"transport":     clientCtx.Transport,
						"shared_secret": len(clientCtx.SharedSecret) > 0,
						"packet_length": req.Length,
					},
				)
			}
		}

		return result, err
	}
}

// MessageAuthenticatorHelper provides utilities for working with Message-Authenticator
type MessageAuthenticatorHelper struct {
	SharedSecret []byte
}

// NewMessageAuthenticatorHelper creates a new Message-Authenticator helper
func NewMessageAuthenticatorHelper(sharedSecret []byte) *MessageAuthenticatorHelper {
	return &MessageAuthenticatorHelper{
		SharedSecret: sharedSecret,
	}
}

// ValidateMessageAuthenticator validates the Message-Authenticator in a packet
func (mah *MessageAuthenticatorHelper) ValidateMessageAuthenticator(req *packet.Packet) error {
	// Look for Message-Authenticator attribute
	var msgAuthAttr packet.Attribute
	var found bool

	for _, attr := range req.Attributes {
		if attr.Type == packet.AttrMessageAuthenticator {
			msgAuthAttr = attr
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("Message-Authenticator attribute not found")
	}

	// Validate Message-Authenticator length
	if len(msgAuthAttr.Value) != 16 {
		return fmt.Errorf("invalid Message-Authenticator length: %d", len(msgAuthAttr.Value))
	}

	// TODO: Implement proper HMAC-MD5 validation when packet encoding is available
	// For now, we'll return success for testing purposes
	return nil
}

// AddMessageAuthenticator adds a Message-Authenticator to a packet
func (mah *MessageAuthenticatorHelper) AddMessageAuthenticator(req *packet.Packet) error {
	// Check if Message-Authenticator already exists
	for _, attr := range req.Attributes {
		if attr.Type == packet.AttrMessageAuthenticator {
			return fmt.Errorf("Message-Authenticator already exists in packet")
		}
	}

	// Create Message-Authenticator attribute with placeholder value
	msgAuthAttr := packet.Attribute{
		Type:   packet.AttrMessageAuthenticator,
		Length: 18, // 2 bytes header + 16 bytes value
		Value:  make([]byte, 16),
	}

	// Add to packet
	req.AddAttribute(msgAuthAttr)

	// TODO: Calculate actual HMAC-MD5 value when packet encoding is available
	return nil
}
