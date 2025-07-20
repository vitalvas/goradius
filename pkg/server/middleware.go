package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/crypto"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// LoggingMiddleware provides request/response logging
func LoggingMiddleware(logger log.Logger) MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		start := time.Now()

		logger.Debugf("Processing request ID %d from %s: code=%d, id=%d",
			clientCtx.RequestID, clientCtx.Addr, req.Code, req.Identifier)

		result, err := next(ctx, clientCtx, req)

		duration := time.Since(start)

		switch {
		case err != nil:
			logger.Errorf("Request ID %d failed after %v: %v", clientCtx.RequestID, duration, err)
		case result != nil && result.Response != nil:
			logger.Debugf("Request ID %d completed after %v: response_code=%d",
				clientCtx.RequestID, duration, result.Response.Code)
		default:
			logger.Debugf("Request ID %d completed after %v: no response", clientCtx.RequestID, duration)
		}

		return result, err
	}
}

// RateLimitMiddleware provides rate limiting functionality
func RateLimitMiddleware(requestsPerSecond int, burstSize int) MiddlewareHandler {
	type clientLimiter struct {
		lastRequest time.Time
		tokens      int
		maxTokens   int
		refillRate  time.Duration
		mu          sync.Mutex
	}

	limiters := make(map[string]*clientLimiter)
	limitersMu := sync.RWMutex{}

	refillRate := time.Second / time.Duration(requestsPerSecond)

	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		clientKey := clientCtx.Addr.String()

		// Get or create limiter for this client
		limitersMu.Lock()
		limiter, exists := limiters[clientKey]
		if !exists {
			limiter = &clientLimiter{
				lastRequest: time.Now(),
				tokens:      burstSize,
				maxTokens:   burstSize,
				refillRate:  refillRate,
			}
			limiters[clientKey] = limiter
		}
		limitersMu.Unlock()

		// Check rate limit
		limiter.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(limiter.lastRequest)

		// Refill tokens based on elapsed time
		tokensToAdd := int(elapsed / limiter.refillRate)
		if tokensToAdd > 0 {
			limiter.tokens += tokensToAdd
			if limiter.tokens > limiter.maxTokens {
				limiter.tokens = limiter.maxTokens
			}
			limiter.lastRequest = now
		}

		// Check if we have tokens available
		if limiter.tokens <= 0 {
			limiter.mu.Unlock()
			return nil, NewHandlerError(ErrorCodeRateLimited,
				fmt.Sprintf("rate limit exceeded for client %s", clientKey), nil)
		}

		// Consume a token
		limiter.tokens--
		limiter.mu.Unlock()

		return next(ctx, clientCtx, req)
	}
}

// AuthenticationMiddleware provides basic authentication validation
func AuthenticationMiddleware() MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Only apply to authentication requests
		if req.Code != packet.CodeAccessRequest {
			return next(ctx, clientCtx, req)
		}

		// Authentication is no longer supported - reject all authentication requests
		return &HandlerResult{
			Response: NewResponseBuilder(uint8(packet.CodeAccessReject), req.Identifier).
				AddStringAttribute(packet.AttrReplyMessage, "Authentication is not supported - all authentication methods have been removed").
				Build(),
			Send: true,
		}, nil
	}
}

// SecurityMiddleware provides security validation
func SecurityMiddleware() MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Validate packet structure
		if err := validatePacketStructure(req); err != nil {
			return nil, NewHandlerError(ErrorCodeInvalidRequest, "invalid packet structure", err)
		}

		// Validate authenticator if it's a response
		if req.Code >= packet.CodeAccessAccept && req.Code <= packet.CodeAccountingResponse {
			if err := validateResponseAuthenticator(req, clientCtx.SharedSecret); err != nil {
				return nil, NewHandlerError(ErrorCodeInvalidRequest, "invalid response authenticator", err)
			}
		}

		// Validate Message-Authenticator if present
		if msgAuthAttr, found := req.GetAttribute(packet.AttrMessageAuthenticator); found {
			if err := validateMessageAuthenticator(req, msgAuthAttr, clientCtx.SharedSecret); err != nil {
				return nil, NewHandlerError(ErrorCodeInvalidRequest, "invalid Message-Authenticator", err)
			}
		}

		return next(ctx, clientCtx, req)
	}
}

// MetricsMiddleware provides request metrics collection
func MetricsMiddleware() MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		start := time.Now()

		// Execute next handler
		result, err := next(ctx, clientCtx, req)

		duration := time.Since(start)

		// Store metrics in client context
		if clientCtx.Attributes == nil {
			clientCtx.Attributes = make(map[string]interface{})
		}

		clientCtx.Attributes["processing_time"] = duration
		clientCtx.Attributes["request_code"] = req.Code

		if result != nil && result.Response != nil {
			clientCtx.Attributes["response_code"] = result.Response.Code
		}

		if err != nil {
			clientCtx.Attributes["error"] = err.Error()
		}

		return result, err
	}
}

// RecoveryMiddleware provides panic recovery
func RecoveryMiddleware(logger log.Logger) MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (result *HandlerResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Panic recovered in request ID %d from %s: %v",
					clientCtx.RequestID, clientCtx.Addr, r)

				// Create error response
				result = &HandlerResult{
					Response: NewResponseBuilder(uint8(packet.CodeAccessReject), req.Identifier).
						AddStringAttribute(packet.AttrReplyMessage, "Internal server error").
						Build(),
					Send:  true,
					Error: fmt.Errorf("panic recovered: %v", r),
				}
				err = NewHandlerError(ErrorCodeInternalError, "panic recovered", fmt.Errorf("%v", r))
			}
		}()

		return next(ctx, clientCtx, req)
	}
}

// Helper functions for validation

func validatePacketStructure(req *packet.Packet) error {
	// Basic packet validation
	if req.Length < packet.PacketHeaderLength {
		return fmt.Errorf("packet too short: %d bytes", req.Length)
	}

	if req.Length > 4096 {
		return fmt.Errorf("packet too long: %d bytes", req.Length)
	}

	// Validate attributes don't exceed packet length
	attributesLength := 0
	for _, attr := range req.Attributes {
		encoded, err := attr.Encode()
		if err == nil {
			attributesLength += len(encoded)
		}
	}

	if uint16(attributesLength) > req.Length-packet.PacketHeaderLength {
		return fmt.Errorf("attributes exceed packet length")
	}

	return nil
}

func validateResponseAuthenticator(_ *packet.Packet, sharedSecret []byte) error {
	// This is a simplified implementation
	// In a real implementation, this would validate the Response Authenticator
	// The authenticator is always [16]byte so no length check needed

	// TODO: Implement proper Response Authenticator validation using HMAC-MD5
	// For now, just validate that shared secret is not empty
	if len(sharedSecret) == 0 {
		return fmt.Errorf("shared secret cannot be empty")
	}

	return nil
}

func validateMessageAuthenticator(pkt *packet.Packet, msgAuthAttr packet.Attribute, sharedSecret []byte) error {
	// Validate Message-Authenticator length
	msgAuth := msgAuthAttr.Value
	if len(msgAuth) != 16 {
		return fmt.Errorf("invalid Message-Authenticator length: %d", len(msgAuth))
	}

	// Encode packet to get raw bytes
	packetData, err := pkt.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode packet: %w", err)
	}

	// Use the crypto package for proper HMAC-MD5 validation
	handler := crypto.NewMessageAuthenticatorHandler(sharedSecret)
	valid, err := handler.ValidatePacket(packetData)
	if err != nil {
		return fmt.Errorf("Message-Authenticator validation error: %w", err)
	}

	if !valid {
		return fmt.Errorf("Message-Authenticator validation failed")
	}

	return nil
}
