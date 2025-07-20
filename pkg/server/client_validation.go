package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/packet"
)

// ClientValidationLevel defines the level of client validation
type ClientValidationLevel int

const (
	ClientValidationBasic ClientValidationLevel = iota
	ClientValidationStrict
	ClientValidationParanoid
)

// ClientValidationConfig configures client validation behavior
type ClientValidationConfig struct {
	Level                   ClientValidationLevel
	RequireSharedSecret     bool
	MinSharedSecretLength   int
	AllowedNASIdentifiers   []string
	RequiredNASIdentifier   bool
	AllowedNASIPAddresses   []net.IP
	AllowedNASIPNetworks    []*net.IPNet
	MaxRequestsPerSecond    int
	MaxConcurrentRequests   int
	SessionTimeout          time.Duration
	EnableNASValidation     bool
	RequireCallingStationID bool
	RequireCalledStationID  bool
	ValidateAcctSessionID   bool
}

// DefaultClientValidationConfig returns default client validation configuration
func DefaultClientValidationConfig() *ClientValidationConfig {
	return &ClientValidationConfig{
		Level:                   ClientValidationBasic,
		RequireSharedSecret:     true,
		MinSharedSecretLength:   8,
		RequiredNASIdentifier:   false,
		MaxRequestsPerSecond:    100,
		MaxConcurrentRequests:   1000,
		SessionTimeout:          time.Hour,
		EnableNASValidation:     true,
		RequireCallingStationID: false,
		RequireCalledStationID:  false,
		ValidateAcctSessionID:   false,
	}
}

// EnhancedClientValidator provides advanced client validation
type EnhancedClientValidator struct {
	config      *ClientValidationConfig
	rateLimiter *ClientRateLimiter
	sessions    sync.Map // map[string]*ClientSession
	// mu          sync.RWMutex // TODO: implement for thread safety
	ctx    context.Context
	cancel context.CancelFunc
}

// ClientSession tracks client session information
type ClientSession struct {
	ClientIP           net.IP
	LastSeen           time.Time
	RequestCount       int64
	ConcurrentRequests int32
	NASIdentifier      string
	SharedSecret       []byte
	CreatedAt          time.Time
	Attributes         map[string]interface{}
	mu                 sync.RWMutex
}

// NewEnhancedClientValidator creates a new enhanced client validator
func NewEnhancedClientValidator(config *ClientValidationConfig) *EnhancedClientValidator {
	if config == nil {
		config = DefaultClientValidationConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	validator := &EnhancedClientValidator{
		config:      config,
		rateLimiter: NewClientRateLimiter(config.MaxRequestsPerSecond),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start cleanup goroutine for expired sessions
	go validator.cleanupSessions()

	return validator
}

// ValidateClient performs comprehensive client validation
func (ecv *EnhancedClientValidator) ValidateClient(_ context.Context, clientCtx *ClientContext, req *packet.Packet) error {
	// Basic validation
	if err := ecv.validateBasic(clientCtx, req); err != nil {
		return fmt.Errorf("basic validation failed: %w", err)
	}

	// Rate limiting validation
	if err := ecv.validateRateLimit(clientCtx); err != nil {
		return fmt.Errorf("rate limit validation failed: %w", err)
	}

	// Strict validation
	if ecv.config.Level >= ClientValidationStrict {
		if err := ecv.validateStrict(clientCtx, req); err != nil {
			return fmt.Errorf("strict validation failed: %w", err)
		}
	}

	// Paranoid validation
	if ecv.config.Level >= ClientValidationParanoid {
		if err := ecv.validateParanoid(clientCtx, req); err != nil {
			return fmt.Errorf("paranoid validation failed: %w", err)
		}
	}

	// Update client session
	ecv.updateClientSession(clientCtx, req)

	return nil
}

// validateBasic performs basic client validation
func (ecv *EnhancedClientValidator) validateBasic(clientCtx *ClientContext, _ *packet.Packet) error {
	// Validate shared secret
	if ecv.config.RequireSharedSecret {
		if len(clientCtx.SharedSecret) == 0 {
			return fmt.Errorf("shared secret is required but not provided")
		}
		if len(clientCtx.SharedSecret) < ecv.config.MinSharedSecretLength {
			return fmt.Errorf("shared secret length %d is below minimum %d",
				len(clientCtx.SharedSecret), ecv.config.MinSharedSecretLength)
		}
	}

	// Validate client IP address
	if len(ecv.config.AllowedNASIPAddresses) > 0 {
		clientIP := getClientIP(clientCtx.RemoteAddr)
		allowed := false
		for _, allowedIP := range ecv.config.AllowedNASIPAddresses {
			if clientIP.Equal(allowedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("client IP %s is not in allowed list", clientIP)
		}
	}

	// Validate client IP networks
	if len(ecv.config.AllowedNASIPNetworks) > 0 {
		clientIP := getClientIP(clientCtx.RemoteAddr)
		allowed := false
		for _, network := range ecv.config.AllowedNASIPNetworks {
			if network.Contains(clientIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("client IP %s is not in allowed networks", clientIP)
		}
	}

	return nil
}

// validateStrict performs strict client validation
func (ecv *EnhancedClientValidator) validateStrict(_ *ClientContext, req *packet.Packet) error {
	// Validate NAS-Identifier if required
	if ecv.config.RequiredNASIdentifier || ecv.config.EnableNASValidation {
		nasID := getStringAttribute(req, packet.AttrNASIdentifier)
		if ecv.config.RequiredNASIdentifier && nasID == "" {
			return fmt.Errorf("NAS-Identifier is required but not present")
		}

		if nasID != "" && len(ecv.config.AllowedNASIdentifiers) > 0 {
			allowed := false
			for _, allowedNAS := range ecv.config.AllowedNASIdentifiers {
				if nasID == allowedNAS {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("NAS-Identifier %s is not allowed", nasID)
			}
		}
	}

	// Validate required attributes
	if ecv.config.RequireCallingStationID {
		if getStringAttribute(req, packet.AttrCallingStationID) == "" {
			return fmt.Errorf("Calling-Station-Id is required but not present")
		}
	}

	if ecv.config.RequireCalledStationID {
		if getStringAttribute(req, packet.AttrCalledStationID) == "" {
			return fmt.Errorf("Called-Station-Id is required but not present")
		}
	}

	return nil
}

// validateParanoid performs paranoid-level client validation
func (ecv *EnhancedClientValidator) validateParanoid(clientCtx *ClientContext, req *packet.Packet) error {
	// Validate Acct-Session-Id for accounting packets
	if ecv.config.ValidateAcctSessionID && req.Code == packet.CodeAccountingRequest {
		sessionID := getStringAttribute(req, packet.AttrAcctSessionID)
		if sessionID == "" {
			return fmt.Errorf("Acct-Session-Id is required for accounting requests")
		}

		// Validate session ID format (basic check for reasonable length and characters)
		if len(sessionID) < 8 || len(sessionID) > 64 {
			return fmt.Errorf("Acct-Session-Id length %d is not within acceptable range (8-64)", len(sessionID))
		}

		// Check for potentially malicious session IDs
		if strings.ContainsAny(sessionID, "\x00\r\n\t") {
			return fmt.Errorf("Acct-Session-Id contains invalid characters")
		}
	}

	// Validate User-Name format for authentication packets
	if req.Code == packet.CodeAccessRequest {
		userName := getStringAttribute(req, packet.AttrUserName)
		if userName != "" {
			// Basic validation for user name format
			if len(userName) > 253 {
				return fmt.Errorf("User-Name length %d exceeds maximum 253", len(userName))
			}

			// Check for null bytes and control characters
			if strings.ContainsAny(userName, "\x00\r\n\t") {
				return fmt.Errorf("User-Name contains invalid characters")
			}
		}
	}

	// Validate NAS-IP-Address consistency
	nasIP := getIPAttribute(req, packet.AttrNASIPAddress)
	if nasIP != nil {
		clientIP := getClientIP(clientCtx.RemoteAddr)
		if !nasIP.Equal(clientIP) {
			return fmt.Errorf("NAS-IP-Address %s does not match client IP %s", nasIP, clientIP)
		}
	}

	return nil
}

// validateRateLimit checks if client is within rate limits
func (ecv *EnhancedClientValidator) validateRateLimit(clientCtx *ClientContext) error {
	clientIP := getClientIP(clientCtx.RemoteAddr)

	if !ecv.rateLimiter.Allow(clientIP.String()) {
		return fmt.Errorf("rate limit exceeded for client %s", clientIP)
	}

	return nil
}

// updateClientSession updates or creates client session information
func (ecv *EnhancedClientValidator) updateClientSession(clientCtx *ClientContext, req *packet.Packet) {
	clientIP := getClientIP(clientCtx.RemoteAddr)
	sessionKey := clientIP.String()

	now := time.Now()

	if sessionValue, exists := ecv.sessions.Load(sessionKey); exists {
		if session, ok := sessionValue.(*ClientSession); ok {
			session.mu.Lock()
			session.LastSeen = now
			session.RequestCount++
			session.mu.Unlock()
		}
	} else {
		// Create new session
		session := &ClientSession{
			ClientIP:      clientIP,
			LastSeen:      now,
			RequestCount:  1,
			NASIdentifier: getStringAttribute(req, packet.AttrNASIdentifier),
			SharedSecret:  clientCtx.SharedSecret,
			CreatedAt:     now,
			Attributes:    make(map[string]interface{}),
		}
		ecv.sessions.Store(sessionKey, session)
	}
}

// cleanupSessions removes expired client sessions
func (ecv *EnhancedClientValidator) cleanupSessions() {
	ticker := time.NewTicker(time.Minute * 5) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ecv.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-ecv.config.SessionTimeout)

			ecv.sessions.Range(func(key, value interface{}) bool {
				if session, ok := value.(*ClientSession); ok {
					session.mu.RLock()
					expired := session.LastSeen.Before(cutoff)
					session.mu.RUnlock()

					if expired {
						ecv.sessions.Delete(key)
					}
				}
				return true
			})
		}
	}
}

// GetClientSession retrieves client session information
// Close stops the cleanup goroutines
func (ecv *EnhancedClientValidator) Close() {
	if ecv.cancel != nil {
		ecv.cancel()
	}
	if ecv.rateLimiter != nil {
		ecv.rateLimiter.Close()
	}
}

func (ecv *EnhancedClientValidator) GetClientSession(clientIP string) (*ClientSession, bool) {
	if sessionValue, exists := ecv.sessions.Load(clientIP); exists {
		if session, ok := sessionValue.(*ClientSession); ok {
			return session, true
		}
	}
	return nil, false
}

// EnhancedClientValidationMiddleware creates middleware for enhanced client validation
func EnhancedClientValidationMiddleware(validator *EnhancedClientValidator) MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Perform enhanced client validation
		if err := validator.ValidateClient(ctx, clientCtx, req); err != nil {
			return nil, NewHandlerError(ErrorCodeSecurityViolation, "client validation failed", err)
		}

		// Continue to next handler
		return next(ctx, clientCtx, req)
	}
}

// Helper function to extract client IP from remote address
func getClientIP(remoteAddr net.Addr) net.IP {
	switch addr := remoteAddr.(type) {
	case *net.UDPAddr:
		return addr.IP
	case *net.TCPAddr:
		return addr.IP
	default:
		// Try to parse as string
		if host, _, err := net.SplitHostPort(addr.String()); err == nil {
			return net.ParseIP(host)
		}
		return net.ParseIP(addr.String())
	}
}

// ClientRateLimiter provides rate limiting functionality
type ClientRateLimiter struct {
	maxRequests int
	window      time.Duration
	clients     sync.Map // map[string]*ClientLimitInfo
	// mu          sync.RWMutex // TODO: implement for thread safety
	ctx    context.Context
	cancel context.CancelFunc
}

// ClientLimitInfo tracks rate limit information for a client
type ClientLimitInfo struct {
	requests  []time.Time
	lastReset time.Time
	mu        sync.Mutex
}

// NewClientRateLimiter creates a new client rate limiter
func NewClientRateLimiter(maxRequestsPerSecond int) *ClientRateLimiter {
	ctx, cancel := context.WithCancel(context.Background())

	rl := &ClientRateLimiter{
		maxRequests: maxRequestsPerSecond,
		window:      time.Second,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request is allowed for the given client
func (rl *ClientRateLimiter) Allow(clientID string) bool {
	now := time.Now()

	clientInfoValue, _ := rl.clients.LoadOrStore(clientID, &ClientLimitInfo{
		requests:  make([]time.Time, 0, rl.maxRequests),
		lastReset: now,
	})

	clientInfo := clientInfoValue.(*ClientLimitInfo)
	clientInfo.mu.Lock()
	defer clientInfo.mu.Unlock()

	// Remove old requests outside the window
	cutoff := now.Add(-rl.window)
	validRequests := 0
	for i, reqTime := range clientInfo.requests {
		if reqTime.After(cutoff) {
			if validRequests != i {
				clientInfo.requests[validRequests] = reqTime
			}
			validRequests++
		}
	}
	clientInfo.requests = clientInfo.requests[:validRequests]

	// Check if we can allow this request
	if len(clientInfo.requests) >= rl.maxRequests {
		return false
	}

	// Add this request
	clientInfo.requests = append(clientInfo.requests, now)
	return true
}

// cleanup removes old client limit info entries
func (rl *ClientRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-time.Minute * 5)

			rl.clients.Range(func(key, value interface{}) bool {
				if clientInfo, ok := value.(*ClientLimitInfo); ok {
					clientInfo.mu.Lock()
					if clientInfo.lastReset.Before(cutoff) && len(clientInfo.requests) == 0 {
						rl.clients.Delete(key)
					}
					clientInfo.mu.Unlock()
				}
				return true
			})
		}
	}
}

// Close stops the cleanup goroutine
func (rl *ClientRateLimiter) Close() {
	if rl.cancel != nil {
		rl.cancel()
	}
}

// constantTimeCompare performs constant-time comparison to prevent timing attacks
func constantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Helper functions for packet attribute access

// getStringAttribute gets a string attribute from a packet
func getStringAttribute(req *packet.Packet, attrType uint8) string {
	if attr, exists := req.GetAttribute(attrType); exists {
		return attr.GetString()
	}
	return ""
}

// getIPAttribute gets an IP address attribute from a packet
func getIPAttribute(req *packet.Packet, attrType uint8) net.IP {
	if attr, exists := req.GetAttribute(attrType); exists {
		if ipBytes, err := attr.GetIPAddress(); err == nil {
			return net.IP(ipBytes[:])
		}
	}
	return nil
}
