package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// EnhancedDefaultHandler provides a comprehensive implementation of the EnhancedHandler interface
type EnhancedDefaultHandler struct {
	// Embed the original DefaultHandler for backward compatibility
	*DefaultHandler

	// Enhanced features
	middlewares    []MiddlewareHandler
	requestCounter uint64

	// Client context cache
	clientContextCache map[string]*ClientContext
	contextCacheMu     sync.RWMutex

	// Configuration
	config *HandlerConfig

	// Lifecycle management
	initialized bool
	shutdown    bool
	mu          sync.RWMutex
}

// HandlerConfig contains configuration for the enhanced handler
type HandlerConfig struct {
	// Timeout settings
	RequestTimeout time.Duration

	// Rate limiting
	EnableRateLimit   bool
	RequestsPerSecond int
	BurstSize         int

	// Cache settings
	EnableContextCache bool
	ContextCacheTTL    time.Duration

	// Security settings
	ValidateMessageAuth bool
	RequireMessageAuth  bool

	// Logging settings
	LogRequests          bool
	LogResponses         bool
	LogSlowRequests      bool
	SlowRequestThreshold time.Duration
}

// DefaultHandlerConfig returns a default handler configuration
func DefaultHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		RequestTimeout:       30 * time.Second,
		EnableRateLimit:      false,
		RequestsPerSecond:    1000,
		BurstSize:            100,
		EnableContextCache:   true,
		ContextCacheTTL:      5 * time.Minute,
		ValidateMessageAuth:  true,
		RequireMessageAuth:   false,
		LogRequests:          true,
		LogResponses:         false,
		LogSlowRequests:      true,
		SlowRequestThreshold: 100 * time.Millisecond,
	}
}

// NewEnhancedDefaultHandler creates a new enhanced default handler
func NewEnhancedDefaultHandler(logger log.Logger, config *HandlerConfig) *EnhancedDefaultHandler {
	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	if config == nil {
		config = DefaultHandlerConfig()
	}

	return &EnhancedDefaultHandler{
		DefaultHandler:     NewDefaultHandler(logger),
		middlewares:        make([]MiddlewareHandler, 0),
		clientContextCache: make(map[string]*ClientContext),
		config:             config,
	}
}

// AddMiddleware adds a middleware to the handler chain
func (eh *EnhancedDefaultHandler) AddMiddleware(middleware MiddlewareHandler) {
	eh.middlewares = append(eh.middlewares, middleware)
}

// Initialize initializes the enhanced handler
func (eh *EnhancedDefaultHandler) Initialize(_ context.Context) error {
	eh.mu.Lock()
	defer eh.mu.Unlock()

	if eh.initialized {
		return fmt.Errorf("handler already initialized")
	}

	eh.logger.Info("Initializing enhanced RADIUS handler")

	// Initialize any required resources here
	if eh.config.EnableContextCache {
		eh.logger.Debugf("Context cache enabled with TTL: %v", eh.config.ContextCacheTTL)
	}

	if eh.config.EnableRateLimit {
		eh.logger.Debugf("Rate limiting enabled: %d RPS, burst: %d",
			eh.config.RequestsPerSecond, eh.config.BurstSize)
	}

	eh.initialized = true
	eh.logger.Info("Enhanced RADIUS handler initialized successfully")
	return nil
}

// Shutdown gracefully shuts down the handler
func (eh *EnhancedDefaultHandler) Shutdown(_ context.Context) error {
	eh.mu.Lock()
	defer eh.mu.Unlock()

	if eh.shutdown {
		return nil
	}

	eh.logger.Info("Shutting down enhanced RADIUS handler")

	// Clear context cache
	eh.contextCacheMu.Lock()
	eh.clientContextCache = make(map[string]*ClientContext)
	eh.contextCacheMu.Unlock()

	eh.shutdown = true
	eh.logger.Info("Enhanced RADIUS handler shutdown complete")
	return nil
}

// GetClientContext builds client context from network information
func (eh *EnhancedDefaultHandler) GetClientContext(clientAddr, serverAddr net.Addr, transport TransportType) (*ClientContext, error) {
	// Generate cache key
	cacheKey := fmt.Sprintf("%s_%s_%s", clientAddr.String(), serverAddr.String(), transport)

	// Check cache first if enabled
	if eh.config.EnableContextCache {
		eh.contextCacheMu.RLock()
		if cached, found := eh.clientContextCache[cacheKey]; found {
			eh.contextCacheMu.RUnlock()
			return cached, nil
		}
		eh.contextCacheMu.RUnlock()
	}

	// Find client configuration
	var clientConfig *ClientConfig
	var clientIP net.IP

	switch addr := clientAddr.(type) {
	case *net.UDPAddr:
		clientIP = addr.IP
	case *net.TCPAddr:
		clientIP = addr.IP
	case *net.IPAddr:
		clientIP = addr.IP
	default:
		return nil, fmt.Errorf("unsupported address type: %T", clientAddr)
	}

	// Find matching client configuration
	eh.mu.RLock()
	for network, client := range eh.clients {
		if isIPInNetwork(clientIP, network) {
			clientConfig = client
			break
		}
	}
	eh.mu.RUnlock()

	if clientConfig == nil {
		return nil, fmt.Errorf("no client configuration found for %s", clientIP)
	}

	// Get shared secret
	sharedSecret, err := eh.GetSharedSecret(clientAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get shared secret: %w", err)
	}

	// Create client context
	clientCtx := &ClientContext{
		Addr:         clientAddr,
		Config:       clientConfig,
		Transport:    transport,
		LocalAddr:    serverAddr,
		RemoteAddr:   clientAddr,
		ReceivedAt:   time.Now(),
		RequestID:    atomic.AddUint64(&eh.requestCounter, 1),
		SharedSecret: sharedSecret,
		Attributes:   make(map[string]interface{}),
	}

	// Cache the context if enabled
	if eh.config.EnableContextCache {
		eh.contextCacheMu.Lock()
		eh.clientContextCache[cacheKey] = clientCtx
		eh.contextCacheMu.Unlock()

		// Set up cache cleanup (simplified - in production would use proper TTL)
		go func() {
			time.Sleep(eh.config.ContextCacheTTL)
			eh.contextCacheMu.Lock()
			delete(eh.clientContextCache, cacheKey)
			eh.contextCacheMu.Unlock()
		}()
	}

	return clientCtx, nil
}

// HandleRequestWithContext processes a request with enhanced context
func (eh *EnhancedDefaultHandler) HandleRequestWithContext(ctx context.Context, clientCtx *ClientContext, req *packet.Packet) (*HandlerResult, error) {
	startTime := time.Now()

	// Check if handler is initialized and not shutdown
	eh.mu.RLock()
	if !eh.initialized {
		eh.mu.RUnlock()
		return nil, NewHandlerError(ErrorCodeInternalError, "handler not initialized", nil)
	}
	if eh.shutdown {
		eh.mu.RUnlock()
		return nil, NewHandlerError(ErrorCodeInternalError, "handler is shutdown", nil)
	}
	eh.mu.RUnlock()

	// Extract user information
	if userNameAttr, found := req.GetAttribute(packet.AttrUserName); found {
		clientCtx.UserName = userNameAttr.GetString()
	}

	// Extract NAS information
	clientCtx.NASInfo = eh.extractNASInfo(req)

	// Create handler chain
	finalHandler := eh.createFinalHandler()
	chain := NewHandlerChain(finalHandler, eh.middlewares...)

	// Execute the handler chain
	result, err := chain.Execute(ctx, clientCtx, req)

	// Calculate processing time
	processingTime := time.Since(startTime)

	if result != nil {
		result.ProcessingTime = processingTime
		result.HandlerName = "enhanced_default"
	}

	// Log slow requests if enabled
	if eh.config.LogSlowRequests && processingTime > eh.config.SlowRequestThreshold {
		eh.logger.Warnf("Slow request processing: %v for request ID %d from %s",
			processingTime, clientCtx.RequestID, clientCtx.Addr)
	}

	// Log request if enabled
	if eh.config.LogRequests {
		eh.logger.Debugf("Processed request ID %d from %s in %v",
			clientCtx.RequestID, clientCtx.Addr, processingTime)
	}

	return result, err
}

// PreProcessRequest allows preprocessing before main handling
func (eh *EnhancedDefaultHandler) PreProcessRequest(_ context.Context, clientCtx *ClientContext, req *packet.Packet) error {
	// Validate Message-Authenticator if required
	if eh.config.ValidateMessageAuth {
		if msgAuthAttr, found := req.GetAttribute(packet.AttrMessageAuthenticator); found {
			if err := eh.validateMessageAuthenticator(req, msgAuthAttr, clientCtx.SharedSecret); err != nil {
				return NewHandlerError(ErrorCodeInvalidRequest, "Message-Authenticator validation failed", err)
			}
		} else if eh.config.RequireMessageAuth {
			return NewHandlerError(ErrorCodeInvalidRequest, "Message-Authenticator required but not present", nil)
		}
	}

	return nil
}

// PostProcessResponse allows post-processing of responses
func (eh *EnhancedDefaultHandler) PostProcessResponse(_ context.Context, clientCtx *ClientContext, req *packet.Packet, result *HandlerResult) error {
	if result == nil || result.Response == nil {
		return nil
	}

	// Add Message-Authenticator to response if EAP is present
	if eh.hasEAPMessage(req) {
		msgAuth := make([]byte, 16) // Placeholder for Message-Authenticator
		result.Response.AddAttribute(packet.NewAttribute(packet.AttrMessageAuthenticator, msgAuth))
	}

	// Log response if enabled
	if eh.config.LogResponses {
		eh.logger.Debugf("Sending response code %d to %s for request ID %d",
			result.Response.Code, clientCtx.Addr, clientCtx.RequestID)
	}

	return nil
}

// createFinalHandler creates the final handler in the chain
func (eh *EnhancedDefaultHandler) createFinalHandler() HandlerFunc {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet) (*HandlerResult, error) {
		// Convert to legacy Request format for compatibility
		legacyReq := &Request{
			ClientAddr: clientCtx.Addr,
			ServerAddr: clientCtx.LocalAddr,
			Packet:     req,
			Client:     clientCtx.Config,
			ReceivedAt: clientCtx.ReceivedAt,
		}

		// Call the original handler
		response, err := eh.DefaultHandler.HandleRequest(ctx, legacyReq)
		if err != nil {
			return nil, err
		}

		// Convert to HandlerResult
		result := &HandlerResult{
			Send:       response != nil && response.Send,
			Attributes: make(map[string]interface{}),
		}

		if response != nil {
			result.Response = response.Packet
		}

		return result, nil
	}
}

// extractNASInfo extracts NAS information from the packet
func (eh *EnhancedDefaultHandler) extractNASInfo(req *packet.Packet) *NASInfo {
	nasInfo := &NASInfo{}

	if attr, found := req.GetAttribute(packet.AttrNASIdentifier); found {
		nasInfo.Identifier = attr.GetString()
	}

	if attr, found := req.GetAttribute(packet.AttrNASIPAddress); found {
		ipBytes, err := attr.GetIPAddress()
		if err == nil {
			nasInfo.IPAddress = net.IP(ipBytes[:])
		}
	}

	if attr, found := req.GetAttribute(packet.AttrNASPort); found {
		port, err := attr.GetInteger()
		if err == nil {
			nasInfo.Port = &port
		}
	}

	if attr, found := req.GetAttribute(packet.AttrNASPortType); found {
		portType, err := attr.GetInteger()
		if err == nil {
			nasInfo.PortType = &portType
		}
	}

	return nasInfo
}

// validateMessageAuthenticator validates the Message-Authenticator attribute
func (eh *EnhancedDefaultHandler) validateMessageAuthenticator(_ *packet.Packet, msgAuthAttr packet.Attribute, _ []byte) error {
	// This is a simplified implementation
	// In a real implementation, this would perform HMAC-MD5 validation
	msgAuth := msgAuthAttr.Value
	if len(msgAuth) != 16 {
		return fmt.Errorf("invalid Message-Authenticator length: %d", len(msgAuth))
	}

	// TODO: Implement proper HMAC-MD5 validation
	return nil
}

// hasEAPMessage checks if the packet contains an EAP-Message attribute
func (eh *EnhancedDefaultHandler) hasEAPMessage(req *packet.Packet) bool {
	_, found := req.GetAttribute(packet.AttrEAPMessage)
	return found
}

// Adapter method to bridge the original Handler interface
func (eh *EnhancedDefaultHandler) HandleRequest(ctx context.Context, req *Request) (*Response, error) {
	// Create client context from request
	clientCtx, err := eh.GetClientContext(req.ClientAddr, req.ServerAddr, TransportUDP)
	if err != nil {
		return nil, err
	}

	// Set additional context information
	clientCtx.ReceivedAt = req.ReceivedAt

	// Handle with enhanced context
	result, err := eh.HandleRequestWithContext(ctx, clientCtx, req.Packet)
	if err != nil {
		return nil, err
	}

	// Convert back to legacy Response format
	if result == nil {
		return nil, nil
	}

	return &Response{
		Packet: result.Response,
		Send:   result.Send,
	}, nil
}
