# Examples and Tutorials

This guide provides practical examples and step-by-step tutorials for common RADIUS use cases.

## Basic Examples

### Simple Authentication Server

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/vitalvas/goradius/pkg/server"
    "github.com/vitalvas/goradius/pkg/packet"
)

type SimpleSecretProvider struct {
    secrets map[string]string
}

func (sp *SimpleSecretProvider) GetSecret(clientIP string) (string, error) {
    secret, exists := sp.secrets[clientIP]
    if !exists {
        return "", fmt.Errorf("no secret for client: %s", clientIP)
    }
    return secret, nil
}

type SimpleAuthHandler struct {
    users map[string]string
}

func NewSimpleAuthHandler() *SimpleAuthHandler {
    return &SimpleAuthHandler{
        users: map[string]string{
            "alice":   "password123",
            "bob":     "secret456",
            "charlie": "mypass789",
        },
    }
}

func (h *SimpleAuthHandler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    switch req.Code {
    case packet.CodeAccessRequest:
        return h.handleAuth(ctx, req)
    default:
        return nil, fmt.Errorf("unsupported packet type: %v", req.Code)
    }
}

func (h *SimpleAuthHandler) handleAuth(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    // Extract username
    username, ok := req.GetStringAttribute(packet.AttributeUserName)
    if !ok {
        log.Printf("Missing username in request")
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Extract password
    password, ok := req.GetStringAttribute(packet.AttributeUserPassword)
    if !ok {
        log.Printf("Missing password in request")
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Validate credentials
    expectedPassword, exists := h.users[username]
    if !exists || expectedPassword != password {
        log.Printf("Authentication failed for user: %s", username)
        resp := packet.New(packet.CodeAccessReject, req.Identifier)
        resp.AddStringAttribute(packet.AttributeReplyMessage, "Invalid credentials")
        return resp, nil
    }

    // Authentication successful
    log.Printf("Authentication successful for user: %s", username)
    resp := packet.New(packet.CodeAccessAccept, req.Identifier)
    resp.AddStringAttribute(packet.AttributeReplyMessage, "Welcome!")
    resp.AddIntegerAttribute(packet.AttributeSessionTimeout, 3600)
    
    return resp, nil
}

func main() {
    // Create secret provider
    secretProvider := &SimpleSecretProvider{
        secrets: map[string]string{
            "127.0.0.1": "testing123", // Allow localhost for testing
        },
    }

    // Create server configuration
    config := &server.Config{
        Bindings: []server.Binding{
            {
                Network: "udp",
                Address: ":1812",
            },
        },
        SecretProvider: secretProvider,
        ReadTimeout:    time.Second * 30,
        WriteTimeout:   time.Second * 30,
        MaxRequestSize: 4096,
    }

    // Create server
    srv, err := server.New(config, NewSimpleAuthHandler())
    if err != nil {
        log.Fatal("Failed to create server:", err)
    }

    // Start server
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    go func() {
        if err := srv.Start(ctx); err != nil {
            log.Fatal("Server failed:", err)
        }
    }()

    log.Println("RADIUS server started on :1812")

    // Wait for interrupt signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan

    log.Println("Shutting down server...")
    cancel()
}
```

### Simple Client Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/vitalvas/goradius/pkg/client"
    "github.com/vitalvas/goradius/pkg/packet"
)

func main() {
    // Create client configuration
    config := &client.Config{
        Servers: []client.ServerConfig{
            {
                Address: "localhost:1812",
                Secret:  "testing123",
            },
        },
        Transport: client.TransportUDP,
        Timeout:   time.Second * 5,
    }

    // Create client
    c, err := client.New(config)
    if err != nil {
        log.Fatal("Failed to create client:", err)
    }
    defer c.Close()

    // Test authentication
    users := []struct {
        username, password string
    }{
        {"alice", "password123"},
        {"bob", "secret456"},
        {"invalid", "wrongpass"},
    }

    for _, user := range users {
        fmt.Printf("\nTesting authentication for user: %s\n", user.username)
        
        req := packet.New(packet.CodeAccessRequest, 1)
        req.AddStringAttribute(packet.AttributeUserName, user.username)
        req.AddStringAttribute(packet.AttributeUserPassword, user.password)
        req.AddStringAttribute(packet.AttributeNASIdentifier, "test-nas")

        resp, err := c.SendRequest(context.Background(), req)
        if err != nil {
            fmt.Printf("Request failed: %v\n", err)
            continue
        }

        switch resp.Code {
        case packet.CodeAccessAccept:
            fmt.Println("✓ Authentication successful")
            if replyMsg, ok := resp.GetStringAttribute(packet.AttributeReplyMessage); ok {
                fmt.Printf("  Reply: %s\n", replyMsg)
            }
        case packet.CodeAccessReject:
            fmt.Println("✗ Authentication failed")
            if replyMsg, ok := resp.GetStringAttribute(packet.AttributeReplyMessage); ok {
                fmt.Printf("  Reply: %s\n", replyMsg)
            }
        default:
            fmt.Printf("Unexpected response: %v\n", resp.Code)
        }
    }
}
```

## Intermediate Examples

### RADIUS Server with Database Integration

```go
package main

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "time"

    _ "github.com/lib/pq"
    "github.com/vitalvas/goradius/pkg/server"
    "github.com/vitalvas/goradius/pkg/packet"
)

type DatabaseAuthHandler struct {
    db *sql.DB
}

func NewDatabaseAuthHandler(dbURL string) (*DatabaseAuthHandler, error) {
    db, err := sql.Open("postgres", dbURL)
    if err != nil {
        return nil, err
    }
    
    if err := db.Ping(); err != nil {
        return nil, err
    }
    
    return &DatabaseAuthHandler{db: db}, nil
}

func (h *DatabaseAuthHandler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    switch req.Code {
    case packet.CodeAccessRequest:
        return h.handleAuth(ctx, req)
    case packet.CodeAccountingRequest:
        return h.handleAccounting(ctx, req)
    default:
        return nil, fmt.Errorf("unsupported packet type: %v", req.Code)
    }
}

func (h *DatabaseAuthHandler) handleAuth(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    username, ok := req.GetStringAttribute(packet.AttributeUserName)
    if !ok {
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    password, ok := req.GetStringAttribute(packet.AttributeUserPassword)
    if !ok {
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Query database for user
    var storedPassword string
    var active bool
    var sessionTimeout int

    query := `
        SELECT password, active, session_timeout 
        FROM users 
        WHERE username = $1
    `
    
    err := h.db.QueryRowContext(ctx, query, username).Scan(&storedPassword, &active, &sessionTimeout)
    if err == sql.ErrNoRows {
        log.Printf("User not found: %s", username)
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }
    if err != nil {
        log.Printf("Database error: %v", err)
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Check if user is active
    if !active {
        log.Printf("User account disabled: %s", username)
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Validate password
    if password != storedPassword {
        log.Printf("Invalid password for user: %s", username)
        h.logAuthAttempt(ctx, username, false)
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Authentication successful
    log.Printf("Authentication successful for user: %s", username)
    h.logAuthAttempt(ctx, username, true)

    resp := packet.New(packet.CodeAccessAccept, req.Identifier)
    resp.AddIntegerAttribute(packet.AttributeSessionTimeout, sessionTimeout)
    
    return resp, nil
}

func (h *DatabaseAuthHandler) handleAccounting(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    statusType, ok := req.GetIntegerAttribute(packet.AttributeAcctStatusType)
    if !ok {
        return nil, fmt.Errorf("missing accounting status type")
    }

    sessionID, ok := req.GetStringAttribute(packet.AttributeAcctSessionID)
    if !ok {
        return nil, fmt.Errorf("missing session ID")
    }

    username, _ := req.GetStringAttribute(packet.AttributeUserName)

    switch statusType {
    case 1: // Start
        h.recordAccountingStart(ctx, sessionID, username, req)
    case 2: // Stop
        h.recordAccountingStop(ctx, sessionID, req)
    case 3: // Interim-Update
        h.recordAccountingUpdate(ctx, sessionID, req)
    }

    return packet.New(packet.CodeAccountingResponse, req.Identifier), nil
}

func (h *DatabaseAuthHandler) logAuthAttempt(ctx context.Context, username string, success bool) {
    query := `
        INSERT INTO auth_log (username, success, timestamp)
        VALUES ($1, $2, $3)
    `
    _, err := h.db.ExecContext(ctx, query, username, success, time.Now())
    if err != nil {
        log.Printf("Failed to log auth attempt: %v", err)
    }
}

func (h *DatabaseAuthHandler) recordAccountingStart(ctx context.Context, sessionID, username string, req *packet.Packet) {
    nasIP, _ := req.GetIPAttribute(packet.AttributeNASIPAddress)
    nasPort, _ := req.GetIntegerAttribute(packet.AttributeNASPort)

    query := `
        INSERT INTO accounting_sessions (session_id, username, nas_ip, nas_port, start_time)
        VALUES ($1, $2, $3, $4, $5)
    `
    _, err := h.db.ExecContext(ctx, query, sessionID, username, nasIP.String(), nasPort, time.Now())
    if err != nil {
        log.Printf("Failed to record accounting start: %v", err)
    }
}

func (h *DatabaseAuthHandler) recordAccountingStop(ctx context.Context, sessionID string, req *packet.Packet) {
    inputOctets, _ := req.GetIntegerAttribute(packet.AttributeAcctInputOctets)
    outputOctets, _ := req.GetIntegerAttribute(packet.AttributeAcctOutputOctets)
    sessionTime, _ := req.GetIntegerAttribute(packet.AttributeAcctSessionTime)

    query := `
        UPDATE accounting_sessions 
        SET stop_time = $1, input_octets = $2, output_octets = $3, session_time = $4
        WHERE session_id = $5
    `
    _, err := h.db.ExecContext(ctx, query, time.Now(), inputOctets, outputOctets, sessionTime, sessionID)
    if err != nil {
        log.Printf("Failed to record accounting stop: %v", err)
    }
}
```

### Client with Failover and Retry Logic

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/vitalvas/goradius/pkg/client"
    "github.com/vitalvas/goradius/pkg/packet"
)

type HighAvailabilityClient struct {
    client client.Client
}

func NewHighAvailabilityClient() (*HighAvailabilityClient, error) {
    config := &client.Config{
        Servers: []client.ServerConfig{
            {
                Address: "radius1.example.com:1812",
                Secret:  "secret1",
                Weight:  10, // Primary server
            },
            {
                Address: "radius2.example.com:1812",
                Secret:  "secret2",
                Weight:  5, // Secondary server
            },
            {
                Address: "radius3.example.com:1812",
                Secret:  "secret3",
                Weight:  1, // Backup server
            },
        },
        Transport:           client.TransportUDP,
        Timeout:            time.Second * 3,
        MaxRetries:         2,
        RetryInterval:      time.Second * 1,
        FailoverTimeout:    time.Second * 10,
        HealthCheckInterval: time.Minute * 2,
    }

    c, err := client.New(config)
    if err != nil {
        return nil, err
    }

    return &HighAvailabilityClient{client: c}, nil
}

func (hac *HighAvailabilityClient) Authenticate(username, password string) (*AuthResult, error) {
    req := packet.New(packet.CodeAccessRequest, 1)
    req.AddStringAttribute(packet.AttributeUserName, username)
    req.AddStringAttribute(packet.AttributeUserPassword, password)
    req.AddStringAttribute(packet.AttributeNASIdentifier, "ha-client")

    // Use context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
    defer cancel()

    // Send with automatic retry and failover
    resp, err := hac.client.SendRequestWithRetry(ctx, req, 3)
    if err != nil {
        return &AuthResult{
            Success: false,
            Error:   err,
        }, err
    }

    result := &AuthResult{
        Username: username,
        Response: resp,
    }

    switch resp.Code {
    case packet.CodeAccessAccept:
        result.Success = true
        if timeout, ok := resp.GetIntegerAttribute(packet.AttributeSessionTimeout); ok {
            result.SessionTimeout = timeout
        }
        if replyMsg, ok := resp.GetStringAttribute(packet.AttributeReplyMessage); ok {
            result.ReplyMessage = replyMsg
        }
    case packet.CodeAccessReject:
        result.Success = false
        if replyMsg, ok := resp.GetStringAttribute(packet.AttributeReplyMessage); ok {
            result.ReplyMessage = replyMsg
        }
    case packet.CodeAccessChallenge:
        result.Challenge = true
        if challengeMsg, ok := resp.GetStringAttribute(packet.AttributeReplyMessage); ok {
            result.ChallengeMessage = challengeMsg
        }
        if state, ok := resp.GetBytesAttribute(packet.AttributeState); ok {
            result.State = state
        }
    }

    return result, nil
}

type AuthResult struct {
    Success          bool
    Challenge        bool
    Username         string
    SessionTimeout   int
    ReplyMessage     string
    ChallengeMessage string
    State            []byte
    Response         *packet.Packet
    Error            error
}

func (hac *HighAvailabilityClient) Close() error {
    return hac.client.Close()
}

func main() {
    client, err := NewHighAvailabilityClient()
    if err != nil {
        log.Fatal("Failed to create client:", err)
    }
    defer client.Close()

    // Test multiple authentication attempts
    testUsers := []struct {
        username, password string
    }{
        {"user1", "pass1"},
        {"user2", "pass2"},
        {"user3", "pass3"},
    }

    for _, user := range testUsers {
        fmt.Printf("Authenticating user: %s\n", user.username)
        
        result, err := client.Authenticate(user.username, user.password)
        if err != nil {
            fmt.Printf("Authentication error: %v\n", err)
            continue
        }

        if result.Success {
            fmt.Printf("✓ Authentication successful, session timeout: %d\n", result.SessionTimeout)
        } else if result.Challenge {
            fmt.Printf("? Challenge required: %s\n", result.ChallengeMessage)
        } else {
            fmt.Printf("✗ Authentication failed: %s\n", result.ReplyMessage)
        }
    }
}
```

## Advanced Examples

### RADIUS Proxy Server

```go
package main

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"

    "github.com/vitalvas/goradius/pkg/server"
    "github.com/vitalvas/goradius/pkg/client"
    "github.com/vitalvas/goradius/pkg/packet"
)

type ProxyHandler struct {
    upstreamClients map[string]client.Client
    mutex           sync.RWMutex
}

func NewProxyHandler() *ProxyHandler {
    return &ProxyHandler{
        upstreamClients: make(map[string]client.Client),
    }
}

func (p *ProxyHandler) AddUpstream(name, address, secret string) error {
    config := &client.Config{
        Servers: []client.ServerConfig{
            {
                Address: address,
                Secret:  secret,
            },
        },
        Transport: client.TransportUDP,
        Timeout:   time.Second * 5,
    }

    c, err := client.New(config)
    if err != nil {
        return err
    }

    p.mutex.Lock()
    p.upstreamClients[name] = c
    p.mutex.Unlock()

    return nil
}

func (p *ProxyHandler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    // Determine which upstream server to use
    upstream := p.selectUpstream(req)
    if upstream == "" {
        log.Printf("No upstream server available")
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    p.mutex.RLock()
    client, exists := p.upstreamClients[upstream]
    p.mutex.RUnlock()

    if !exists {
        log.Printf("Upstream server not found: %s", upstream)
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Forward request to upstream
    log.Printf("Forwarding request to upstream: %s", upstream)
    resp, err := client.SendRequest(ctx, req)
    if err != nil {
        log.Printf("Upstream request failed: %v", err)
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    return resp, nil
}

func (p *ProxyHandler) selectUpstream(req *packet.Packet) string {
    // Simple realm-based routing
    username, ok := req.GetStringAttribute(packet.AttributeUserName)
    if !ok {
        return "default"
    }

    // Extract realm from username (user@realm.com)
    if idx := strings.LastIndex(username, "@"); idx != -1 {
        realm := username[idx+1:]
        switch realm {
        case "company.com":
            return "corporate"
        case "guest.com":
            return "guest"
        default:
            return "default"
        }
    }

    return "default"
}

func main() {
    proxy := NewProxyHandler()
    
    // Add upstream servers
    proxy.AddUpstream("corporate", "corp-radius.company.com:1812", "corp-secret")
    proxy.AddUpstream("guest", "guest-radius.company.com:1812", "guest-secret")
    proxy.AddUpstream("default", "main-radius.company.com:1812", "main-secret")

    secretProvider := &SimpleSecretProvider{
        secrets: map[string]string{
            "192.168.1.0/24": "proxy-secret", // Example network range
        },
    }

    config := &server.Config{
        Bindings: []server.Binding{
            {
                Network: "udp",
                Address: ":1812",
            },
        },
        SecretProvider: secretProvider,
    }

    srv, err := server.New(config, proxy)
    if err != nil {
        log.Fatal("Failed to create proxy server:", err)
    }

    ctx := context.Background()
    if err := srv.Start(ctx); err != nil {
        log.Fatal("Proxy server failed:", err)
    }
}
```

### RADIUS Server with Middleware Chain

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/vitalvas/goradius/pkg/server"
    "github.com/vitalvas/goradius/pkg/packet"
)

// Middleware interface
type Middleware func(server.Handler) server.Handler

// Logging middleware
func LoggingMiddleware() Middleware {
    return func(next server.Handler) server.Handler {
        return server.HandlerFunc(func(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
            start := time.Now()
            clientIP := getClientIP(ctx)
            
            log.Printf("Request: %v from %s (ID: %d)", req.Code, clientIP, req.Identifier)
            
            resp, err := next.HandleRequest(ctx, req)
            
            duration := time.Since(start)
            if err != nil {
                log.Printf("Request failed: %v (duration: %v)", err, duration)
            } else {
                log.Printf("Response: %v (duration: %v)", resp.Code, duration)
            }
            
            return resp, err
        })
    }
}

// Rate limiting middleware
func RateLimitMiddleware(limit int, window time.Duration) Middleware {
    limiter := NewRateLimiter(limit, window)
    
    return func(next server.Handler) server.Handler {
        return server.HandlerFunc(func(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
            clientIP := getClientIP(ctx)
            
            if !limiter.Allow(clientIP) {
                log.Printf("Rate limit exceeded for client: %s", clientIP)
                return packet.New(packet.CodeAccessReject, req.Identifier), nil
            }
            
            return next.HandleRequest(ctx, req)
        })
    }
}

// Authentication validation middleware
func AuthValidationMiddleware() Middleware {
    return func(next server.Handler) server.Handler {
        return server.HandlerFunc(func(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
            if req.Code == packet.CodeAccessRequest {
                // Validate required attributes
                if _, ok := req.GetStringAttribute(packet.AttributeUserName); !ok {
                    log.Printf("Missing username in authentication request")
                    return packet.New(packet.CodeAccessReject, req.Identifier), nil
                }
                
                if _, ok := req.GetStringAttribute(packet.AttributeUserPassword); !ok {
                    if _, ok := req.GetBytesAttribute(packet.AttributeCHAPPassword); !ok {
                        log.Printf("Missing password in authentication request")
                        return packet.New(packet.CodeAccessReject, req.Identifier), nil
                    }
                }
            }
            
            return next.HandleRequest(ctx, req)
        })
    }
}

// Chain middleware helper
func ChainMiddleware(middlewares ...Middleware) Middleware {
    return func(final server.Handler) server.Handler {
        for i := len(middlewares) - 1; i >= 0; i-- {
            final = middlewares[i](final)
        }
        return final
    }
}

// Core authentication handler
type CoreAuthHandler struct {
    users map[string]string
}

func (h *CoreAuthHandler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    username, _ := req.GetStringAttribute(packet.AttributeUserName)
    password, _ := req.GetStringAttribute(packet.AttributeUserPassword)
    
    if expectedPass, exists := h.users[username]; exists && expectedPass == password {
        resp := packet.New(packet.CodeAccessAccept, req.Identifier)
        resp.AddStringAttribute(packet.AttributeReplyMessage, "Welcome!")
        return resp, nil
    }
    
    return packet.New(packet.CodeAccessReject, req.Identifier), nil
}

func main() {
    // Create core handler
    coreHandler := &CoreAuthHandler{
        users: map[string]string{
            "alice": "password123",
            "bob":   "secret456",
        },
    }
    
    // Build middleware chain
    middlewareChain := ChainMiddleware(
        LoggingMiddleware(),
        RateLimitMiddleware(10, time.Minute),
        AuthValidationMiddleware(),
    )
    
    // Apply middleware to handler
    finalHandler := middlewareChain(coreHandler)
    
    secretProvider := &SimpleSecretProvider{
        secrets: map[string]string{
            "127.0.0.1": "testing123",
        },
    }

    config := &server.Config{
        Bindings: []server.Binding{
            {
                Network: "udp",
                Address: ":1812",
            },
        },
        SecretProvider: secretProvider,
    }
    
    srv, err := server.New(config, finalHandler)
    if err != nil {
        log.Fatal("Failed to create server:", err)
    }
    
    ctx := context.Background()
    if err := srv.Start(ctx); err != nil {
        log.Fatal("Server failed:", err)
    }
}
```

## Testing Examples

### Integration Test Suite

```go
package main

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/vitalvas/goradius/pkg/server"
    "github.com/vitalvas/goradius/pkg/client"
    "github.com/vitalvas/goradius/pkg/packet"
)

func TestRADIUSIntegration(t *testing.T) {
    // Start test server
    srv := startTestServer(t)
    defer srv.Close()
    
    // Create test client
    c := createTestClient(t, srv.Address())
    defer c.Close()
    
    t.Run("SuccessfulAuthentication", func(t *testing.T) {
        req := packet.New(packet.CodeAccessRequest, 1)
        req.AddStringAttribute(packet.AttributeUserName, "testuser")
        req.AddStringAttribute(packet.AttributeUserPassword, "testpass")
        
        resp, err := c.SendRequest(context.Background(), req)
        require.NoError(t, err)
        assert.Equal(t, packet.CodeAccessAccept, resp.Code)
    })
    
    t.Run("FailedAuthentication", func(t *testing.T) {
        req := packet.New(packet.CodeAccessRequest, 2)
        req.AddStringAttribute(packet.AttributeUserName, "testuser")
        req.AddStringAttribute(packet.AttributeUserPassword, "wrongpass")
        
        resp, err := c.SendRequest(context.Background(), req)
        require.NoError(t, err)
        assert.Equal(t, packet.CodeAccessReject, resp.Code)
    })
    
    t.Run("Accounting", func(t *testing.T) {
        sessionID := "test-session-123"
        
        // Start accounting
        startReq := packet.New(packet.CodeAccountingRequest, 3)
        startReq.AddIntegerAttribute(packet.AttributeAcctStatusType, 1) // Start
        startReq.AddStringAttribute(packet.AttributeAcctSessionID, sessionID)
        startReq.AddStringAttribute(packet.AttributeUserName, "testuser")
        
        startResp, err := c.SendRequest(context.Background(), startReq)
        require.NoError(t, err)
        assert.Equal(t, packet.CodeAccountingResponse, startResp.Code)
        
        // Stop accounting
        stopReq := packet.New(packet.CodeAccountingRequest, 4)
        stopReq.AddIntegerAttribute(packet.AttributeAcctStatusType, 2) // Stop
        stopReq.AddStringAttribute(packet.AttributeAcctSessionID, sessionID)
        stopReq.AddIntegerAttribute(packet.AttributeAcctSessionTime, 3600)
        
        stopResp, err := c.SendRequest(context.Background(), stopReq)
        require.NoError(t, err)
        assert.Equal(t, packet.CodeAccountingResponse, stopResp.Code)
    })
}

func startTestServer(t *testing.T) *TestServer {
    handler := &TestHandler{
        users: map[string]string{
            "testuser": "testpass",
        },
    }
    
    secretProvider := &SimpleSecretProvider{
        secrets: map[string]string{
            "127.0.0.1": "testing123",
        },
    }
    
    config := &server.Config{
        Bindings: []server.Binding{
            {
                Network: "udp",
                Address: ":0", // Use random port
            },
        },
        SecretProvider: secretProvider,
    }
    
    srv, err := server.New(config, handler)
    require.NoError(t, err)
    
    ctx, cancel := context.WithCancel(context.Background())
    
    go func() {
        srv.Start(ctx)
    }()
    
    // Wait for server to start
    time.Sleep(100 * time.Millisecond)
    
    return &TestServer{
        server: srv,
        cancel: cancel,
    }
}

type TestServer struct {
    server server.Server
    cancel context.CancelFunc
}

func (ts *TestServer) Address() string {
    return ts.server.GetAddress()
}

func (ts *TestServer) Close() {
    ts.cancel()
}

func createTestClient(t *testing.T, serverAddr string) client.Client {
    config := &client.Config{
        Servers: []client.ServerConfig{
            {
                Address: serverAddr,
                Secret:  "testing123",
            },
        },
        Transport: client.TransportUDP,
        Timeout:   time.Second * 5,
    }
    
    c, err := client.New(config)
    require.NoError(t, err)
    
    return c
}
```

### Benchmark Tests

```go
func BenchmarkRADIUSAuthentication(b *testing.B) {
    srv := startTestServer(b)
    defer srv.Close()
    
    c := createTestClient(b, srv.Address())
    defer c.Close()
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        identifier := uint8(1)
        for pb.Next() {
            req := packet.New(packet.CodeAccessRequest, identifier)
            req.AddStringAttribute(packet.AttributeUserName, "testuser")
            req.AddStringAttribute(packet.AttributeUserPassword, "testpass")
            
            _, err := c.SendRequest(context.Background(), req)
            if err != nil {
                b.Fatal(err)
            }
            
            identifier++
        }
    })
}

func BenchmarkPacketEncoding(b *testing.B) {
    req := packet.New(packet.CodeAccessRequest, 1)
    req.AddStringAttribute(packet.AttributeUserName, "testuser")
    req.AddStringAttribute(packet.AttributeUserPassword, "testpass")
    req.AddStringAttribute(packet.AttributeNASIdentifier, "test-nas")
    
    secret := "testing123"
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := req.Encode(secret)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Performance Tuning Examples

### High-Performance Server Configuration

```go
func createHighPerformanceServer() (*server.Server, error) {
    config := &server.Config{
        Bindings: []server.Binding{
            {
                Network: "udp",
                Address: ":1812",
                Secret:  "high-perf-secret",
            },
        },
        
        // Performance tuning
        ReadTimeout:      time.Second * 5,
        WriteTimeout:     time.Second * 5,
        MaxRequestSize:   4096,
        WorkerPoolSize:   runtime.NumCPU() * 2,
        RequestQueueSize: 10000,
        
        // Memory optimization
        BufferPoolSize:   1000,
        RequestPoolSize:  500,
        ResponsePoolSize: 500,
    }
    
    handler := &OptimizedHandler{
        userCache: cache.New(5*time.Minute, 10*time.Minute),
    }
    
    return server.New(config, handler)
}

type OptimizedHandler struct {
    userCache *cache.Cache
}

func (h *OptimizedHandler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    // Use caching for frequent lookups
    username, _ := req.GetStringAttribute(packet.AttributeUserName)
    
    // Check cache first
    if cachedResult, found := h.userCache.Get(username); found {
        result := cachedResult.(*AuthResult)
        resp := packet.New(result.Code, req.Identifier)
        return resp, nil
    }
    
    // Process authentication
    result := h.authenticateUser(username, req)
    
    // Cache result
    h.userCache.Set(username, result, cache.DefaultExpiration)
    
    return packet.New(result.Code, req.Identifier), nil
}
```

This comprehensive documentation provides practical examples for implementing RADIUS servers and clients with various levels of complexity, from basic authentication to advanced features like proxying, middleware, and performance optimization.