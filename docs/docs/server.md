# RADIUS Server Usage

This guide covers how to implement and configure RADIUS servers using the GoRADIUS library.

## Basic Server Setup

### Creating a Simple Server

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/vitalvas/goradius/pkg/server"
    "github.com/vitalvas/goradius/pkg/packet"
)

func main() {
    // Configure server
    config := &server.Config{
        Bindings: []server.Binding{
            {
                Network: "udp",
                Address: ":1812",
            },
        },
        ReadTimeout:    time.Second * 30,
        WriteTimeout:   time.Second * 30,
        MaxRequestSize: 4096,
    }

    // Create server with handler
    srv, err := server.New(config, &AuthHandler{})
    if err != nil {
        log.Fatal("Failed to create server:", err)
    }

    // Start server
    ctx := context.Background()
    if err := srv.Start(ctx); err != nil {
        log.Fatal("Failed to start server:", err)
    }

    log.Println("RADIUS server started on :1812")
    
    // Keep server running
    select {}
}
```

## Server Configuration

### Network Bindings

Configure multiple network bindings for different protocols:

```go
config := &server.Config{
    Bindings: []server.Binding{
        // UDP binding (standard RADIUS)
        {
            Network: "udp",
            Address: ":1812",
        },
        // TCP binding
        {
            Network: "tcp", 
            Address: ":1812",
        },
        // TCP with TLS
        {
            Network: "tcp",
            Address: ":2083",
            TLSConfig: &tls.Config{
                CertFile: "/path/to/cert.pem",
                KeyFile:  "/path/to/key.pem",
            },
        },
        // Accounting server
        {
            Network: "udp",
            Address: ":1813",
        },
    },
    
    // Secret management - configure per-client secrets
    SecretProvider: &MySecretProvider{},
}
```

### Secret Management

Instead of configuring secrets in bindings, use a SecretProvider to manage client secrets:

```go
type SecretProvider interface {
    GetSecret(clientIP string) (string, error)
}

type MySecretProvider struct {
    secrets map[string]string
}

func (sp *MySecretProvider) GetSecret(clientIP string) (string, error) {
    secret, exists := sp.secrets[clientIP]
    if !exists {
        return "", fmt.Errorf("no secret for client: %s", clientIP)
    }
    return secret, nil
}

// Initialize with client secrets
secretProvider := &MySecretProvider{
    secrets: map[string]string{
        "192.168.1.100": "nas-secret-1",
        "192.168.1.101": "nas-secret-2",
        "10.0.0.50":     "accounting-secret",
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
```

### Database-backed Secret Provider

```go
type DatabaseSecretProvider struct {
    db *sql.DB
}

func (dsp *DatabaseSecretProvider) GetSecret(clientIP string) (string, error) {
    var secret string
    query := "SELECT secret FROM radius_clients WHERE ip_address = $1 AND active = true"
    
    err := dsp.db.QueryRow(query, clientIP).Scan(&secret)
    if err == sql.ErrNoRows {
        return "", fmt.Errorf("client not authorized: %s", clientIP)
    }
    if err != nil {
        return "", fmt.Errorf("database error: %v", err)
    }
    
    return secret, nil
}
```

### Timeouts and Limits

```go
config := &server.Config{
    // Network timeouts
    ReadTimeout:    time.Second * 30,
    WriteTimeout:   time.Second * 30,
    
    // Request limits
    MaxRequestSize: 4096,
    MaxClients:     1000,
    
    // Rate limiting
    RequestsPerSecond: 100,
    BurstSize:        200,
}
```

## Handler Implementation

### Basic Handler Interface

```go
type AuthHandler struct {
    users map[string]string // username -> password
}

func (h *AuthHandler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    switch req.Code {
    case packet.CodeAccessRequest:
        return h.handleAuth(ctx, req)
    case packet.CodeAccountingRequest:
        return h.handleAccounting(ctx, req)
    default:
        return nil, fmt.Errorf("unsupported packet type: %v", req.Code)
    }
}

func (h *AuthHandler) handleAuth(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    // Extract username and password
    username, ok := req.GetStringAttribute(packet.AttributeUserName)
    if !ok {
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    password, ok := req.GetStringAttribute(packet.AttributeUserPassword)
    if !ok {
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Validate credentials
    if h.validateUser(username, password) {
        resp := packet.New(packet.CodeAccessAccept, req.Identifier)
        
        // Add reply attributes
        resp.AddStringAttribute(packet.AttributeReplyMessage, "Access granted")
        resp.AddIntegerAttribute(packet.AttributeSessionTimeout, 3600)
        
        return resp, nil
    }

    return packet.New(packet.CodeAccessReject, req.Identifier), nil
}
```

### Enhanced Handler with Middleware

```go
type EnhancedHandler struct {
    db     *sql.DB
    logger log.Logger
    cache  *redis.Client
}

func (h *EnhancedHandler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    // Log request
    h.logger.WithFields(log.Fields{
        "code":       req.Code,
        "identifier": req.Identifier,
        "client_ip":  getClientIP(ctx),
    }).Info("Processing RADIUS request")

    // Rate limiting check
    if !h.checkRateLimit(ctx, getClientIP(ctx)) {
        return packet.New(packet.CodeAccessReject, req.Identifier), nil
    }

    // Process based on packet type
    switch req.Code {
    case packet.CodeAccessRequest:
        return h.handleAuthentication(ctx, req)
    case packet.CodeAccountingRequest:
        return h.handleAccounting(ctx, req)
    case packet.CodeStatusServer:
        return h.handleStatusCheck(ctx, req)
    default:
        return nil, fmt.Errorf("unsupported request type: %v", req.Code)
    }
}
```

## Middleware Support

### Implementing Middleware

```go
func LoggingMiddleware(logger log.Logger) server.Middleware {
    return func(next server.Handler) server.Handler {
        return server.HandlerFunc(func(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
            start := time.Now()
            
            resp, err := next.HandleRequest(ctx, req)
            
            duration := time.Since(start)
            logger.WithFields(log.Fields{
                "duration":   duration,
                "request":    req.Code,
                "response":   resp.Code,
                "identifier": req.Identifier,
            }).Info("Request processed")
            
            return resp, err
        })
    }
}

func AuthenticationMiddleware(secretProvider SecretProvider) server.Middleware {
    return func(next server.Handler) server.Handler {
        return server.HandlerFunc(func(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
            clientIP := getClientIP(ctx)
            secret, err := secretProvider.GetSecret(clientIP)
            if err != nil {
                log.Printf("Failed to get secret for client %s: %v", clientIP, err)
                return packet.New(packet.CodeAccessReject, req.Identifier), nil
            }
            
            // Validate request authenticator
            if !validateAuthenticator(req, secret) {
                return packet.New(packet.CodeAccessReject, req.Identifier), nil
            }
            
            return next.HandleRequest(ctx, req)
        })
    }
}
```

### Using Middleware

```go
func createServer() *server.Server {
    handler := &MyHandler{}
    secretProvider := &MySecretProvider{...}
    
    // Wrap handler with middleware
    handler = LoggingMiddleware(logger)(handler)
    handler = AuthenticationMiddleware(secretProvider)(handler)
    handler = RateLimitMiddleware(rateLimit)(handler)
    
    config := &server.Config{
        SecretProvider: secretProvider,
        ...
    }
    return server.New(config, handler)
}
```

## Advanced Configuration

### Client Validation

```go
config := &server.Config{
    ClientValidation: &server.ClientValidation{
        RequireValidSecret: true,
        AllowedClients: []server.ClientConfig{
            {
                IPAddress: "192.168.1.100",
                Name:      "NAS-1",
            },
            {
                IPAddress: "192.168.1.101", 
                Name:      "NAS-2",
            },
        },
        DefaultAction: server.ActionReject,
    },
    
    // Secrets are managed separately via SecretProvider
    SecretProvider: &MySecretProvider{
        secrets: map[string]string{
            "192.168.1.100": "nas-secret-1",
            "192.168.1.101": "nas-secret-2",
        },
    },
}
```

### Statistics and Monitoring

```go
// Get server statistics
stats := srv.GetStatistics()
fmt.Printf("Requests processed: %d\n", stats.RequestsProcessed)
fmt.Printf("Authentication success rate: %.2f%%\n", stats.AuthSuccessRate)
fmt.Printf("Average response time: %v\n", stats.AvgResponseTime)

// Set up Prometheus metrics
import "github.com/prometheus/client_golang/prometheus"

var (
    requestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "radius_requests_total",
            Help: "Total number of RADIUS requests",
        },
        []string{"code", "result"},
    )
    
    responseTime = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "radius_response_duration_seconds",
            Help: "RADIUS response duration",
        },
        []string{"code"},
    )
)
```

### Graceful Shutdown

```go
func main() {
    srv, err := server.New(config, handler)
    if err != nil {
        log.Fatal(err)
    }

    // Start server
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    go func() {
        if err := srv.Start(ctx); err != nil {
            log.Fatal("Server failed:", err)
        }
    }()

    // Wait for interrupt signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan

    log.Println("Shutting down server...")
    
    // Graceful shutdown with timeout
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer shutdownCancel()
    
    if err := srv.Shutdown(shutdownCtx); err != nil {
        log.Printf("Server shutdown error: %v", err)
    }
    
    log.Println("Server stopped")
}
```

## Performance Optimization

### Connection Pooling

```go
config := &server.Config{
    TCP: &server.TCPConfig{
        KeepAlive:       true,
        KeepAlivePeriod: time.Minute * 2,
        MaxConnections:  1000,
        IdleTimeout:     time.Minute * 5,
    },
}
```

### Memory Management

```go
config := &server.Config{
    Memory: &server.MemoryConfig{
        MaxRequestSize:   4096,
        BufferPoolSize:   1000,
        RequestPoolSize:  500,
        ResponsePoolSize: 500,
    },
}
```

## Error Handling

### Custom Error Responses

```go
func (h *Handler) HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    defer func() {
        if r := recover(); r != nil {
            h.logger.Errorf("Handler panic: %v", r)
        }
    }()

    resp, err := h.processRequest(ctx, req)
    if err != nil {
        // Log error
        h.logger.WithError(err).Error("Request processing failed")
        
        // Return appropriate error response
        switch {
        case errors.Is(err, ErrInvalidCredentials):
            return packet.New(packet.CodeAccessReject, req.Identifier), nil
        case errors.Is(err, ErrServerBusy):
            return nil, err // Let server handle retry
        default:
            return packet.New(packet.CodeAccessReject, req.Identifier), nil
        }
    }

    return resp, nil
}
```

## Testing

### Unit Testing Server Components

```go
func TestHandler(t *testing.T) {
    handler := &AuthHandler{
        users: map[string]string{
            "testuser": "testpass",
        },
    }

    req := packet.New(packet.CodeAccessRequest, 1)
    req.AddStringAttribute(packet.AttributeUserName, "testuser")
    req.AddStringAttribute(packet.AttributeUserPassword, "testpass")

    resp, err := handler.HandleRequest(context.Background(), req)
    
    assert.NoError(t, err)
    assert.Equal(t, packet.CodeAccessAccept, resp.Code)
}
```

### Integration Testing

```go
func TestServerIntegration(t *testing.T) {
    // Start test server
    srv := startTestServer(t)
    defer srv.Shutdown(context.Background())

    // Create test client
    client := createTestClient(t)
    defer client.Close()

    // Send test request
    req := createAuthRequest("testuser", "testpass")
    resp, err := client.SendRequest(context.Background(), req)

    assert.NoError(t, err)
    assert.Equal(t, packet.CodeAccessAccept, resp.Code)
}
```