# RADIUS Client Usage

This guide covers how to use the RADIUS client for authentication, accounting, and other RADIUS operations.

## Basic Client Setup

### Creating a Simple Client

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/vitalvas/goradius/pkg/client"
    "github.com/vitalvas/goradius/pkg/packet"
)

func main() {
    // Configure client
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

    // Create authentication request
    req := packet.New(packet.CodeAccessRequest, 1)
    req.AddStringAttribute(packet.AttributeUserName, "testuser")
    req.AddStringAttribute(packet.AttributeUserPassword, "testpass")

    // Send request
    resp, err := c.SendRequest(context.Background(), req)
    if err != nil {
        log.Fatal("Request failed:", err)
    }

    // Handle response
    switch resp.Code {
    case packet.CodeAccessAccept:
        log.Println("Authentication successful")
    case packet.CodeAccessReject:
        log.Println("Authentication failed")
    case packet.CodeAccessChallenge:
        log.Println("Challenge required")
    }
}
```

## Client Configuration

### Multiple Servers with Failover

```go
config := &client.Config{
    Servers: []client.ServerConfig{
        {
            Address: "radius1.example.com:1812",
            Secret:  "secret1",
            Weight:  10, // Higher weight = higher priority
        },
        {
            Address: "radius2.example.com:1812",
            Secret:  "secret2", 
            Weight:  5,
        },
        {
            Address: "radius3.example.com:1812",
            Secret:  "secret3",
            Weight:  1, // Backup server
        },
    },
    
    // Failover configuration
    FailoverTimeout:     time.Second * 30,
    HealthCheckInterval: time.Minute * 2,
    MaxFailures:         3,
}
```

### Transport Options

```go
// UDP Transport (default)
config := &client.Config{
    Transport: client.TransportUDP,
    Timeout:   time.Second * 5,
}

// TCP Transport
config := &client.Config{
    Transport: client.TransportTCP,
    TCP: &client.TCPConfig{
        KeepAlive:       true,
        KeepAlivePeriod: time.Minute * 2,
        ConnectTimeout:  time.Second * 10,
        IdleTimeout:     time.Minute * 5,
    },
}

// TCP with TLS
config := &client.Config{
    Transport: client.TransportTLS,
    TLSConfig: &tls.Config{
        ServerName:         "radius.example.com",
        InsecureSkipVerify: false,
        Certificates:       []tls.Certificate{clientCert},
    },
}
```

### Retry Configuration

```go
config := &client.Config{
    // Basic retry settings
    MaxRetries:    3,
    RetryInterval: time.Second * 2,
    
    // Advanced retry settings
    RetryBackoff: client.BackoffExponential,
    MaxBackoff:   time.Second * 30,
    
    // Per-request timeout
    Timeout: time.Second * 5,
}
```

## Authentication Requests

### Basic Authentication

```go
func authenticate(c client.Client, username, password string) error {
    req := packet.New(packet.CodeAccessRequest, getNextID())
    
    // Add required attributes
    req.AddStringAttribute(packet.AttributeUserName, username)
    req.AddStringAttribute(packet.AttributeUserPassword, password)
    
    // Add optional attributes
    req.AddStringAttribute(packet.AttributeNASIdentifier, "my-nas")
    req.AddIPAttribute(packet.AttributeNASIPAddress, net.ParseIP("192.168.1.1"))
    req.AddIntegerAttribute(packet.AttributeNASPort, 123)
    
    // Send request
    ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
    defer cancel()
    
    resp, err := c.SendRequest(ctx, req)
    if err != nil {
        return fmt.Errorf("authentication request failed: %w", err)
    }
    
    switch resp.Code {
    case packet.CodeAccessAccept:
        return nil
    case packet.CodeAccessReject:
        return fmt.Errorf("authentication rejected")
    case packet.CodeAccessChallenge:
        return handleChallenge(c, resp)
    default:
        return fmt.Errorf("unexpected response: %v", resp.Code)
    }
}
```

### PAP Authentication

```go
func authenticatePAP(c client.Client, username, password string) (*packet.Packet, error) {
    req := packet.New(packet.CodeAccessRequest, getNextID())
    
    req.AddStringAttribute(packet.AttributeUserName, username)
    req.AddStringAttribute(packet.AttributeUserPassword, password)
    
    return c.SendRequest(context.Background(), req)
}
```

### CHAP Authentication

```go
func authenticateCHAP(c client.Client, username, password string, challenge []byte) (*packet.Packet, error) {
    req := packet.New(packet.CodeAccessRequest, getNextID())
    
    // Generate CHAP response
    chapID := byte(1)
    chapResponse := generateCHAPResponse(chapID, password, challenge)
    
    req.AddStringAttribute(packet.AttributeUserName, username)
    req.AddBytesAttribute(packet.AttributeCHAPPassword, append([]byte{chapID}, chapResponse...))
    req.AddBytesAttribute(packet.AttributeCHAPChallenge, challenge)
    
    return c.SendRequest(context.Background(), req)
}
```

## Accounting Requests

### Start Accounting

```go
func startAccounting(c client.Client, sessionID, username string) error {
    req := packet.New(packet.CodeAccountingRequest, getNextID())
    
    // Required attributes
    req.AddIntegerAttribute(packet.AttributeAcctStatusType, 1) // Start
    req.AddStringAttribute(packet.AttributeAcctSessionID, sessionID)
    req.AddStringAttribute(packet.AttributeUserName, username)
    
    // Optional session info
    req.AddStringAttribute(packet.AttributeNASIdentifier, "my-nas")
    req.AddIPAttribute(packet.AttributeFramedIPAddress, net.ParseIP("10.0.0.100"))
    req.AddIntegerAttribute(packet.AttributeNASPort, 123)
    
    resp, err := c.SendRequest(context.Background(), req)
    if err != nil {
        return err
    }
    
    if resp.Code != packet.CodeAccountingResponse {
        return fmt.Errorf("accounting start failed: %v", resp.Code)
    }
    
    return nil
}
```

### Interim Accounting Updates

```go
func sendInterimUpdate(c client.Client, sessionID string, stats SessionStats) error {
    req := packet.New(packet.CodeAccountingRequest, getNextID())
    
    req.AddIntegerAttribute(packet.AttributeAcctStatusType, 3) // Interim-Update
    req.AddStringAttribute(packet.AttributeAcctSessionID, sessionID)
    
    // Session statistics
    req.AddIntegerAttribute(packet.AttributeAcctInputOctets, stats.InputOctets)
    req.AddIntegerAttribute(packet.AttributeAcctOutputOctets, stats.OutputOctets)
    req.AddIntegerAttribute(packet.AttributeAcctInputPackets, stats.InputPackets)
    req.AddIntegerAttribute(packet.AttributeAcctOutputPackets, stats.OutputPackets)
    req.AddIntegerAttribute(packet.AttributeAcctSessionTime, stats.SessionTime)
    
    resp, err := c.SendRequest(context.Background(), req)
    if err != nil {
        return err
    }
    
    return nil
}
```

### Stop Accounting

```go
func stopAccounting(c client.Client, sessionID string, cause int, stats SessionStats) error {
    req := packet.New(packet.CodeAccountingRequest, getNextID())
    
    req.AddIntegerAttribute(packet.AttributeAcctStatusType, 2) // Stop
    req.AddStringAttribute(packet.AttributeAcctSessionID, sessionID)
    req.AddIntegerAttribute(packet.AttributeAcctTerminateCause, cause)
    
    // Final statistics
    req.AddIntegerAttribute(packet.AttributeAcctInputOctets, stats.InputOctets)
    req.AddIntegerAttribute(packet.AttributeAcctOutputOctets, stats.OutputOctets)
    req.AddIntegerAttribute(packet.AttributeAcctSessionTime, stats.SessionTime)
    
    resp, err := c.SendRequest(context.Background(), req)
    if err != nil {
        return err
    }
    
    return nil
}
```

## Advanced Features

### High-Level API

```go
// Use simplified API for common operations
api := client.NewHighLevelAPI(config)

// Simple authentication
result, err := api.Authenticate("username", "password")
if err != nil {
    log.Fatal(err)
}

switch result.Status {
case client.AuthSuccess:
    log.Printf("Authenticated successfully, session timeout: %d", result.SessionTimeout)
case client.AuthFailure:
    log.Printf("Authentication failed: %s", result.ReplyMessage)
case client.AuthChallenge:
    log.Printf("Challenge required: %s", result.Challenge)
}

// Simple accounting using packet builder
req := hlc.NewRequest(packet.CodeAccountingRequest).
    WithUserName("testuser").
    WithStringAttribute(packet.AttrAcctSessionID, "sess-12345").
    WithIntegerAttribute(packet.AttrAcctStatusType, 1). // Start
    WithNASPort(123).
    WithRetries(3).
    WithTimeout(30 * time.Second)

response, err := req.Send(context.Background())
```

### Connection Pooling

```go
config := &client.Config{
    ConnectionPool: &client.PoolConfig{
        MaxConnections:     50,
        MaxIdleConnections: 10,
        IdleTimeout:        time.Minute * 5,
        MaxLifetime:        time.Hour,
    },
}
```

### Request/Response Middleware

```go
type LoggingMiddleware struct {
    logger log.Logger
}

func (m *LoggingMiddleware) BeforeRequest(ctx context.Context, req *packet.Packet) error {
    m.logger.WithFields(log.Fields{
        "code":       req.Code,
        "identifier": req.Identifier,
    }).Debug("Sending RADIUS request")
    return nil
}

func (m *LoggingMiddleware) AfterResponse(ctx context.Context, req *packet.Packet, resp *packet.Packet, err error) {
    if err != nil {
        m.logger.WithError(err).Error("RADIUS request failed")
        return
    }
    
    m.logger.WithFields(log.Fields{
        "request_code":  req.Code,
        "response_code": resp.Code,
        "identifier":    req.Identifier,
    }).Debug("Received RADIUS response")
}

// Use middleware
c, err := client.NewWithMiddleware(config, &LoggingMiddleware{logger: logger})
```

## Error Handling

### Retry Logic

```go
func authenticateWithRetry(c client.Client, username, password string) error {
    req := packet.New(packet.CodeAccessRequest, getNextID())
    req.AddStringAttribute(packet.AttributeUserName, username)
    req.AddStringAttribute(packet.AttributeUserPassword, password)
    
    // Use built-in retry
    resp, err := c.SendRequestWithRetry(context.Background(), req, 3)
    if err != nil {
        // Check if it's a permanent or temporary error
        if client.IsPermanentError(err) {
            return fmt.Errorf("permanent error: %w", err)
        }
        return fmt.Errorf("temporary error: %w", err)
    }
    
    return nil
}
```

### Custom Error Handling

```go
func handleResponse(resp *packet.Packet, err error) {
    if err != nil {
        switch {
        case client.IsTimeoutError(err):
            log.Printf("Request timed out")
        case client.IsNetworkError(err):
            log.Printf("Network error: %v", err)
        case client.IsServerError(err):
            log.Printf("Server error: %v", err)
        default:
            log.Printf("Unknown error: %v", err)
        }
        return
    }
    
    // Handle successful response
    switch resp.Code {
    case packet.CodeAccessAccept:
        handleAccessAccept(resp)
    case packet.CodeAccessReject:
        handleAccessReject(resp)
    case packet.CodeAccessChallenge:
        handleAccessChallenge(resp)
    }
}
```

## Performance Optimization

### Concurrent Requests

```go
func authenticateMultiple(c client.Client, users []User) []AuthResult {
    results := make([]AuthResult, len(users))
    var wg sync.WaitGroup
    
    for i, user := range users {
        wg.Add(1)
        go func(idx int, u User) {
            defer wg.Done()
            
            req := packet.New(packet.CodeAccessRequest, getNextID())
            req.AddStringAttribute(packet.AttributeUserName, u.Username)
            req.AddStringAttribute(packet.AttributeUserPassword, u.Password)
            
            resp, err := c.SendRequest(context.Background(), req)
            results[idx] = AuthResult{
                User:     u,
                Response: resp,
                Error:    err,
            }
        }(i, user)
    }
    
    wg.Wait()
    return results
}
```

### Request Batching

```go
func batchAccountingUpdates(c client.Client, updates []AccountingUpdate) error {
    const batchSize = 10
    
    for i := 0; i < len(updates); i += batchSize {
        end := i + batchSize
        if end > len(updates) {
            end = len(updates)
        }
        
        batch := updates[i:end]
        if err := processBatch(c, batch); err != nil {
            return err
        }
    }
    
    return nil
}
```

## Monitoring and Statistics

### Client Statistics

```go
// Get client statistics
stats := c.GetStatistics()
fmt.Printf("Requests sent: %d\n", stats.RequestsSent)
fmt.Printf("Responses received: %d\n", stats.ResponsesReceived)
fmt.Printf("Timeouts: %d\n", stats.Timeouts)
fmt.Printf("Network errors: %d\n", stats.NetworkErrors)
fmt.Printf("Average response time: %v\n", stats.AvgResponseTime)
fmt.Printf("Success rate: %.2f%%\n", stats.SuccessRate)
```

### Health Monitoring

```go
// Check server health
healthy := c.IsHealthy()
if !healthy {
    log.Println("RADIUS server is not healthy")
}

// Get detailed health status
status := c.GetHealthStatus()
for _, server := range status.Servers {
    fmt.Printf("Server %s: %s (failures: %d)\n", 
        server.Address, server.Status, server.FailureCount)
}
```

## Testing

### Unit Testing

```go
func TestClient(t *testing.T) {
    // Create test server
    server := startTestServer(t)
    defer server.Stop()
    
    // Create client
    config := &client.Config{
        Servers: []client.ServerConfig{
            {
                Address: server.Address(),
                Secret:  "testing123",
            },
        },
    }
    
    c, err := client.New(config)
    require.NoError(t, err)
    defer c.Close()
    
    // Test authentication
    req := packet.New(packet.CodeAccessRequest, 1)
    req.AddStringAttribute(packet.AttributeUserName, "testuser")
    req.AddStringAttribute(packet.AttributeUserPassword, "testpass")
    
    resp, err := c.SendRequest(context.Background(), req)
    assert.NoError(t, err)
    assert.Equal(t, packet.CodeAccessAccept, resp.Code)
}
```

### Mock Client

```go
type MockClient struct {
    responses map[string]*packet.Packet
    errors    map[string]error
}

func (m *MockClient) SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
    key := req.String()
    if err, exists := m.errors[key]; exists {
        return nil, err
    }
    if resp, exists := m.responses[key]; exists {
        return resp, nil
    }
    return packet.New(packet.CodeAccessReject, req.Identifier), nil
}

// Use in tests
func TestWithMockClient(t *testing.T) {
    mock := &MockClient{
        responses: make(map[string]*packet.Packet),
    }
    
    // Configure mock responses
    mock.responses["auth-request"] = packet.New(packet.CodeAccessAccept, 1)
    
    // Test your code with mock client
    result := authenticateUser(mock, "testuser", "testpass")
    assert.True(t, result)
}
```