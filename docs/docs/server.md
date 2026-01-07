# RADIUS Server Usage

This guide covers how to implement RADIUS servers using the GoRADIUS library.

## Basic Server Setup

### Creating a Simple Server

```go
package main

import (
    "fmt"
    "log"
    "net"

    "github.com/vitalvas/goradius/pkg/dictionaries"
    "github.com/vitalvas/goradius/pkg/packet"
    "github.com/vitalvas/goradius/pkg/server"
)

type myHandler struct{}

func (h *myHandler) ServeSecret(req server.SecretRequest) (server.SecretResponse, error) {
    fmt.Printf("Secret request from %s\n", req.RemoteAddr)

    // Return shared secret for this client
    return server.SecretResponse{
        Secret: []byte("testing123"),
        Metadata: map[string]interface{}{
            "client":  req.RemoteAddr.String(),
            "nastype": "generic",
        },
    }, nil
}

func (h *myHandler) ServeRADIUS(req *server.Request) (server.Response, error) {
    fmt.Printf("Received %s from %s\n", req.Code().String(), req.RemoteAddr)

    resp := server.NewResponse(req)

    // Handle different request types
    switch req.Code() {
    case packet.CodeAccessRequest:
        resp.SetCode(packet.CodeAccessAccept)
        resp.SetAttribute("Reply-Message", "Access granted")

    case packet.CodeAccountingRequest:
        resp.SetCode(packet.CodeAccountingResponse)
    }

    return resp, nil
}

func main() {
    // Create dictionary with standard attributes and common vendors
    dict, err := dictionaries.NewDefault()
    if err != nil {
        log.Fatal(err)
    }

    // Create server
    srv, err := server.New(server.Config{
        Handler:    &myHandler{},
        Dictionary: dict,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Create UDP listener
    conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 1812})
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("RADIUS server listening on :1812")
    transport := server.NewUDPTransport(conn)
    log.Fatal(srv.Serve(transport))
}
```

## Handler Interface

The server requires a handler that implements two methods:

### ServeSecret

Returns the shared secret for a client:

```go
type SecretRequest struct {
    Context    context.Context
    LocalAddr  net.Addr
    RemoteAddr net.Addr
}

type SecretResponse struct {
    Secret   []byte
    Metadata map[string]interface{}
}

func (h *myHandler) ServeSecret(req server.SecretRequest) (server.SecretResponse, error) {
    // Lookup secret based on client address
    secret := lookupSecretForClient(req.RemoteAddr.String())

    return server.SecretResponse{
        Secret: []byte(secret),
        Metadata: map[string]interface{}{
            "client": req.RemoteAddr.String(),
        },
    }, nil
}
```

### ServeRADIUS

Processes RADIUS requests and returns responses:

```go
type Request struct {
    Context    context.Context
    LocalAddr  net.Addr
    RemoteAddr net.Addr
    Packet     *packet.Packet
    Secret     SecretResponse
}

func (h *myHandler) ServeRADIUS(req *server.Request) (server.Response, error) {
    resp := server.NewResponse(req)

    switch req.Code() {
    case packet.CodeAccessRequest:
        // Authenticate user
        if authenticateUser(req) {
            resp.SetCode(packet.CodeAccessAccept)
        } else {
            resp.SetCode(packet.CodeAccessReject)
        }

    case packet.CodeAccountingRequest:
        // Handle accounting
        handleAccounting(req)
        resp.SetCode(packet.CodeAccountingResponse)
    }

    return resp, nil
}
```

## Response Helper Methods

The Response object provides convenient methods:

### SetCode

Set the response packet code:

```go
resp.SetCode(packet.CodeAccessAccept)
resp.SetCode(packet.CodeAccessReject)
resp.SetCode(packet.CodeAccountingResponse)
```

### SetAttribute

Add a single attribute by name:

```go
resp.SetAttribute("Reply-Message", "Welcome!")
resp.SetAttribute("Framed-IP-Address", "192.0.2.10")
resp.SetAttribute("Session-Timeout", 3600)
```

### SetAttributes

Add multiple attributes at once:

```go
attrs := map[string]interface{}{
    "Reply-Message":           "Access granted",
    "Framed-IP-Address":       "192.0.2.10",
    "Session-Timeout":         3600,
    "ERX-Primary-Dns":         "8.8.8.8",
    "ERX-Service-Activate:1":  "ipoe-parking",
}
resp.SetAttributes(attrs)
```

## Authentication Example

```go
func (h *myHandler) ServeRADIUS(req *server.Request) (server.Response, error) {
    resp := server.NewResponse(req)

    if req.Code() != packet.CodeAccessRequest {
        return resp, nil
    }

    // Get username using Request API
    usernames := req.GetAttribute("User-Name")
    if len(usernames) == 0 {
        resp.SetCode(packet.CodeAccessReject)
        resp.SetAttribute("Reply-Message", "Username required")
        return resp, nil
    }
    username := usernames[0].String()

    // Authenticate (implement your logic)
    if authenticateUser(username, req.Secret.Secret) {
        resp.SetCode(packet.CodeAccessAccept)
        resp.SetAttribute("Reply-Message", "Access granted")

        // Add service attributes
        attrs := map[string]interface{}{
            "Framed-IP-Address": "192.0.2.10",
            "Session-Timeout":   3600,
        }
        resp.SetAttributes(attrs)
    } else {
        resp.SetCode(packet.CodeAccessReject)
        resp.SetAttribute("Reply-Message", "Authentication failed")
    }

    return resp, nil
}
```

## Accounting Example

```go
func (h *myHandler) ServeRADIUS(req *server.Request) (server.Response, error) {
    resp := server.NewResponse(req)

    if req.Code() != packet.CodeAccountingRequest {
        return resp, nil
    }

    // Get accounting status type using Request API
    statusAttrs := req.GetAttribute("Acct-Status-Type")
    if len(statusAttrs) == 0 {
        return resp, fmt.Errorf("missing Acct-Status-Type")
    }

    statusType := statusAttrs[0].String()

    switch statusType {
    case "Start":
        handleAccountingStart(req)
    case "Stop":
        handleAccountingStop(req)
    case "Interim-Update":
        handleAccountingUpdate(req)
    }

    resp.SetCode(packet.CodeAccountingResponse)
    return resp, nil
}

func handleAccountingStart(req *server.Request) {
    // Get session ID using Request API
    sessions := req.GetAttribute("Acct-Session-ID")
    if len(sessions) > 0 {
        sessionID := sessions[0].String()
        // Store session start
        fmt.Printf("Session started: %s\n", sessionID)
    }
}

func handleAccountingStop(req *server.Request) {
    // Get session statistics using Request API
    sessions := req.GetAttribute("Acct-Session-ID")
    inputOctets := req.GetAttribute("Acct-Input-Octets")
    outputOctets := req.GetAttribute("Acct-Output-Octets")
    sessionTime := req.GetAttribute("Acct-Session-Time")

    if len(sessions) > 0 && len(inputOctets) > 0 && len(outputOctets) > 0 && len(sessionTime) > 0 {
        fmt.Printf("Session %s ended: %s bytes in, %s bytes out, %s seconds\n",
            sessions[0].String(),
            inputOctets[0].String(),
            outputOctets[0].String(),
            sessionTime[0].String())
    }
}
```

## Transport Interface

The server supports multiple transport protocols through the Transport interface. This allows running RADIUS over UDP (standard), TCP, or TLS (RadSec).

### Transport Types

#### UDP Transport (Default)

For standard RADIUS over UDP:

```go
srv, err := server.New(server.Config{
    Handler: handler,
})
if err != nil {
    log.Fatal(err)
}

conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 1812})
if err != nil {
    log.Fatal(err)
}

transport := server.NewUDPTransport(conn)
log.Fatal(srv.Serve(transport))
```

#### TCP Transport

For RADIUS over TCP (RFC 6613):

```go
srv, err := server.New(server.Config{
    Handler: handler,
})
if err != nil {
    log.Fatal(err)
}

listener, err := net.Listen("tcp", ":1812")
if err != nil {
    log.Fatal(err)
}

transport := server.NewTCPTransport(listener)
log.Fatal(srv.Serve(transport))
```

#### TLS Transport (RadSec)

For RADIUS over TLS (RFC 6614, RadSec):

```go
srv, err := server.New(server.Config{
    Handler: handler,
})
if err != nil {
    log.Fatal(err)
}

cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}

listener, err := tls.Listen("tcp", ":2083", tlsConfig)
if err != nil {
    log.Fatal(err)
}

transport := server.NewTCPTransport(listener)
log.Fatal(srv.Serve(transport))
```

### Transport Interface Definition

```go
type Transport interface {
    Serve(handler TransportHandler) error
    LocalAddr() net.Addr
    Close() error
}

type TransportHandler func(data []byte, remoteAddr net.Addr, respond ResponderFunc)

type ResponderFunc func(data []byte) error
```

## Secret Management

Implement per-client secret lookup:

```go
type SecretStore struct {
    secrets map[string]string
}

func NewSecretStore() *SecretStore {
    return &SecretStore{
        secrets: map[string]string{
            "192.168.1.1":   "secret1",
            "192.168.1.2":   "secret2",
            "10.0.0.0/24":   "shared-secret",
        },
    }
}

func (s *SecretStore) ServeSecret(req server.SecretRequest) (server.SecretResponse, error) {
    clientIP := req.RemoteAddr.(*net.UDPAddr).IP.String()

    secret, found := s.secrets[clientIP]
    if !found {
        // Try subnet match or default
        secret = "default-secret"
    }

    return server.SecretResponse{
        Secret: []byte(secret),
        Metadata: map[string]interface{}{
            "client": clientIP,
        },
    }, nil
}
```

## Server Control

### Graceful Shutdown

```go
srv, err := server.New(server.Config{
    Handler:    handler,
    Dictionary: dict,
})
if err != nil {
    log.Fatal(err)
}

// Create UDP listener
conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 1812})
if err != nil {
    log.Fatal(err)
}
transport := server.NewUDPTransport(conn)

// Start server in goroutine
go func() {
    if err := srv.Serve(transport); err != nil {
        log.Printf("Server error: %v\n", err)
    }
}()

// Wait for shutdown signal
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
<-sigChan

// Close server - waits for in-flight requests to complete
log.Println("Shutting down...")
srv.Close()
```

## Best Practices

### Error Handling

1. **Always validate input**: Check for required attributes
2. **Handle decode errors**: Attribute value decoding can fail
3. **Log errors**: Use structured logging for debugging
4. **Return appropriate codes**: Use Access-Reject for auth failures

### Performance

1. **Use dictionaries**: Pre-load dictionaries once
2. **Avoid blocking**: Keep handlers fast
3. **Connection pooling**: Reuse database connections
4. **Caching**: Cache authentication results when appropriate

### Security

1. **Validate clients**: Check client IP addresses
2. **Use strong secrets**: Minimum 16 random characters
3. **Rate limiting**: Implement rate limiting per client
4. **Audit logging**: Log all authentication attempts
5. **Network isolation**: Run on private networks when possible

## Complete Example

See `cmd/simple-server/main.go` in the repository for a complete working example.
