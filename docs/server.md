# RADIUS Server Usage

This guide covers how to implement RADIUS servers
using the GoRADIUS library.

## Basic Server Setup

### Creating a Simple Server

```go
package main

import (
    "fmt"
    "log"
    "net"

    "github.com/vitalvas/goradius"
)

type myHandler struct{}

func (h *myHandler) ServeSecret(
    req goradius.SecretRequest,
) (goradius.SecretResponse, error) {
    fmt.Printf(
        "Secret request from %s\n",
        req.RemoteAddr,
    )

    return goradius.SecretResponse{
        Secret: []byte("testing123"),
        UserData: map[string]string{
            "client":  req.RemoteAddr.String(),
            "nastype": "generic",
        },
    }, nil
}

func (h *myHandler) ServeRADIUS(
    req *goradius.Request,
) (goradius.Response, error) {
    fmt.Printf(
        "Received %s from %s\n",
        req.Code().String(), req.RemoteAddr,
    )

    resp := goradius.NewResponse(req)

    switch req.Code() {
    case goradius.CodeAccessRequest:
        resp.SetCode(goradius.CodeAccessAccept)
        resp.SetAttribute(
            "reply-message", "Access granted",
        )

    case goradius.CodeAccountingRequest:
        resp.SetCode(
            goradius.CodeAccountingResponse,
        )
    }

    return resp, nil
}

func main() {
    // Create dictionary
    dict, err := goradius.NewDefault()
    if err != nil {
        log.Fatal(err)
    }

    // Create server using functional options
    srv, err := goradius.NewServer(
        goradius.WithHandler(&myHandler{}),
        goradius.WithDictionary(dict),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create UDP listener
    conn, err := net.ListenUDP(
        "udp", &net.UDPAddr{Port: 1812},
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("RADIUS server listening on :1812")
    transport := goradius.NewUDPTransport(conn)
    log.Fatal(srv.Serve(transport))
}
```

## Handler Interface

The server requires a handler that implements two
methods:

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
    UserData map[string]string
}

func (h *myHandler) ServeSecret(
    req goradius.SecretRequest,
) (goradius.SecretResponse, error) {
    secret := lookupSecretForClient(
        req.RemoteAddr.String(),
    )

    return goradius.SecretResponse{
        Secret: []byte(secret),
        UserData: map[string]string{
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
    Packet     *goradius.Packet
    Secret     SecretResponse
}

func (h *myHandler) ServeRADIUS(
    req *goradius.Request,
) (goradius.Response, error) {
    resp := goradius.NewResponse(req)

    switch req.Code() {
    case goradius.CodeAccessRequest:
        if authenticateUser(req) {
            resp.SetCode(
                goradius.CodeAccessAccept,
            )
        } else {
            resp.SetCode(
                goradius.CodeAccessReject,
            )
        }

    case goradius.CodeAccountingRequest:
        handleAccounting(req)
        resp.SetCode(
            goradius.CodeAccountingResponse,
        )
    }

    return resp, nil
}
```

## Response Helper Methods

The Response object provides convenient methods:

### SetCode

Set the response packet code:

```go
resp.SetCode(goradius.CodeAccessAccept)
resp.SetCode(goradius.CodeAccessReject)
resp.SetCode(goradius.CodeAccountingResponse)
```

### SetAttribute

Add a single attribute by name:

```go
resp.SetAttribute(
    "reply-message", "Welcome!",
)
resp.SetAttribute(
    "framed-ip-address", "192.0.2.10",
)
resp.SetAttribute("session-timeout", 3600)
```

### SetAttributes

Add multiple attributes at once:

```go
attrs := map[string]interface{}{
    "reply-message":          "Access granted",
    "framed-ip-address":      "192.0.2.10",
    "session-timeout":        3600,
    "erx-primary-dns":        "8.8.8.8",
    "erx-service-activate:1": "ipoe-parking",
}
resp.SetAttributes(attrs)
```

## Authentication Example

```go
func (h *myHandler) ServeRADIUS(
    req *goradius.Request,
) (goradius.Response, error) {
    resp := goradius.NewResponse(req)

    if req.Code() !=
        goradius.CodeAccessRequest {
        return resp, nil
    }

    usernames := req.GetAttribute("user-name")
    if len(usernames) == 0 {
        resp.SetCode(goradius.CodeAccessReject)
        resp.SetAttribute(
            "reply-message",
            "Username required",
        )
        return resp, nil
    }
    username := usernames[0].String()

    if authenticateUser(
        username, req.Secret.Secret,
    ) {
        resp.SetCode(goradius.CodeAccessAccept)
        resp.SetAttribute(
            "reply-message", "Access granted",
        )

        attrs := map[string]interface{}{
            "framed-ip-address": "192.0.2.10",
            "session-timeout":   3600,
        }
        resp.SetAttributes(attrs)
    } else {
        resp.SetCode(goradius.CodeAccessReject)
        resp.SetAttribute(
            "reply-message",
            "Authentication failed",
        )
    }

    return resp, nil
}
```

## Accounting Example

```go
func (h *myHandler) ServeRADIUS(
    req *goradius.Request,
) (goradius.Response, error) {
    resp := goradius.NewResponse(req)

    if req.Code() !=
        goradius.CodeAccountingRequest {
        return resp, nil
    }

    statusAttrs := req.GetAttribute(
        "acct-status-type",
    )
    if len(statusAttrs) == 0 {
        return resp, fmt.Errorf(
            "missing acct-status-type",
        )
    }

    statusType := statusAttrs[0].String()

    switch statusType {
    case "start":
        handleAccountingStart(req)
    case "stop":
        handleAccountingStop(req)
    case "interim-update":
        handleAccountingUpdate(req)
    }

    resp.SetCode(
        goradius.CodeAccountingResponse,
    )
    return resp, nil
}

func handleAccountingStart(
    req *goradius.Request,
) {
    sessions := req.GetAttribute(
        "acct-session-id",
    )
    if len(sessions) > 0 {
        sessionID := sessions[0].String()
        fmt.Printf(
            "Session started: %s\n", sessionID,
        )
    }
}

func handleAccountingStop(
    req *goradius.Request,
) {
    sessions := req.GetAttribute(
        "acct-session-id",
    )
    inputOctets := req.GetAttribute(
        "acct-input-octets",
    )
    outputOctets := req.GetAttribute(
        "acct-output-octets",
    )
    sessionTime := req.GetAttribute(
        "acct-session-time",
    )

    if len(sessions) > 0 &&
        len(inputOctets) > 0 &&
        len(outputOctets) > 0 &&
        len(sessionTime) > 0 {
        fmt.Printf(
            "Session %s ended: "+
                "%s bytes in, "+
                "%s bytes out, "+
                "%s seconds\n",
            sessions[0].String(),
            inputOctets[0].String(),
            outputOctets[0].String(),
            sessionTime[0].String(),
        )
    }
}
```

## Transport Interface

The server supports multiple transport protocols
through the Transport interface. This allows running
RADIUS over UDP (standard), TCP, or TLS (RadSec).

### Transport Types

#### UDP Transport (Default)

For standard RADIUS over UDP:

```go
srv, err := goradius.NewServer(
    goradius.WithHandler(handler),
)
if err != nil {
    log.Fatal(err)
}

conn, err := net.ListenUDP(
    "udp", &net.UDPAddr{Port: 1812},
)
if err != nil {
    log.Fatal(err)
}

transport := goradius.NewUDPTransport(conn)
log.Fatal(srv.Serve(transport))
```

#### TCP Transport

For RADIUS over TCP (RFC 6613):

```go
srv, err := goradius.NewServer(
    goradius.WithHandler(handler),
)
if err != nil {
    log.Fatal(err)
}

listener, err := net.Listen("tcp", ":1812")
if err != nil {
    log.Fatal(err)
}

transport := goradius.NewTCPTransport(listener)
log.Fatal(srv.Serve(transport))
```

#### TLS Transport (RadSec)

For RADIUS over TLS (RFC 6614, RadSec):

```go
srv, err := goradius.NewServer(
    goradius.WithHandler(handler),
)
if err != nil {
    log.Fatal(err)
}

cert, err := tls.LoadX509KeyPair(
    "server.crt", "server.key",
)
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}

listener, err := tls.Listen(
    "tcp", ":2083", tlsConfig,
)
if err != nil {
    log.Fatal(err)
}

transport := goradius.NewTCPTransport(listener)
log.Fatal(srv.Serve(transport))
```

### Transport Interface Definition

```go
type Transport interface {
    Serve(handler TransportHandler) error
    LocalAddr() net.Addr
    Close() error
}

type TransportHandler func(
    data []byte,
    remoteAddr net.Addr,
    respond ResponderFunc,
)

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
            "192.168.1.1": "secret1",
            "192.168.1.2": "secret2",
            "10.0.0.0/24": "shared-secret",
        },
    }
}

func (s *SecretStore) ServeSecret(
    req goradius.SecretRequest,
) (goradius.SecretResponse, error) {
    clientIP := req.RemoteAddr.(*net.UDPAddr).
        IP.String()

    secret, found := s.secrets[clientIP]
    if !found {
        secret = "default-secret"
    }

    return goradius.SecretResponse{
        Secret: []byte(secret),
        UserData: map[string]string{
            "client": clientIP,
        },
    }, nil
}
```

## Server Control

### Graceful Shutdown

```go
srv, err := goradius.NewServer(
    goradius.WithHandler(handler),
    goradius.WithDictionary(dict),
)
if err != nil {
    log.Fatal(err)
}

conn, err := net.ListenUDP(
    "udp", &net.UDPAddr{Port: 1812},
)
if err != nil {
    log.Fatal(err)
}
transport := goradius.NewUDPTransport(conn)

go func() {
    if err := srv.Serve(transport); err != nil {
        log.Printf("Server error: %v\n", err)
    }
}()

sigChan := make(chan os.Signal, 1)
signal.Notify(
    sigChan, os.Interrupt, syscall.SIGTERM,
)
<-sigChan

log.Println("Shutting down...")
srv.Close()
```

## Complete Example

See `cmd/simple-server/main.go` in the repository
for a complete working example.
