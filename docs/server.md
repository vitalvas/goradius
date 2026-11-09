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

    "go.vitalvas.com/goradius"
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

## Server Options

| Option | Default | Description |
|---|---|---|
| `WithHandler(h)` | none | Handler implementing `ServeSecret` and `ServeRADIUS` |
| `WithDictionary(dict)` | `NewDefault()` | Dictionary attached to every decoded request |
| `WithMessageAuthPolicy(p)` | `MessageAuthPolicyAuto` | Message-Authenticator policy, see Secret Management below |
| `WithRequireRequestAuthenticator(b)` | `true` | Validate the computed Request Authenticator of Accounting, CoA, and Disconnect requests |
| `WithRequestTimeout(d)` | none | Deadline on the context passed to `ServeSecret` and `ServeRADIUS` |

The request timeout only sets the deadline on
`req.Context`; handlers that do slow work must observe
it themselves.

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
    Secret            []byte
    UserData          map[string]string
    MessageAuthPolicy goradius.MessageAuthPolicy
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

Replace multiple attributes at once. Every value is a
slice, and each element becomes one attribute
instance. Existing instances of each key are removed
first:

```go
err := resp.SetAttributes(map[string][]any{
    "reply-message":          {"Access granted"},
    "framed-ip-address":      {"192.0.2.10"},
    "session-timeout":        {3600},
    "erx-primary-dns":        {"8.8.8.8", "8.8.4.4"},
    "erx-service-activate:1": {"ipoe-parking"},
})
```

A `name:tag` key replaces only the instances carrying
that tag. Container members (struct, TLV, and EVS
children) are addressed by their own flat child name
and are grouped into one container instance.

### AddAttribute and AddAttributes

Append without removing existing instances:

```go
resp.AddAttribute("reply-message", "Line one")
resp.AddAttribute("reply-message", "Line two")

resp.AddAttributes(map[string][]any{
    "erx-service-activate:2": {"svc-video"},
})
```

### DeleteAttribute

Remove every instance of an attribute, or only the
instances with a given tag. Returns the number of
attributes removed:

```go
removed := resp.DeleteAttribute("reply-message")
resp.DeleteAttribute("erx-service-activate:1")
```

### Inspecting a Response

Middleware can read a response produced by the inner
handler:

```go
code := resp.Code()
names := resp.ListAttributes()
values := resp.GetAttribute("framed-ip-address")
strs := resp.GetAttributeStrings() // name -> String() values
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

        resp.SetAttributes(map[string][]any{
            "framed-ip-address": {"192.0.2.10"},
            "session-timeout":   {3600},
        })
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

## Middleware

A `Middleware` wraps a `Handler` and returns a new
one. `HandlerFunc` adapts a plain function to the
`Handler` interface; its `ServeSecret` returns an
empty secret, so secrets always come from the handler
at the core of the chain:

```go
func logging(next goradius.Handler) goradius.Handler {
    return goradius.HandlerFunc(func(
        req *goradius.Request,
    ) (goradius.Response, error) {
        start := time.Now()
        resp, err := next.ServeRADIUS(req)
        log.Printf(
            "%s from %s -> %s in %s",
            req.Code(), req.RemoteAddr,
            resp.Code(), time.Since(start),
        )
        return resp, err
    })
}

srv.Use(validation)
srv.Use(logging) // outermost
```

The last middleware added is the outermost: it sees
the request first and the response last. The chain is
composed per request, so every `Use` call made so far
applies to the next packet.

Middleware runs after secret lookup and packet
validation, so `req.Secret` is already resolved.
Returning an error, or a zero `Response`, drops the
request without a reply. Handlers run concurrently,
one goroutine per packet, so shared state in a
middleware must be synchronized. See
`examples/advanced-server/main.go` for logging,
validation, and statistics middleware.

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

### Secret Rotation

Set `Attempts` on the `SecretResponse` returned for
attempt 0 to the number of secrets a client may be
using. When that secret fails to validate the packet,
the server calls `ServeSecret` again with `Attempt`
set to 1, 2, and so on up to `Attempts - 1`, and uses
the first secret that validates. A value of 0 or 1
disables rotation:

```go
func (s *SecretStore) ServeSecret(
    req goradius.SecretRequest,
) (goradius.SecretResponse, error) {
    secrets := []string{"new-secret", "old-secret"}
    if req.Attempt >= len(secrets) {
        return goradius.SecretResponse{},
            fmt.Errorf("no more secrets")
    }

    return goradius.SecretResponse{
        Secret:   []byte(secrets[req.Attempt]),
        Attempts: len(secrets),
    }, nil
}
```

The request handed to `ServeRADIUS` carries the
secret that validated in `req.Secret`. Validation
relies on the Request Authenticator and
Message-Authenticator checks described below, so an
Access-Request without a Message-Authenticator cannot
be matched against any secret and the first one is
used.

### Request Authenticator Validation

The computed Request Authenticator of Accounting-Request, CoA-Request,
and Disconnect-Request packets is validated by default and invalid
packets are silently discarded (RFC 2866 Section 3, RFC 5176
Section 3.3, RFC 5080 Section 2.3.3). Every compliant device computes
it from the shared secret, so this costs no interoperability; use
`WithRequireRequestAuthenticator(false)` only for devices that compute
it incorrectly. Access-Request and Status-Server carry a random
authenticator and are never subject to this check.

### Message-Authenticator Policy

`WithMessageAuthPolicy` selects how the server treats the
Message-Authenticator attribute (RFC 2869 Section 5.14) for the whole
fleet. The default is `MessageAuthPolicyAuto`:

| Policy | Access-Request | Accounting, CoA, Disconnect | Replies carry it |
|---|---|---|---|
| `MessageAuthPolicyAuto` (default) | Optional until the device has sent one valid attribute, required from that device afterwards | Optional | Yes |
| `MessageAuthPolicyRequired` | Required | Required | Yes |
| `MessageAuthPolicyOptional` | Optional | Optional | Yes |
| `MessageAuthPolicyDisabled` | Optional | Optional | No |

Two rules hold under every policy. A Message-Authenticator that is
present is always verified and the packet silently dropped on mismatch
(RFC 3579 Section 3.2). Status-Server always requires one (RFC 5997).

#### Auto Mode for Mixed Fleets

Auto mode is the FreeRADIUS `require_message_authenticator = auto`
behaviour. A device is identified by its source IP. Access-Requests
from a device are accepted with or without the attribute until one of
them carries a Message-Authenticator that verifies under the device's
secret. From then on the device is recorded and its Access-Requests
without the attribute are dropped. End-of-life devices that never send
it keep working, and devices that do send it are protected from the
second packet on.

Only a verified attribute records a device, so a forged one can neither
lock a legitimate device out nor fill the table. The table is
in-process and starts empty on each server start.

A device that sends the attribute for some Access-Requests only, for
example EAP but not PAP, is locked out after its first one. Give such a
device a per-device override.

#### Strict Mode

Every request type must carry a verified Message-Authenticator,
including Accounting, CoA, and Disconnect:

```go
srv, err := goradius.NewServer(
    goradius.WithHandler(handler),
    goradius.WithMessageAuthPolicy(goradius.MessageAuthPolicyRequired),
)
```

#### Per-Device Override

`MessageAuthPolicy` on `SecretResponse` overrides the server-wide
policy for that device. `MessageAuthPolicyDefault` defers to the
server:

```go
return goradius.SecretResponse{
    Secret:            []byte(secret),
    MessageAuthPolicy: goradius.MessageAuthPolicyDisabled,
}, nil
```

A strict fleet can keep one legacy device on `Optional` or `Disabled`,
and a mixed fleet can pin a device to `Required`, without changing the
server-wide policy. `Disabled` also omits the attribute from replies to
that device. RFC 3579 requires it in replies carrying EAP-Message, so
reserve `Disabled` for devices that need it.

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

`Close` closes every transport passed to `Serve` and
is safe to call more than once. A later `Serve` call
returns `ErrServerClosed`.

### Multiple Transports

`Serve` may be called once per transport to listen on
several sockets with one server, for example UDP on
the authentication and accounting ports. Each request
reports the socket it arrived on in `LocalAddr` of
both `SecretRequest` and `Request`, so `ServeSecret`
can key secrets per listener. `Addr` returns the
first transport's address and blocks until `Serve`
has been called.

### Processing Packets Without a Transport

`ProcessRawPacket` runs the full pipeline on raw
bytes: secret lookup and rotation, validation,
middleware, the handler, and the response
authenticators. It returns the reply bytes, or nil
when the packet was dropped or the handler chose not
to respond, and works without ever calling `Serve`:

```go
reply, err := srv.ProcessRawPacket(data, remoteAddr)
if err == nil && reply != nil {
    conn.WriteTo(reply, remoteAddr)
}
```

The server does not copy `data`, so the caller must
not modify it during the call.

## Complete Example

See `examples/simple-server/main.go` in the repository
for a complete working example.
