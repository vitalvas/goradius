# RADIUS Client Usage

This guide covers how to send RADIUS requests with
the GoRADIUS client.

## Creating a Client

```go
import (
    "log"

    "go.vitalvas.com/goradius"
)

dict, err := goradius.NewDefault()
if err != nil {
    log.Fatal(err)
}

cl, err := goradius.NewClient(
    goradius.WithAddr("192.0.2.1:1812"),
    goradius.WithSecret([]byte("testing123")),
    goradius.WithClientDictionary(dict),
)
if err != nil {
    log.Fatal(err)
}
defer cl.Close()
```

### Client Options

| Option | Default | Description |
|---|---|---|
| `WithAddr(addr)` | none | Server address as `host:port` |
| `WithSecret(secret)` | none | Shared secret |
| `WithClientDictionary(dict)` | none | Dictionary used to encode request attributes and decode replies |
| `WithTimeout(d)` | 3 seconds | Deadline for one request, covering dial, write, and read |
| `WithTransport(t)` | `TransportUDP` | `TransportUDP`, `TransportTCP`, or `TransportTLS` |
| `WithTLSConfig(cfg)` | none | TLS configuration, required with `TransportTLS` |
| `WithClientUseMessageAuthenticator(b)` | `true` | Add Message-Authenticator to every request |
| `WithVerifyMessageAuthenticator(b)` | `true` | Require Message-Authenticator in replies to Access-Request and Status-Server |

A dictionary is required to add attributes by name.
Without one every request method fails when it tries
to add an attribute.

## Sending Requests

Each request method takes a flat attribute map keyed
by lowercase dictionary name, with the `name:tag`
notation for tagged attributes, and returns the
verified reply packet.

### Access-Request

```go
resp, err := cl.AccessRequest(map[string]any{
    "user-name":      "john.doe",
    "user-password":  "secret123",
    "nas-ip-address": "192.0.2.10",
})
if err != nil {
    log.Fatal(err)
}

switch resp.Code {
case goradius.CodeAccessAccept:
    for _, msg := range resp.GetAttribute("reply-message") {
        log.Println(msg.String())
    }
case goradius.CodeAccessChallenge:
    state := resp.GetAttribute("state")
    // continue the exchange with the returned state
case goradius.CodeAccessReject:
    log.Println("rejected")
}
```

The request carries a random Request Authenticator.
User-Password and other encrypted attributes are
encrypted with it transparently before the packet is
sent.

### Accounting-Request

```go
resp, err := cl.AccountingRequest(map[string]any{
    "acct-status-type": "start",
    "acct-session-id":  "sess-0001",
    "user-name":        "john.doe",
    "nas-ip-address":   "192.0.2.10",
})
if err != nil {
    log.Fatal(err)
}
// resp.Code is CodeAccountingResponse
```

### CoA-Request and Disconnect-Request

Dynamic Authorization (RFC 5176) requests are sent
to the device, usually on port 3799:

```go
cl, err := goradius.NewClient(
    goradius.WithAddr("192.0.2.10:3799"),
    goradius.WithSecret([]byte("testing123")),
    goradius.WithClientDictionary(dict),
)
if err != nil {
    log.Fatal(err)
}
defer cl.Close()

resp, err := cl.CoA(map[string]any{
    "user-name":              "john.doe",
    "acct-session-id":        "sess-0001",
    "erx-service-activate:1": "ipoe-parking",
})
if err != nil {
    log.Fatal(err)
}
if resp.Code != goradius.CodeCoAACK {
    log.Printf("CoA rejected: %s", resp.Code)
}

resp, err = cl.Disconnect(map[string]any{
    "user-name":       "john.doe",
    "acct-session-id": "sess-0001",
})
if err != nil {
    log.Fatal(err)
}
if resp.Code != goradius.CodeDisconnectACK {
    log.Printf("Disconnect rejected: %s", resp.Code)
}
```

Accounting, CoA, and Disconnect requests compute the
Request Authenticator from the shared secret as
their RFCs require. The Message-Authenticator is
inserted first and the Request Authenticator is then
computed over the packet carrying it (RFC 5176
Section 3.4).

Attribute usage masks from the dictionary apply to
client requests as well: an attribute the dictionary
does not allow in the request type is skipped.

## Reading Replies

The returned packet already carries the dictionary,
the shared secret, and the Request Authenticator of
the request it answers. Encrypted reply attributes
such as MPPE keys decrypt transparently:

```go
keys := resp.GetAttribute("ms-mppe-send-key")
if len(keys) > 0 {
    sendKey := keys[0].Value // plaintext key bytes
}

for _, name := range resp.ListAttributes() {
    for _, v := range resp.GetAttribute(name) {
        log.Printf("%s = %s", name, v.String())
    }
}
```

See [packets.md](packets.md) for the full attribute
API.

## Reply Verification

Every candidate reply is checked before it is
returned:

- The Identifier must match the request.
- The Response Authenticator must match (RFC 2865
  Section 3).
- A Message-Authenticator that is present is always
  verified (RFC 3579 Section 3.2). Its absence is an
  error only for Access-Request and Status-Server
  replies, and only while
  `WithVerifyMessageAuthenticator` is on. Replies to
  Accounting, CoA, and Disconnect carry it optionally
  (RFC 2866, RFC 5176).

### Legacy Servers

Not every device supports Message-Authenticator. To
talk to a server that neither expects it in requests
nor sends it in replies, turn both off. A
Message-Authenticator that the server does send is
still verified:

```go
cl, err := goradius.NewClient(
    goradius.WithAddr("192.0.2.1:1812"),
    goradius.WithSecret([]byte("testing123")),
    goradius.WithClientDictionary(dict),
    goradius.WithClientUseMessageAuthenticator(false),
    goradius.WithVerifyMessageAuthenticator(false),
)
```

The server detects support per device automatically
by default and offers strict, optional, and disabled
modes through `WithMessageAuthPolicy` server-wide
and `SecretResponse.MessageAuthPolicy` per device;
see [server.md](server.md).

On UDP a reply that fails verification is discarded
and the client keeps reading until a valid reply
arrives or the timeout expires, so a stray or
spoofed datagram cannot abort the exchange (RFC 2865
Section 4.2). On TCP and TLS the stream is framed by
the server, so the first packet is authoritative and
a verification failure is returned as an error.

## Transports

Each request opens its own connection and closes it
once the reply has been read.

### TCP

```go
cl, err := goradius.NewClient(
    goradius.WithAddr("192.0.2.1:1812"),
    goradius.WithSecret([]byte("testing123")),
    goradius.WithClientDictionary(dict),
    goradius.WithTransport(goradius.TransportTCP),
)
```

### TLS (RadSec)

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    RootCAs:    pool,
}

cl, err := goradius.NewClient(
    goradius.WithAddr("radsec.example.net:2083"),
    goradius.WithSecret([]byte("radsec")),
    goradius.WithClientDictionary(dict),
    goradius.WithTransport(goradius.TransportTLS),
    goradius.WithTLSConfig(tlsConfig),
)
```

## Closing

`Close` cancels any in-flight request and releases
resources. It is safe to call more than once. After
`Close`, every request method returns
`ErrClientClosed`:

```go
cl.Close()

_, err := cl.AccessRequest(attrs)
if errors.Is(err, goradius.ErrClientClosed) {
    // client is no longer usable
}
```

## Complete Example

See `examples/radclient/main.go` in the repository
for a CoA and Disconnect command-line tool built on
the client.
