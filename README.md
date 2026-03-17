# GoRADIUS

Go library for RADIUS servers and clients
(RFC 2865, RFC 2866, RFC 2868, RFC 2869).

## Features

- Server and client with UDP, TCP, TLS (RadSec)
- Packet encoding/decoding with attribute type safety
- Built-in dictionary with RFC and vendor attributes
  (Juniper, ERX, Ascend, Mikrotik, WISPr)
- Vendor-Specific Attributes (VSA) and tagged
  attributes (RFC 2868)
- Password encryption (User-Password, Tunnel-Password,
  Ascend-Secret)
- Message-Authenticator (HMAC-MD5, RFC 2869)
- Middleware support and per-client secret management
  with secret rotation
- Dynamic Authorization (CoA/Disconnect, RFC 3576)
- Graceful shutdown

## Examples

- `cmd/simple-server/` - basic RADIUS server
- `cmd/advanced-server/` - server with middleware
- `cmd/radclient/` - CoA/Disconnect client tool
