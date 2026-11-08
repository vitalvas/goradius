# GoRADIUS

Go library for RADIUS servers and clients
(RFC 2865, RFC 2866, RFC 2868, RFC 2869, RFC 3162,
RFC 5176, RFC 6613, RFC 6614, RFC 6929).

## Features

- Server and client with UDP, TCP (RFC 6613), and
  TLS / RadSec (RFC 6614)
- Packet encoding/decoding with attribute type safety
- Built-in dictionary with RFC and vendor attributes
  (Juniper, ERX, Ascend, Mikrotik, WISPr, Cisco,
  DSL Forum, Microsoft, F5, A10, Arista, Arista WiFi,
  Ciena, Benu, ZTE, Huawei, Alcatel, Alcatel-Lucent AAA,
  Alcatel-ESAM, Nokia SR, ADVA, Ericsson,
  Ericsson-AB, Ericsson Packet Core Networks, 3GPP)
- Vendor-Specific Attributes (VSA) and tagged
  attributes (RFC 2868)
- IPv6 attributes: ipv6addr, ipv6prefix, and
  interface-id types (RFC 3162)
- Complex attribute types: TLV, struct, and RFC 6929
  extended / long-extended / vendor-specific (EVS)
  attributes
- Password encryption (User-Password, Tunnel-Password,
  Ascend-Secret)
- Message-Authenticator (HMAC-MD5, RFC 2869) with
  automatic per-device detection as in FreeRADIUS,
  plus strict, optional, and disabled modes
  server-wide or per device
- CHAP challenge and response helpers (RFC 2865)
- Middleware support and per-client secret management
  with secret rotation
- Dynamic Authorization (CoA/Disconnect, RFC 5176)
- Graceful shutdown

## Documentation

- [docs/server.md](docs/server.md) - server setup,
  handlers, middleware, transports, secrets
- [docs/client.md](docs/client.md) - sending
  Access, Accounting, CoA, and Disconnect requests
- [docs/packets.md](docs/packets.md) - packets,
  attributes, encoding, encryption
- [docs/dictionary.md](docs/dictionary.md) -
  dictionaries, data types, vendors, containers

## Examples

- `examples/simple-server/` - basic RADIUS server
- `examples/advanced-server/` - server with middleware
- `examples/radclient/` - CoA/Disconnect client tool
