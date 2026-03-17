# GoRADIUS

A comprehensive Go library for implementing RADIUS
(Remote Authentication Dial-In User Service) servers
and clients according to RFC 2865, RFC 2866,
and related specifications.

## Features

### Core RADIUS Protocol Support

- **RFC 2865**: Remote Authentication Dial-In User Service
- **RFC 2866**: RADIUS Accounting
- **RFC 2868**: Tunnel Protocol Support (Tagged Attributes)
- **RFC 2869**: RADIUS Extensions
- **RFC 3576**: Dynamic Authorization Extensions (CoA/Disconnect)
- Full packet encoding/decoding with validation
- Support for all standard RADIUS packet types
- Comprehensive attribute handling with type safety

### Transport Protocols

- **UDP**: Standard RADIUS transport (RFC 2865)
- **TCP**: RADIUS over TCP (RFC 6613)
- **TLS**: RADIUS over TLS / RadSec (RFC 6614)

### Security Features

- Request/response authenticator calculation and verification
- Message-Authenticator attribute support (HMAC-MD5, RFC 2869)
- User-Password encryption (RFC 2865)
- Tunnel-Password encryption (RFC 2868)
- Ascend-Secret encryption
- Cryptographic packet validation using MD5 (RFC required)

### Dictionary Support

- Efficient in-memory attribute dictionary system
- Fast O(1) attribute lookups by ID and name
- Support for vendor-specific attributes (VSAs)
- Type validation for all attribute types
- Tagged attribute support (RFC 2868)
- Enumerated value support
- Built-in RFC and vendor dictionaries (ERX, Ascend)

### Server Features

- Multi-transport RADIUS server (UDP, TCP, TLS)
- Concurrent request handling with goroutines
- Flexible handler interface
- Middleware support for request processing
- Per-client secret management
- Dictionary-based attribute validation
- Graceful shutdown with in-flight request completion

### Client Features

- Full RADIUS client implementation
- Access-Request for authentication
- Accounting-Request for accounting
- Dynamic Authorization (CoA/Disconnect)
- Configurable timeout support
- Attribute-based request building
- Response validation

### Packet Features

- Dictionary-based attribute manipulation
- Type-safe attribute handling
- VSA (Vendor-Specific Attribute) support
- Tagged attribute handling
- Automatic password encryption with dictionaries

## Definition of Done (SDK Goals)

GoRADIUS targets developers who need to ship RADIUS
integrations without becoming protocol experts.
The library is considered "done" when it delivers
a batteries-included SDK for both server and client
use cases with the following traits:

- **High-level server workflow**: Handlers receive
  already-parsed attribute sets, apply business rules,
  and send attributes back via a fluent response builder.
  Low-level details such as packet encoding,
  authenticators, retries, and dictionary lookups
  stay inside the library.
- **High-level client workflow**: Callers describe
  the attributes they want to send and receive parsed
  attributes in return. Session management,
  retransmissions, and message authentication are
  handled automatically.
- **Protocol expertise optional**: Exhaustive
  dictionaries, sane defaults, guardrails, and
  validation should make it possible to build a RADIUS
  client or server while only thinking about the
  business domain.
- **Composable SDK building blocks**: Helpers,
  middleware hooks, and extensibility points should
  allow mixing low-level and high-level APIs as needed
  without leaking protocol complexity into business
  logic.

## Architecture

GoRADIUS centers around three layers:

1. **Transport/server layer** that listens on network
   sockets (UDP, TCP, or TLS), manages authenticators,
   and orchestrates request handling.
2. **Packet and dictionary layer** that owns
   encoding/decoding, attribute mapping, vendor logic,
   and validation.
3. **Business logic layer** where developers plug
   custom handlers or client calls, only
   receiving/sending attribute sets.

## Quick Start

### Basic RADIUS Server Flow

1. Create a dictionary with standard attributes
   (and optionally vendor extensions).
2. Instantiate the UDP server with a handler
   implementation.
3. Implement `ServeSecret` to return the shared secret
   for each client.
4. Implement `ServeRADIUS` to inspect the parsed
   request attributes, run business logic, and populate
   the response attributes/code.
5. Call `Serve()` to start processing requests
   concurrently.

## Package Structure

GoRADIUS uses a flat package structure where all types
and functions are exported from the root `goradius`
package.

### Key Components

#### Packet Processing

- Packet encoding/decoding (Encode/Decode)
- Attribute creation and manipulation
- Vendor-Specific Attribute (VSA) support
- Tagged attribute handling
- Value encoding/decoding helpers
- Authenticator calculation
- Message-Authenticator calculation and verification
- Password encryption (User-Password, Tunnel-Password,
  Ascend-Secret)

#### Dictionary System

- Fast O(1) lookups by attribute ID or name
- Vendor attribute lookups
- Standard RFC attributes
- Vendor-specific attributes
- Data type definitions
- Encryption type support
- Enumerated values

#### Server

- Multi-transport RADIUS server (UDP, TCP, TLS)
- Functional options configuration pattern
- Transport interface for pluggable network backends
- Handler interface for request processing
- Middleware support
- Secret management per client
- Response helper functions
- Graceful shutdown

#### Client

- Functional options configuration pattern
- Access-Request for authentication
- Accounting-Request for accounting
- CoA (Change-of-Authorization) request support
- Disconnect request support
- Configurable timeout
- Dictionary-based attribute handling
- Automatic authenticator generation

#### Built-in Dictionaries

- Standard RFC attributes (RFC 2865, 2866, etc.)
- Juniper ERX vendor attributes
- Ascend vendor attributes

## Usage Examples

### Creating Packets with Dictionary

- Instantiate a dictionary, register standard and
  vendor definitions, then create packets with
  `NewWithDictionary`.
- Attributes can be added by name, including
  vendor-specific or tagged variants, without
  remembering numeric IDs.
- The packet layer enforces type safety, value
  encoding, and authenticator calculation
  automatically.

### Working with VSAs

- Use vendor helper functions to create attributes
  for a given vendor ID and attribute code, then
  attach them to the packet.
- Retrieve vendor attributes through lookup helpers
  that return both the attribute and a flag indicating
  whether it was present.
- Vendor helpers allow working with dictionary metadata
  so business logic references human-readable names
  instead of numeric identifiers.

## Standards Compliance

This library implements the following RFCs:

- **RFC 2865**: Remote Authentication Dial-In User
  Service (RADIUS)
- **RFC 2866**: RADIUS Accounting
- **RFC 2868**: RADIUS Attributes for Tunnel Protocol
  Support
- **RFC 2869**: RADIUS Extensions
- **RFC 3576**: Dynamic Authorization Extensions
  to RADIUS
- **RFC 6613**: RADIUS over TCP
- **RFC 6614**: TLS Encryption for RADIUS (RadSec)

## Examples

### Server Example

See `cmd/simple-server/main.go` for a working example
of a basic RADIUS server with middleware support.

### Client Example

See `cmd/radclient/main.go` for a command-line tool
that sends CoA and Disconnect requests.

## Documentation

Detailed documentation is available in the `docs/`
directory:

- [Dictionary Usage](docs/dictionary.md)
- [Packet Handling](docs/packets.md)
- [Server Usage](docs/server.md)
