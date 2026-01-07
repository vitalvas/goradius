# GoRADIUS

A comprehensive Go library for implementing RADIUS (Remote Authentication Dial-In User Service) servers and clients according to RFC 2865, RFC 2866, and related specifications.

## Features

### Core RADIUS Protocol Support
- **RFC 2865**: Remote Authentication Dial-In User Service (RADIUS)
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
- Dynamic Authorization (CoA/Disconnect) for session management
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

GoRADIUS targets developers who need to ship RADIUS integrations without becoming protocol experts. The library is considered “done” when it delivers a batteries-included SDK for both server and client use cases with the following traits:

- **High-level server workflow**: Handlers receive already-parsed attribute sets, apply business rules, and send attributes back via a fluent response builder. Low-level details such as packet encoding, authenticators, retries, and dictionary lookups stay inside the library.
- **High-level client workflow**: Callers describe the attributes they want to send (e.g., Access-Request, Accounting-Request) and receive parsed attributes in return. Session management, retransmissions, and message authentication are handled automatically, so client code resembles `send attributes → wait for attributes`.
- **Protocol expertise optional**: Exhaustive dictionaries, sane defaults, guardrails, and validation should make it possible to build a RADIUS client or server while only thinking about the business domain (authorize a user, record accounting data, etc.).
- **Composable SDK building blocks**: Helpers, middleware hooks, and extensibility points should allow mixing low-level and high-level APIs as needed without leaking protocol complexity into business logic.

## Architecture

GoRADIUS centers around three layers:

1. **Transport/server layer** that listens on network sockets (UDP, TCP, or TLS), manages authenticators, and orchestrates request handling.
2. **Packet and dictionary layer** that owns encoding/decoding, attribute mapping, vendor logic, and validation.
3. **Business logic layer** where developers plug custom handlers or client calls, only receiving/sending attribute sets.

## Quick Start

### Basic RADIUS Server Flow

1. Create a dictionary with standard attributes (and optionally vendor extensions).
2. Instantiate the UDP server with a handler implementation.
3. Implement `ServeSecret` to return the shared secret for each client.
4. Implement `ServeRADIUS` to inspect the parsed request attributes, run business logic, and populate the response attributes/code.
5. Call `Serve()` to start processing requests concurrently.

## Package Structure

### Core Packages

- **`pkg/packet`**: RADIUS packet encoding, decoding, and attribute handling
- **`pkg/server`**: Simple RADIUS UDP server implementation
- **`pkg/client`**: Full RADIUS client (Access, Accounting, CoA/Disconnect)
- **`pkg/dictionary`**: In-memory attribute dictionary with fast lookups
- **`pkg/dictionaries`**: Built-in RFC and vendor dictionary definitions

### Key Components

#### Packet Processing (pkg/packet)
- Packet encoding/decoding (Encode/Decode)
- Attribute creation and manipulation
- Vendor-Specific Attribute (VSA) support
- Tagged attribute handling
- Value encoding/decoding helpers
- Authenticator calculation
- Message-Authenticator calculation and verification (HMAC-MD5)
- Password encryption (User-Password, Tunnel-Password, Ascend-Secret)

#### Dictionary System (pkg/dictionary)
- Fast O(1) lookups by attribute ID or name
- Vendor attribute lookups
- Standard RFC attributes
- Vendor-specific attributes
- Data type definitions
- Encryption type support
- Enumerated values

#### Server (pkg/server)
- Multi-transport RADIUS server (UDP, TCP, TLS)
- Transport interface for pluggable network backends
- Handler interface for request processing
- Middleware support
- Secret management per client
- Response helper functions
- Graceful shutdown

#### Client (pkg/client)
- Access-Request for authentication
- Accounting-Request for accounting (Start, Stop, Interim-Update)
- CoA (Change-of-Authorization) request support
- Disconnect request support
- Configurable timeout
- Dictionary-based attribute handling
- Automatic authenticator generation

#### Built-in Dictionaries (pkg/dictionaries)
- Standard RFC attributes (RFC 2865, 2866, etc.)
- Juniper ERX vendor attributes
- Ascend vendor attributes

## Usage Examples

### Creating Packets with Dictionary

- Instantiate a dictionary, register standard and vendor definitions, then create packets with `NewWithDictionary`.
- Attributes can be added by name, including vendor-specific or tagged variants, without remembering numeric IDs.
- The packet layer enforces type safety, value encoding, and authenticator calculation automatically.

### Working with VSAs

- Use vendor helper functions to create attributes for a given vendor ID and attribute code, then attach them to the packet.
- Retrieve vendor attributes through lookup helpers that return both the attribute and a flag indicating whether it was present.
- Vendor helpers allow working with dictionary metadata so business logic references human-readable names instead of numeric identifiers.

## Standards Compliance

This library implements the following RFCs:

- **RFC 2865**: Remote Authentication Dial-In User Service (RADIUS)
- **RFC 2866**: RADIUS Accounting
- **RFC 2868**: RADIUS Attributes for Tunnel Protocol Support
- **RFC 2869**: RADIUS Extensions
- **RFC 3576**: Dynamic Authorization Extensions to RADIUS
- **RFC 6613**: RADIUS over TCP
- **RFC 6614**: TLS Encryption for RADIUS (RadSec)

## Performance

- Concurrent request handling with goroutines
- Efficient O(1) dictionary lookups using hash maps
- Memory-efficient packet encoding/decoding
- Pre-allocated attribute structures

## Security Considerations

- **MD5 Usage**: This library uses MD5 for RADIUS authenticator calculation and HMAC-MD5 for Message-Authenticator as required by RFC 2865 and RFC 2869. While MD5 is cryptographically weak, it is mandated by the RADIUS specification.
- **Message-Authenticator**: Use the Message-Authenticator attribute (RFC 2869) for additional packet integrity verification, especially for EAP and other sensitive operations. This provides HMAC-MD5 based authentication of the entire packet.
- **Shared Secrets**: Always use strong, random shared secrets (minimum 16 characters recommended)
- **Password Encryption**: User passwords are encrypted using the RFC-specified algorithm when using dictionary-based attribute methods
- **Network Security**: RADIUS transmits over UDP without built-in transport encryption. Use network-level security (VPN, private networks) for production deployments
- **Input Validation**: All packet decoding includes length and structure validation to prevent malformed packet attacks
- **Constant-Time Comparison**: Message-Authenticator verification uses constant-time comparison to prevent timing attacks

## Project Status

This is an active RADIUS library implementation with the following status:

**Implemented:**
- ✅ RADIUS packet encoding/decoding
- ✅ Standard attribute handling
- ✅ Vendor-Specific Attributes (VSAs)
- ✅ Dictionary system with fast lookups
- ✅ Multi-transport server (UDP, TCP, TLS/RadSec) with middleware support
- ✅ Password encryption (User-Password, Tunnel-Password, Ascend-Secret)
- ✅ Tagged attributes (RFC 2868)
- ✅ Authenticator calculation and verification
- ✅ Message-Authenticator attribute (HMAC-MD5, RFC 2869)
- ✅ Full RADIUS client (Access-Request, Accounting-Request, CoA/Disconnect)

**Not Yet Implemented:**
- ❌ EAP support
- ❌ Client retransmission logic

## Examples

### Server
See `cmd/simple-server/main.go` for a working example of a basic RADIUS server with middleware support.

### Client
See `cmd/radclient/main.go` for a command-line tool that sends CoA and Disconnect requests.

## Documentation

Detailed documentation is available in the `docs/` directory:
- [Dictionary Usage](docs/docs/dictionary.md)
- [Packet Handling](docs/docs/packets.md)
