# RADIUS Packet Handling

This guide covers how to work with RADIUS packets, attributes, and encoding/decoding in the GoRADIUS library.

## Packet Structure

RADIUS packets follow the structure defined in RFC 2865:

```mermaid
graph LR
    A[Code - 1 byte] --> B[Identifier - 1 byte]
    B --> C[Length - 2 bytes]
    C --> D[Authenticator - 16 bytes]
    D --> E[Attributes - Variable]
```

### Packet Fields

- **Code**: Identifies the packet type (Access-Request, Access-Accept, etc.)
- **Identifier**: Unique identifier for matching requests and responses
- **Length**: Total length of the packet in bytes
- **Authenticator**: 16-byte field for authentication and integrity
- **Attributes**: Variable-length attribute-value pairs

## Creating Packets

### Basic Packet Creation

```go
import "github.com/vitalvas/goradius/pkg/packet"

// Create a new Access-Request packet
req := packet.New(packet.CodeAccessRequest, 1)

// Create a response packet
resp := packet.New(packet.CodeAccessAccept, req.Identifier)
```

### Packet Codes

```go
// Authentication packets
packet.CodeAccessRequest     // 1
packet.CodeAccessAccept      // 2
packet.CodeAccessReject      // 3
packet.CodeAccessChallenge   // 11

// Accounting packets
packet.CodeAccountingRequest  // 4
packet.CodeAccountingResponse // 5

// Status packets
packet.CodeStatusServer      // 12
packet.CodeStatusClient      // 13

// Dynamic Authorization (CoA/Disconnect)
packet.CodeDisconnectRequest // 40
packet.CodeDisconnectACK     // 41
packet.CodeDisconnectNAK     // 42
packet.CodeCoARequest        // 43
packet.CodeCoAACK           // 44
packet.CodeCoANAK           // 45
```

## Working with Attributes

### Adding Attributes

```go
req := packet.New(packet.CodeAccessRequest, 1)

// String attributes
req.AddStringAttribute(packet.AttributeUserName, "john.doe")
req.AddStringAttribute(packet.AttributeNASIdentifier, "nas-01")

// Integer attributes
req.AddIntegerAttribute(packet.AttributeNASPort, 123)

// IP address attributes
req.AddIPAttribute(packet.AttributeNASIPAddress, net.ParseIP("192.168.1.1"))
req.AddIPAttribute(packet.AttributeFramedIPAddress, net.ParseIP("10.0.0.100"))

// Binary/bytes attributes
req.AddBytesAttribute(packet.AttributeState, []byte{0x01, 0x02, 0x03})

// Date/time attributes
req.AddDateAttribute(packet.AttributeEventTimestamp, time.Now())
```

### Retrieving Attributes

```go
// Get string attributes
username, ok := req.GetStringAttribute(packet.AttributeUserName)
if ok {
    fmt.Printf("Username: %s\n", username)
}

// Get integer attributes
nasPort, ok := req.GetIntegerAttribute(packet.AttributeNASPort)
if ok {
    fmt.Printf("NAS Port: %d\n", nasPort)
}

// Get IP address attributes
nasIP, ok := req.GetIPAttribute(packet.AttributeNASIPAddress)
if ok {
    fmt.Printf("NAS IP: %s\n", nasIP.String())
}

// Get all attributes of a specific type
usernames := req.GetAllStringAttributes(packet.AttributeUserName)
for _, name := range usernames {
    fmt.Printf("User: %s\n", name)
}
```

### Working with Raw Attributes

```go
// Create raw attribute
attr := packet.Attribute{
    Type:   packet.AttributeUserName,
    Length: uint8(2 + len("john.doe")),
    Value:  []byte("john.doe"),
}
req.AddAttribute(attr)

// Get raw attribute
attr, ok := req.GetAttribute(packet.AttributeUserName)
if ok {
    fmt.Printf("Attribute type: %d, length: %d, value: %s\n", 
        attr.Type, attr.Length, string(attr.Value))
}

// Iterate through all attributes
for _, attr := range req.Attributes {
    fmt.Printf("Type: %d, Value: %x\n", attr.Type, attr.Value)
}
```

## Standard Attributes

### User Authentication Attributes

```go
// User credentials
req.AddStringAttribute(packet.AttributeUserName, "john.doe")
req.AddStringAttribute(packet.AttributeUserPassword, "secret123")

// CHAP authentication
req.AddBytesAttribute(packet.AttributeCHAPPassword, chapResponse)
req.AddBytesAttribute(packet.AttributeCHAPChallenge, challenge)

// Service information
req.AddIntegerAttribute(packet.AttributeServiceType, 1)req.AddIntegerAttribute(packet.AttributeLoginService, 0) // Telnet
```

### NAS Information Attributes

```go
// NAS identification
req.AddStringAttribute(packet.AttributeNASIdentifier, "nas-gateway-01")
req.AddIPAttribute(packet.AttributeNASIPAddress, net.ParseIP("192.168.1.1"))
req.AddIntegerAttribute(packet.AttributeNASPort, 123)
req.AddIntegerAttribute(packet.AttributeNASPortType, 5) // Ethernet

// Connection information
req.AddStringAttribute(packet.AttributeCallingStationID, "00:11:22:33:44:55")
req.AddStringAttribute(packet.AttributeCalledStationID, "66:77:88:99:AA:BB")
```

### Session Attributes

```go
// Session management
req.AddStringAttribute(packet.AttributeAcctSessionID, "sess-12345")
req.AddIntegerAttribute(packet.AttributeSessionTimeout, 3600)
req.AddIntegerAttribute(packet.AttributeIdleTimeout, 300)

// Framed protocol attributes
req.AddIPAttribute(packet.AttributeFramedIPAddress, net.ParseIP("10.0.0.100"))
req.AddIPAttribute(packet.AttributeFramedIPNetmask, net.ParseIP("255.255.255.0"))
req.AddIntegerAttribute(packet.AttributeFramedMTU, 1500)
```

### Accounting Attributes

```go
// Accounting status
req.AddIntegerAttribute(packet.AttributeAcctStatusType, 1) // Start

// Usage statistics
req.AddIntegerAttribute(packet.AttributeAcctInputOctets, 1024000)
req.AddIntegerAttribute(packet.AttributeAcctOutputOctets, 2048000)
req.AddIntegerAttribute(packet.AttributeAcctInputPackets, 1000)
req.AddIntegerAttribute(packet.AttributeAcctOutputPackets, 1500)
req.AddIntegerAttribute(packet.AttributeAcctSessionTime, 3600)

// Termination
req.AddIntegerAttribute(packet.AttributeAcctTerminateCause, 1) // User Request
```

## Vendor-Specific Attributes

### Creating VSAs

```go
// Cisco VSA example
vsa := packet.VendorSpecificAttribute{
    VendorID: 9,    // Cisco
    Type:     1,    // Cisco-AVPair
    Value:    []byte("tunnel-type=PPTP"),
}

vsaBytes := vsa.Encode()
req.AddBytesAttribute(packet.AttributeVendorSpecific, vsaBytes)
```

### Parsing VSAs

```go
// Get vendor-specific attributes
vsaAttrs := req.GetAllBytesAttributes(packet.AttributeVendorSpecific)
for _, vsaData := range vsaAttrs {
    vsa, err := packet.ParseVendorSpecificAttribute(vsaData)
    if err != nil {
        continue
    }
    
    fmt.Printf("Vendor ID: %d, Type: %d, Value: %s\n", 
        vsa.VendorID, vsa.Type, string(vsa.Value))
}
```

## Packet Encoding and Decoding

### Encoding Packets

```go
// Create packet
req := packet.New(packet.CodeAccessRequest, 1)
req.AddStringAttribute(packet.AttributeUserName, "john.doe")

// Set secret for authenticator calculation
secret := "testing123"

// Encode packet to bytes
data, err := req.Encode(secret)
if err != nil {
    log.Fatal("Failed to encode packet:", err)
}

fmt.Printf("Encoded packet: %x\n", data)
```

### Decoding Packets

```go
// Decode packet from bytes
secret := "testing123"
req, err := packet.Decode(data, secret)
if err != nil {
    log.Fatal("Failed to decode packet:", err)
}

fmt.Printf("Decoded packet code: %v\n", req.Code)
fmt.Printf("Decoded packet identifier: %d\n", req.Identifier)
```

### Packet Validation

```go
// Validate packet structure
if err := req.Validate(); err != nil {
    log.Printf("Invalid packet: %v", err)
}

// Validate authenticator
secret := "testing123"
if !req.ValidateAuthenticator(secret) {
    log.Printf("Invalid authenticator")
}

// Validate message authenticator (if present)
if !req.ValidateMessageAuthenticator(secret) {
    log.Printf("Invalid message authenticator")
}
```

## Advanced Packet Operations

### Packet Modification

```go
// Copy packet
newReq := req.Copy()

// Remove attribute
req.RemoveAttribute(packet.AttributeState)

// Replace attribute
req.RemoveAttribute(packet.AttributeUserName)
req.AddStringAttribute(packet.AttributeUserName, "new.user")

// Update packet length after modifications
req.UpdateLength()
```

### Request/Response Matching

```go
// Create response matching request
func createResponse(req *packet.Packet, code packet.Code) *packet.Packet {
    resp := packet.New(code, req.Identifier)
    
    // Copy request authenticator for response calculation
    resp.SetRequestAuthenticator(req.Authenticator)
    
    return resp
}

// Verify response matches request
func verifyResponse(req, resp *packet.Packet) bool {
    return req.Identifier == resp.Identifier
}
```

### Packet Statistics

```go
// Calculate packet size
size := req.GetSize()
fmt.Printf("Packet size: %d bytes\n", size)

// Count attributes
attrCount := req.GetAttributeCount()
fmt.Printf("Number of attributes: %d\n", attrCount)

// Get attribute summary
summary := req.GetAttributeSummary()
for attrType, count := range summary {
    fmt.Printf("Attribute %d: %d occurrences\n", attrType, count)
}
```

## Packet Security

### Message Authenticator

```go
// Add message authenticator for enhanced security
req.AddMessageAuthenticator(secret)

// Verify message authenticator in response
if !resp.VerifyMessageAuthenticator(secret, req.Authenticator) {
    log.Printf("Message authenticator verification failed")
}
```

### Password Encryption

```go
// Encrypt user password attribute
func encryptPassword(password, secret string, authenticator [16]byte) []byte {
    return packet.EncryptPassword([]byte(password), secret, authenticator)
}

// Decrypt user password attribute
func decryptPassword(encrypted []byte, secret string, authenticator [16]byte) string {
    decrypted := packet.DecryptPassword(encrypted, secret, authenticator)
    return string(decrypted)
}
```

### Tunnel Password Encryption

```go
// Encrypt tunnel password (RFC 2868)
tunnelPassword := "tunnel-secret"
tag := byte(1)
salt := generateSalt()

encrypted := packet.EncryptTunnelPassword(
    []byte(tunnelPassword), 
    secret, 
    authenticator, 
    tag, 
    salt,
)

req.AddBytesAttribute(packet.AttributeTunnelPassword, encrypted)
```

## Error Handling

### Packet Validation Errors

```go
func validatePacket(data []byte, secret string) error {
    // Check minimum packet length
    if len(data) < packet.MinPacketLength {
        return fmt.Errorf("packet too short: %d bytes", len(data))
    }
    
    // Check maximum packet length
    if len(data) > packet.MaxPacketLength {
        return fmt.Errorf("packet too long: %d bytes", len(data))
    }
    
    // Decode and validate
    req, err := packet.Decode(data, secret)
    if err != nil {
        return fmt.Errorf("decode failed: %w", err)
    }
    
    if err := req.Validate(); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }
    
    return nil
}
```

### Attribute Parsing Errors

```go
func safeGetAttribute(req *packet.Packet, attrType packet.AttributeType) (string, error) {
    attr, ok := req.GetAttribute(attrType)
    if !ok {
        return "", fmt.Errorf("attribute %d not found", attrType)
    }
    
    if len(attr.Value) == 0 {
        return "", fmt.Errorf("attribute %d has empty value", attrType)
    }
    
    return string(attr.Value), nil
}
```

## Testing Packets

### Packet Testing Utilities

```go
func TestPacketCreation(t *testing.T) {
    req := packet.New(packet.CodeAccessRequest, 123)
    
    assert.Equal(t, packet.CodeAccessRequest, req.Code)
    assert.Equal(t, uint8(123), req.Identifier)
    assert.Equal(t, uint16(20), req.Length) // Header only
}

func TestAttributeHandling(t *testing.T) {
    req := packet.New(packet.CodeAccessRequest, 1)
    
    // Add attribute
    req.AddStringAttribute(packet.AttributeUserName, "testuser")
    
    // Verify attribute
    username, ok := req.GetStringAttribute(packet.AttributeUserName)
    assert.True(t, ok)
    assert.Equal(t, "testuser", username)
}
```

### Packet Comparison

```go
func comparePackets(t *testing.T, expected, actual *packet.Packet) {
    assert.Equal(t, expected.Code, actual.Code)
    assert.Equal(t, expected.Identifier, actual.Identifier)
    assert.Equal(t, len(expected.Attributes), len(actual.Attributes))
    
    for i, expectedAttr := range expected.Attributes {
        actualAttr := actual.Attributes[i]
        assert.Equal(t, expectedAttr.Type, actualAttr.Type)
        assert.Equal(t, expectedAttr.Value, actualAttr.Value)
    }
}
```

## Performance Considerations

### Efficient Packet Handling

```go
// Use packet pools for high-throughput applications
var packetPool = sync.Pool{
    New: func() interface{} {
        return &packet.Packet{
            Attributes: make([]packet.Attribute, 0, 10),
        }
    },
}

func getPacket() *packet.Packet {
    return packetPool.Get().(*packet.Packet)
}

func putPacket(p *packet.Packet) {
    p.Reset()
    packetPool.Put(p)
}
```

### Memory Optimization

```go
// Pre-allocate attribute slices for known packet types
func createAuthPacket(identifier uint8) *packet.Packet {
    req := packet.New(packet.CodeAccessRequest, identifier)
    // Pre-allocate for common auth attributes
    req.Attributes = make([]packet.Attribute, 0, 8)
    return req
}

// Reuse byte buffers for encoding
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 0, packet.MaxPacketLength)
    },
}
```