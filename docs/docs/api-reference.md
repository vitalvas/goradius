# API Reference

Complete reference documentation for the GoRADIUS library APIs.

## Package Overview

The GoRADIUS library is organized into several packages:

- `pkg/packet` - RADIUS packet handling and encoding/decoding
- `pkg/server` - RADIUS server implementation
- `pkg/client` - RADIUS client implementation
- `pkg/dictionary` - Attribute dictionary management
- `pkg/crypto` - Cryptographic functions and security
- `pkg/log` - Logging interface and utilities

## pkg/packet

### Types

#### Packet

```go
type Packet struct {
    Code          Code
    Identifier    uint8
    Length        uint16
    Authenticator [AuthenticatorLength]byte
    Attributes    []Attribute
}
```

Represents a RADIUS packet as defined in RFC 2865.

#### Code

```go
type Code uint8
```

RADIUS packet codes:

```go
const (
    CodeAccessRequest      Code = 1
    CodeAccessAccept       Code = 2
    CodeAccessReject       Code = 3
    CodeAccountingRequest  Code = 4
    CodeAccountingResponse Code = 5
    CodeAccessChallenge    Code = 11
    CodeStatusServer       Code = 12
    CodeStatusClient       Code = 13
    CodeDisconnectRequest  Code = 40
    CodeDisconnectACK      Code = 41
    CodeDisconnectNAK      Code = 42
    CodeCoARequest         Code = 43
    CodeCoAACK            Code = 44
    CodeCoANAK            Code = 45
)
```

#### Attribute

```go
type Attribute struct {
    Type   AttributeType
    Length uint8
    Value  []byte
}
```

#### AttributeType

```go
type AttributeType uint8
```

Standard RADIUS attributes:

```go
const (
    AttributeUserName             AttributeType = 1
    AttributeUserPassword         AttributeType = 2
    AttributeCHAPPassword         AttributeType = 3
    AttributeNASIPAddress         AttributeType = 4
    AttributeNASPort              AttributeType = 5
    AttributeServiceType          AttributeType = 6
    AttributeFramedProtocol       AttributeType = 7
    AttributeFramedIPAddress      AttributeType = 8
    AttributeFramedIPNetmask      AttributeType = 9
    AttributeFramedRouting        AttributeType = 10
    // ... additional attributes
)
```

### Functions

#### New

```go
func New(code Code, identifier uint8) *Packet
```

Creates a new RADIUS packet with the specified code and identifier.

#### Decode

```go
func Decode(data []byte, secret string) (*Packet, error)
```

Decodes a RADIUS packet from raw bytes using the provided secret.

### Methods

#### Packet.Encode

```go
func (p *Packet) Encode(secret string) ([]byte, error)
```

Encodes the packet to bytes using the provided secret.

#### Packet.AddAttribute

```go
func (p *Packet) AddAttribute(attr Attribute)
```

Adds an attribute to the packet.

#### Packet.AddStringAttribute

```go
func (p *Packet) AddStringAttribute(attrType AttributeType, value string)
```

Adds a string attribute to the packet.

#### Packet.AddIntegerAttribute

```go
func (p *Packet) AddIntegerAttribute(attrType AttributeType, value int)
```

Adds an integer attribute to the packet.

#### Packet.AddIPAttribute

```go
func (p *Packet) AddIPAttribute(attrType AttributeType, value net.IP)
```

Adds an IP address attribute to the packet.

#### Packet.AddBytesAttribute

```go
func (p *Packet) AddBytesAttribute(attrType AttributeType, value []byte)
```

Adds a binary attribute to the packet.

#### Packet.GetAttribute

```go
func (p *Packet) GetAttribute(attrType AttributeType) (Attribute, bool)
```

Returns the first attribute with the specified type.

#### Packet.GetStringAttribute

```go
func (p *Packet) GetStringAttribute(attrType AttributeType) (string, bool)
```

Returns the value of a string attribute.

#### Packet.GetIntegerAttribute

```go
func (p *Packet) GetIntegerAttribute(attrType AttributeType) (int, bool)
```

Returns the value of an integer attribute.

#### Packet.GetIPAttribute

```go
func (p *Packet) GetIPAttribute(attrType AttributeType) (net.IP, bool)
```

Returns the value of an IP address attribute.

#### Packet.GetBytesAttribute

```go
func (p *Packet) GetBytesAttribute(attrType AttributeType) ([]byte, bool)
```

Returns the value of a binary attribute.

#### Packet.Validate

```go
func (p *Packet) Validate() error
```

Validates the packet structure and contents.

#### Packet.Copy

```go
func (p *Packet) Copy() *Packet
```

Creates a deep copy of the packet.

## pkg/server

### Types

#### Server

```go
type Server struct {
    // Internal fields
}
```

RADIUS server instance.

#### Config

```go
type Config struct {
    Bindings           []Binding
    SecretProvider     SecretProvider
    ReadTimeout        time.Duration
    WriteTimeout       time.Duration
    MaxRequestSize     int
    WorkerPoolSize     int
    RequestQueueSize   int
    BufferPoolSize     int
    RequestPoolSize    int
    ResponsePoolSize   int
}
```

Server configuration.

#### Binding

```go
type Binding struct {
    Network   string
    Address   string
    TLSConfig *tls.Config
}
```

Network binding configuration.

#### SecretProvider

```go
type SecretProvider interface {
    GetSecret(clientIP string) (string, error)
}
```

Interface for providing client secrets based on IP address.

#### Handler

```go
type Handler interface {
    HandleRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error)
}
```

Interface for handling RADIUS requests.

#### HandlerFunc

```go
type HandlerFunc func(ctx context.Context, req *packet.Packet) (*packet.Packet, error)
```

Function type that implements Handler interface.

#### Middleware

```go
type Middleware func(Handler) Handler
```

Middleware function type.

### Functions

#### New

```go
func New(config *Config, handler Handler) (*Server, error)
```

Creates a new RADIUS server with the specified configuration and handler.

### Methods

#### Server.Start

```go
func (s *Server) Start(ctx context.Context) error
```

Starts the RADIUS server.

#### Server.Shutdown

```go
func (s *Server) Shutdown(ctx context.Context) error
```

Gracefully shuts down the server.

#### Server.GetStatistics

```go
func (s *Server) GetStatistics() *Statistics
```

Returns server statistics.

#### Server.GetAddress

```go
func (s *Server) GetAddress() string
```

Returns the server's listening address.

## pkg/client

### Types

#### Client

```go
type Client interface {
    SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error)
    SendRequestWithRetry(ctx context.Context, req *packet.Packet, maxRetries int) (*packet.Packet, error)
    GetStatistics() *Statistics
    IsHealthy() bool
    Close() error
}
```

RADIUS client interface.

#### Config

```go
type Config struct {
    Servers             []ServerConfig
    Transport           TransportType
    Timeout             time.Duration
    MaxRetries          int
    RetryInterval       time.Duration
    FailoverTimeout     time.Duration
    HealthCheckInterval time.Duration
    TLSConfig          *tls.Config
    ConnectionPool     *PoolConfig
}
```

Client configuration.

#### ServerConfig

```go
type ServerConfig struct {
    Address string
    Secret  string
    Weight  int
}
```

Individual server configuration.

#### TransportType

```go
type TransportType string

const (
    TransportUDP TransportType = "udp"
    TransportTCP TransportType = "tcp"
    TransportTLS TransportType = "tls"
)
```

Transport protocol types.

#### PoolConfig

```go
type PoolConfig struct {
    MaxConnections     int
    MaxIdleConnections int
    IdleTimeout        time.Duration
    MaxLifetime        time.Duration
}
```

Connection pool configuration.

#### Statistics

```go
type Statistics struct {
    RequestsSent      uint64
    ResponsesReceived uint64
    Timeouts          uint64
    NetworkErrors     uint64
    AvgResponseTime   time.Duration
    SuccessRate       float64
}
```

Client statistics.

### Functions

#### New

```go
func New(config *Config) (Client, error)
```

Creates a new RADIUS client with the specified configuration.

#### NewWithMiddleware

```go
func NewWithMiddleware(config *Config, middleware ...ClientMiddleware) (Client, error)
```

Creates a new RADIUS client with middleware.

### Error Types

```go
var (
    ErrTimeout      = errors.New("request timeout")
    ErrNoServers    = errors.New("no servers available")
    ErrInvalidResp  = errors.New("invalid response")
    ErrNetworkError = errors.New("network error")
)
```

#### Error Checking Functions

```go
func IsTimeoutError(err error) bool
func IsNetworkError(err error) bool
func IsPermanentError(err error) bool
func IsServerError(err error) bool
```

## pkg/dictionary

### Types

#### Dictionary

```go
type Dictionary struct {
    // Internal fields
}
```

RADIUS attribute dictionary.

#### AttributeDefinition

```go
type AttributeDefinition struct {
    Name        string            `yaml:"name" json:"name"`
    Type        uint8             `yaml:"type" json:"type"`
    DataType    DataType          `yaml:"data_type" json:"data_type"`
    Length      int               `yaml:"length,omitempty" json:"length,omitempty"`
    MaxLength   int               `yaml:"max_length,omitempty" json:"max_length,omitempty"`
    Values      map[int]string    `yaml:"values,omitempty" json:"values,omitempty"`
    Description string            `yaml:"description,omitempty" json:"description,omitempty"`
    Encrypted   bool              `yaml:"encrypted,omitempty" json:"encrypted,omitempty"`
}
```

Attribute definition in the dictionary.

#### DataType

```go
type DataType string

const (
    DataTypeString   DataType = "string"
    DataTypeOctets   DataType = "octets"
    DataTypeInteger  DataType = "integer"
    DataTypeDate     DataType = "date"
    DataTypeIPAddr   DataType = "ipaddr"
    DataTypeIPv6Addr DataType = "ipv6addr"
    DataTypeUint32   DataType = "uint32"
    DataTypeUint64   DataType = "uint64"
)
```

Supported data types for attributes.

#### VendorDefinition

```go
type VendorDefinition struct {
    ID         uint32                   `yaml:"id" json:"id"`
    Name       string                   `yaml:"name" json:"name"`
    Attributes []AttributeDefinition    `yaml:"attributes" json:"attributes"`
}
```

Vendor-specific attribute definition.

### Functions

#### LoadFromFile

```go
func LoadFromFile(filename string) (*Dictionary, error)
```

Loads a dictionary from a YAML file.

#### LoadFromYAML

```go
func LoadFromYAML(data []byte) (*Dictionary, error)
```

Loads a dictionary from YAML data.

#### New

```go
func New() *Dictionary
```

Creates a new empty dictionary.

#### Merge

```go
func Merge(dicts ...*Dictionary) *Dictionary
```

Merges multiple dictionaries into one.

### Methods

#### Dictionary.GetAttributeByName

```go
func (d *Dictionary) GetAttributeByName(name string) (AttributeDefinition, error)
```

Returns an attribute definition by name.

#### Dictionary.GetAttributeByType

```go
func (d *Dictionary) GetAttributeByType(attrType uint8) (AttributeDefinition, error)
```

Returns an attribute definition by type.

#### Dictionary.AddAttribute

```go
func (d *Dictionary) AddAttribute(attr AttributeDefinition) error
```

Adds an attribute definition to the dictionary.

#### Dictionary.GetVendor

```go
func (d *Dictionary) GetVendor(vendorID uint32) (VendorDefinition, error)
```

Returns a vendor definition by ID.

#### Dictionary.GetVSA

```go
func (d *Dictionary) GetVSA(vendorID uint32, attrType uint8) (AttributeDefinition, error)
```

Returns a vendor-specific attribute definition.

#### Dictionary.ValidateValue

```go
func (d *Dictionary) ValidateValue(attr AttributeDefinition, value string) bool
```

Validates an attribute value according to its definition.

#### Dictionary.ConvertValue

```go
func (d *Dictionary) ConvertValue(attr AttributeDefinition, value string) (interface{}, error)
```

Converts a string value to the appropriate type.

#### Dictionary.ValidatePacket

```go
func (d *Dictionary) ValidatePacket(pkt *packet.Packet) []error
```

Validates all attributes in a packet against the dictionary.

## pkg/crypto

### Functions

#### CalculateRequestAuthenticator

```go
func CalculateRequestAuthenticator(packet []byte, secret string) [16]byte
```

Calculates the request authenticator for a packet.

#### CalculateResponseAuthenticator

```go
func CalculateResponseAuthenticator(responsePacket []byte, requestAuthenticator [16]byte, secret string) [16]byte
```

Calculates the response authenticator.

#### CalculateMessageAuthenticator

```go
func CalculateMessageAuthenticator(pkt *packet.Packet, secret string) ([16]byte, error)
```

Calculates the message authenticator attribute.

#### EncryptPassword

```go
func EncryptPassword(password []byte, secret string, authenticator [16]byte) []byte
```

Encrypts a user password using RADIUS encryption.

#### DecryptPassword

```go
func DecryptPassword(encrypted []byte, secret string, authenticator [16]byte) []byte
```

Decrypts a RADIUS-encrypted password.

#### EncryptTunnelPassword

```go
func EncryptTunnelPassword(password []byte, secret string, authenticator [16]byte, tag byte, salt uint16) []byte
```

Encrypts a tunnel password using salt-based encryption.

#### DecryptTunnelPassword

```go
func DecryptTunnelPassword(encrypted []byte, secret string, authenticator [16]byte, tag byte, salt uint16) []byte
```

Decrypts a tunnel password.

#### GenerateCHAPResponse

```go
func GenerateCHAPResponse(id byte, password string, challenge []byte) []byte
```

Generates a CHAP response hash.

#### GenerateRandomSalt

```go
func GenerateRandomSalt() uint16
```

Generates a random salt for tunnel password encryption.

#### EqualAuthenticators

```go
func EqualAuthenticators(a, b [16]byte) bool
```

Securely compares two authenticators.

#### EqualBytes

```go
func EqualBytes(a, b []byte) bool
```

Securely compares two byte slices.

## pkg/log

### Types

#### Logger

```go
type Logger interface {
    Debug(args ...interface{})
    Debugf(format string, args ...interface{})
    Info(args ...interface{})
    Infof(format string, args ...interface{})
    Warn(args ...interface{})
    Warnf(format string, args ...interface{})
    Error(args ...interface{})
    Errorf(format string, args ...interface{})
    WithField(key string, value interface{}) Logger
    WithFields(fields Fields) Logger
    WithError(err error) Logger
}
```

Logging interface.

#### Fields

```go
type Fields map[string]interface{}
```

Log fields type.

### Functions

#### New

```go
func New() Logger
```

Creates a new logger instance.

#### NewWithLevel

```go
func NewWithLevel(level Level) Logger
```

Creates a new logger with specified level.

#### SetLevel

```go
func SetLevel(level Level)
```

Sets the global log level.

### Constants

```go
const (
    LevelDebug Level = iota
    LevelInfo
    LevelWarn
    LevelError
)
```

Log levels.

## Error Handling

### Common Error Types

The library defines several common error types that can be returned by various functions:

```go
var (
    ErrInvalidPacket     = errors.New("invalid packet")
    ErrInvalidAttribute  = errors.New("invalid attribute")
    ErrPacketTooLarge    = errors.New("packet too large")
    ErrPacketTooSmall    = errors.New("packet too small")
    ErrInvalidSecret     = errors.New("invalid secret")
    ErrTimeout           = errors.New("timeout")
    ErrServerUnavailable = errors.New("server unavailable")
)
```

### Error Checking

Most functions return errors that can be checked using standard Go error handling:

```go
packet, err := client.SendRequest(ctx, request)
if err != nil {
    if client.IsTimeoutError(err) {
        // Handle timeout
    } else if client.IsNetworkError(err) {
        // Handle network error
    } else {
        // Handle other errors
    }
    return err
}
```

## Context Support

All long-running operations support Go contexts for cancellation and timeouts:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

response, err := client.SendRequest(ctx, request)
```

## Thread Safety

- `Packet` types are not thread-safe and should not be shared between goroutines without synchronization
- `Client` instances are thread-safe and can be used concurrently
- `Server` instances are thread-safe
- `Dictionary` instances are thread-safe for read operations after loading

## Memory Management

The library provides several features for efficient memory usage:

- Object pooling for packets and buffers
- Configurable buffer sizes
- Automatic cleanup of expired connections
- Efficient attribute encoding/decoding

Use the appropriate configuration options to tune memory usage for your specific use case.

## Performance Considerations

- Use connection pooling for TCP clients
- Configure appropriate timeouts
- Use worker pools for server implementations
- Cache dictionary lookups for high-throughput scenarios
- Consider using UDP transport for better performance
- Monitor and tune buffer pool sizes

## Compatibility

The library is compatible with:
- Go 1.24.4 and later
- RFC 2865 (RADIUS)
- RFC 2866 (RADIUS Accounting)
- RFC 2869 (RADIUS Extensions)
- RFC 3576 (Dynamic Authorization)

## Version Information

Current API version: 1.0
Minimum Go version: 1.24.4

Breaking changes will result in a major version increment. Minor versions may add new features while maintaining backward compatibility.