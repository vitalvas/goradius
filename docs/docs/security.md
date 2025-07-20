# RADIUS Security and Cryptography

This guide covers security features, cryptographic functions, and best practices for secure RADIUS implementations.

## Security Overview

RADIUS security is based on several mechanisms:
- Shared secrets for authentication
- Request/Response authenticators
- Message authenticator (RFC 2869)
- Attribute encryption
- Replay attack prevention

## Authenticators

### Request Authenticator

The Request Authenticator provides integrity protection for requests:

```go
import "github.com/vitalvas/goradius/pkg/crypto"

// Calculate request authenticator
func calculateRequestAuthenticator(packet []byte, secret string) [16]byte {
    return crypto.CalculateRequestAuthenticator(packet, secret)
}

// Verify request authenticator
func verifyRequestAuthenticator(packet []byte, secret string, authenticator [16]byte) bool {
    calculated := crypto.CalculateRequestAuthenticator(packet, secret)
    return crypto.EqualAuthenticators(calculated, authenticator)
}
```

### Response Authenticator

The Response Authenticator validates responses:

```go
// Calculate response authenticator
func calculateResponseAuthenticator(responsePacket []byte, requestAuthenticator [16]byte, secret string) [16]byte {
    return crypto.CalculateResponseAuthenticator(responsePacket, requestAuthenticator, secret)
}

// Verify response authenticator
func verifyResponseAuthenticator(responsePacket []byte, requestAuthenticator [16]byte, secret string, authenticator [16]byte) bool {
    calculated := crypto.CalculateResponseAuthenticator(responsePacket, requestAuthenticator, secret)
    return crypto.EqualAuthenticators(calculated, authenticator)
}
```

## Message Authenticator

### Adding Message Authenticator

The Message Authenticator (RFC 2869) provides additional security:

```go
import "github.com/vitalvas/goradius/pkg/packet"

func addMessageAuthenticator(req *packet.Packet, secret string) error {
    // Calculate message authenticator
    ma, err := crypto.CalculateMessageAuthenticator(req, secret)
    if err != nil {
        return err
    }
    
    // Add as attribute
    req.AddBytesAttribute(packet.AttributeMessageAuthenticator, ma[:])
    return nil
}
```

### Verifying Message Authenticator

```go
func verifyMessageAuthenticator(req *packet.Packet, secret string) bool {
    // Get message authenticator attribute
    maAttr, exists := req.GetBytesAttribute(packet.AttributeMessageAuthenticator)
    if !exists {
        return false
    }
    
    if len(maAttr) != 16 {
        return false
    }
    
    // Calculate expected value
    expected, err := crypto.CalculateMessageAuthenticator(req, secret)
    if err != nil {
        return false
    }
    
    // Compare
    var received [16]byte
    copy(received[:], maAttr)
    return crypto.EqualAuthenticators(expected, received)
}
```

## Password Encryption

### User-Password Attribute

The User-Password attribute is encrypted using a simple XOR cipher:

```go
func encryptUserPassword(password, secret string, requestAuthenticator [16]byte) []byte {
    return crypto.EncryptPassword([]byte(password), secret, requestAuthenticator)
}

func decryptUserPassword(encrypted []byte, secret string, requestAuthenticator [16]byte) string {
    decrypted := crypto.DecryptPassword(encrypted, secret, requestAuthenticator)
    return string(decrypted)
}
```

### CHAP-Password Handling

CHAP passwords are not encrypted but use challenge-response:

```go
func generateCHAPResponse(id byte, password string, challenge []byte) []byte {
    return crypto.GenerateCHAPResponse(id, password, challenge)
}

func verifyCHAPResponse(id byte, password string, challenge, response []byte) bool {
    expected := crypto.GenerateCHAPResponse(id, password, challenge)
    return crypto.EqualBytes(expected, response)
}
```

## Tunnel Password Encryption

### Encrypting Tunnel Passwords

Tunnel passwords use salt-based encryption (RFC 2868):

```go
func encryptTunnelPassword(password, secret string, requestAuthenticator [16]byte, tag byte) ([]byte, error) {
    // Generate random salt
    salt := crypto.GenerateRandomSalt()
    
    // Encrypt password
    encrypted := crypto.EncryptTunnelPassword(
        []byte(password),
        secret,
        requestAuthenticator,
        tag,
        salt,
    )
    
    return encrypted, nil
}
```

### Decrypting Tunnel Passwords

```go
func decryptTunnelPassword(encrypted []byte, secret string, requestAuthenticator [16]byte) (string, byte, error) {
    if len(encrypted) < 3 {
        return "", 0, fmt.Errorf("encrypted data too short")
    }
    
    tag := encrypted[0] & 0x1F
    salt := binary.BigEndian.Uint16(encrypted[1:3])
    
    decrypted := crypto.DecryptTunnelPassword(
        encrypted[3:],
        secret,
        requestAuthenticator,
        tag,
        salt,
    )
    
    return string(decrypted), tag, nil
}
```

## Secret Management

### Secure Secret Generation

```go
func generateSecureSecret(length int) (string, error) {
    if length < 16 {
        return "", fmt.Errorf("secret too short")
    }
    
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    
    // Convert to base64 for readability
    return base64.StdEncoding.EncodeToString(bytes), nil
}
```

### Secret Validation

```go
func validateSecret(secret string) error {
    if len(secret) < 8 {
        return fmt.Errorf("secret too short (minimum 8 characters)")
    }
    
    if len(secret) > 253 {
        return fmt.Errorf("secret too long (maximum 253 characters)")
    }
    
    // Check for common weak secrets
    weakSecrets := []string{"password", "secret", "radius", "testing123"}
    for _, weak := range weakSecrets {
        if strings.EqualFold(secret, weak) {
            return fmt.Errorf("weak secret detected")
        }
    }
    
    return nil
}
```

### Secret Storage

```go
type SecretStore interface {
    GetSecret(clientIP string) (string, error)
    SetSecret(clientIP, secret string) error
    DeleteSecret(clientIP string) error
}

type FileSecretStore struct {
    filePath string
    mutex    sync.RWMutex
    secrets  map[string]string
}

func (f *FileSecretStore) GetSecret(clientIP string) (string, error) {
    f.mutex.RLock()
    defer f.mutex.RUnlock()
    
    secret, exists := f.secrets[clientIP]
    if !exists {
        return "", fmt.Errorf("secret not found for client: %s", clientIP)
    }
    
    return secret, nil
}

func (f *FileSecretStore) loadSecrets() error {
    data, err := ioutil.ReadFile(f.filePath)
    if err != nil {
        return err
    }
    
    f.mutex.Lock()
    defer f.mutex.Unlock()
    
    return yaml.Unmarshal(data, &f.secrets)
}
```

## Replay Attack Prevention

### Request Tracking

```go
type RequestTracker struct {
    requests map[string]time.Time
    mutex    sync.RWMutex
    window   time.Duration
}

func NewRequestTracker(window time.Duration) *RequestTracker {
    return &RequestTracker{
        requests: make(map[string]time.Time),
        window:   window,
    }
}

func (r *RequestTracker) IsReplay(clientIP string, identifier uint8, authenticator [16]byte) bool {
    key := fmt.Sprintf("%s:%d:%x", clientIP, identifier, authenticator)
    
    r.mutex.Lock()
    defer r.mutex.Unlock()
    
    // Check if request exists and is recent
    if timestamp, exists := r.requests[key]; exists {
        if time.Since(timestamp) < r.window {
            return true // Replay detected
        }
    }
    
    // Record this request
    r.requests[key] = time.Now()
    
    // Clean old entries
    r.cleanup()
    
    return false
}

func (r *RequestTracker) cleanup() {
    cutoff := time.Now().Add(-r.window)
    for key, timestamp := range r.requests {
        if timestamp.Before(cutoff) {
            delete(r.requests, key)
        }
    }
}
```

### Nonce Generation

```go
func generateNonce(length int) ([]byte, error) {
    nonce := make([]byte, length)
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    return nonce, nil
}

func validateNonce(nonce []byte, minLength int) error {
    if len(nonce) < minLength {
        return fmt.Errorf("nonce too short")
    }
    
    // Check for all-zero nonce
    allZero := true
    for _, b := range nonce {
        if b != 0 {
            allZero = false
            break
        }
    }
    
    if allZero {
        return fmt.Errorf("invalid nonce: all zeros")
    }
    
    return nil
}
```

## TLS Support

### TLS Configuration

```go
func createTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
        },
        PreferServerCipherSuites: true,
        CurvePreferences: []tls.CurveID{
            tls.CurveP256,
            tls.X25519,
        },
    }
}
```

### Certificate Validation

```go
func validateCertificate(cert *x509.Certificate) error {
    now := time.Now()
    
    if now.Before(cert.NotBefore) {
        return fmt.Errorf("certificate not yet valid")
    }
    
    if now.After(cert.NotAfter) {
        return fmt.Errorf("certificate expired")
    }
    
    // Check key usage
    if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
        return fmt.Errorf("certificate missing digital signature usage")
    }
    
    return nil
}
```

## Access Control

### IP-based Access Control

```go
type IPAccessControl struct {
    allowedNetworks []*net.IPNet
    deniedNetworks  []*net.IPNet
    mutex           sync.RWMutex
}

func NewIPAccessControl() *IPAccessControl {
    return &IPAccessControl{
        allowedNetworks: make([]*net.IPNet, 0),
        deniedNetworks:  make([]*net.IPNet, 0),
    }
}

func (ac *IPAccessControl) AddAllowedNetwork(cidr string) error {
    _, network, err := net.ParseCIDR(cidr)
    if err != nil {
        return err
    }
    
    ac.mutex.Lock()
    defer ac.mutex.Unlock()
    
    ac.allowedNetworks = append(ac.allowedNetworks, network)
    return nil
}

func (ac *IPAccessControl) IsAllowed(ip net.IP) bool {
    ac.mutex.RLock()
    defer ac.mutex.RUnlock()
    
    // Check denied networks first
    for _, network := range ac.deniedNetworks {
        if network.Contains(ip) {
            return false
        }
    }
    
    // Check allowed networks
    if len(ac.allowedNetworks) == 0 {
        return true // No restrictions
    }
    
    for _, network := range ac.allowedNetworks {
        if network.Contains(ip) {
            return true
        }
    }
    
    return false
}
```

### Rate Limiting

```go
type RateLimiter struct {
    requests map[string][]time.Time
    mutex    sync.RWMutex
    limit    int
    window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
    return &RateLimiter{
        requests: make(map[string][]time.Time),
        limit:    limit,
        window:   window,
    }
}

func (rl *RateLimiter) Allow(clientIP string) bool {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    now := time.Now()
    cutoff := now.Add(-rl.window)
    
    // Get existing requests for this client
    times := rl.requests[clientIP]
    
    // Remove old requests
    validTimes := make([]time.Time, 0, len(times))
    for _, t := range times {
        if t.After(cutoff) {
            validTimes = append(validTimes, t)
        }
    }
    
    // Check rate limit
    if len(validTimes) >= rl.limit {
        return false
    }
    
    // Add current request
    validTimes = append(validTimes, now)
    rl.requests[clientIP] = validTimes
    
    return true
}
```

## Secure Logging

### Security Event Logging

```go
type SecurityLogger struct {
    logger log.Logger
}

func (sl *SecurityLogger) LogAuthFailure(clientIP, username string, reason string) {
    sl.logger.WithFields(log.Fields{
        "event":     "auth_failure",
        "client_ip": clientIP,
        "username":  username,
        "reason":    reason,
        "timestamp": time.Now(),
    }).Warn("Authentication failure")
}

func (sl *SecurityLogger) LogReplayAttack(clientIP string, identifier uint8) {
    sl.logger.WithFields(log.Fields{
        "event":      "replay_attack",
        "client_ip":  clientIP,
        "identifier": identifier,
        "timestamp":  time.Now(),
    }).Error("Replay attack detected")
}

func (sl *SecurityLogger) LogRateLimitExceeded(clientIP string) {
    sl.logger.WithFields(log.Fields{
        "event":     "rate_limit_exceeded",
        "client_ip": clientIP,
        "timestamp": time.Now(),
    }).Warn("Rate limit exceeded")
}
```

### Audit Trail

```go
type AuditEvent struct {
    Timestamp time.Time
    Event     string
    ClientIP  string
    Username  string
    Success   bool
    Details   map[string]interface{}
}

type AuditLogger struct {
    events chan AuditEvent
    file   *os.File
    mutex  sync.Mutex
}

func NewAuditLogger(filename string) (*AuditLogger, error) {
    file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, err
    }
    
    al := &AuditLogger{
        events: make(chan AuditEvent, 1000),
        file:   file,
    }
    
    go al.processEvents()
    return al, nil
}

func (al *AuditLogger) LogEvent(event AuditEvent) {
    select {
    case al.events <- event:
    default:
        // Buffer full, drop event
    }
}

func (al *AuditLogger) processEvents() {
    encoder := json.NewEncoder(al.file)
    
    for event := range al.events {
        al.mutex.Lock()
        encoder.Encode(event)
        al.mutex.Unlock()
    }
}
```

## Security Best Practices

### Configuration Hardening

```go
type SecurityConfig struct {
    MinSecretLength     int
    MaxRequestSize      int
    RequestWindow       time.Duration
    RateLimit          int
    RateLimitWindow    time.Duration
    RequireTLS         bool
    RequireMessageAuth bool
}

func (sc *SecurityConfig) Validate() error {
    if sc.MinSecretLength < 16 {
        return fmt.Errorf("minimum secret length too low")
    }
    
    if sc.MaxRequestSize > 4096 {
        return fmt.Errorf("maximum request size too large")
    }
    
    if sc.RequestWindow < time.Second {
        return fmt.Errorf("request window too small")
    }
    
    return nil
}
```

### Secure Defaults

```go
func GetSecureDefaults() *SecurityConfig {
    return &SecurityConfig{
        MinSecretLength:     16,
        MaxRequestSize:      4096,
        RequestWindow:       time.Second * 30,
        RateLimit:          100,
        RateLimitWindow:    time.Minute,
        RequireTLS:         true,
        RequireMessageAuth: true,
    }
}
```

## Testing Security Features

### Unit Tests

```go
func TestPasswordEncryption(t *testing.T) {
    password := "secret123"
    secret := "testing123"
    authenticator := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
    
    // Encrypt
    encrypted := crypto.EncryptPassword([]byte(password), secret, authenticator)
    
    // Decrypt
    decrypted := crypto.DecryptPassword(encrypted, secret, authenticator)
    
    assert.Equal(t, password, string(decrypted))
}

func TestMessageAuthenticator(t *testing.T) {
    req := packet.New(packet.CodeAccessRequest, 1)
    req.AddStringAttribute(packet.AttributeUserName, "testuser")
    
    secret := "testing123"
    
    // Add message authenticator
    err := addMessageAuthenticator(req, secret)
    assert.NoError(t, err)
    
    // Verify message authenticator
    valid := verifyMessageAuthenticator(req, secret)
    assert.True(t, valid)
}
```

### Security Testing

```go
func TestReplayProtection(t *testing.T) {
    tracker := NewRequestTracker(time.Minute)
    
    clientIP := "192.168.1.100"
    identifier := uint8(123)
    authenticator := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
    
    // First request should be allowed
    replay := tracker.IsReplay(clientIP, identifier, authenticator)
    assert.False(t, replay)
    
    // Immediate replay should be detected
    replay = tracker.IsReplay(clientIP, identifier, authenticator)
    assert.True(t, replay)
}

func TestRateLimiting(t *testing.T) {
    limiter := NewRateLimiter(5, time.Minute)
    clientIP := "192.168.1.100"
    
    // First 5 requests should be allowed
    for i := 0; i < 5; i++ {
        allowed := limiter.Allow(clientIP)
        assert.True(t, allowed)
    }
    
    // 6th request should be denied
    allowed := limiter.Allow(clientIP)
    assert.False(t, allowed)
}
```