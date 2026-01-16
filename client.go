package goradius

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// ClientTransport specifies the network transport protocol for the client.
type ClientTransport int

const (
	// TransportUDP uses standard RADIUS over UDP (RFC 2865).
	TransportUDP ClientTransport = iota
	// TransportTCP uses RADIUS over TCP (RFC 6613).
	TransportTCP
	// TransportTLS uses RADIUS over TLS / RadSec (RFC 6614).
	TransportTLS
)

// ErrClientClosed is returned when attempting to use a closed client.
var ErrClientClosed = errors.New("client is closed")

type Client struct {
	addr              string
	secret            []byte
	dict              *Dictionary
	timeout           time.Duration
	useMessageAuth    bool
	verifyMessageAuth bool
	transport         ClientTransport
	tlsConfig         *tls.Config
	closed            atomic.Bool
	ctx               context.Context
	cancel            context.CancelFunc
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithAddr sets the server address for the client.
func WithAddr(addr string) ClientOption {
	return func(c *Client) {
		c.addr = addr
	}
}

// WithSecret sets the shared secret for the client.
func WithSecret(secret []byte) ClientOption {
	return func(c *Client) {
		c.secret = secret
	}
}

// WithClientDictionary sets the RADIUS dictionary for the client.
func WithClientDictionary(d *Dictionary) ClientOption {
	return func(c *Client) {
		c.dict = d
	}
}

// WithTimeout sets the request timeout for the client.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithClientUseMessageAuthenticator sets whether to add Message-Authenticator to requests.
func WithClientUseMessageAuthenticator(b bool) ClientOption {
	return func(c *Client) {
		c.useMessageAuth = b
	}
}

// WithVerifyMessageAuthenticator sets whether to verify Message-Authenticator in responses.
func WithVerifyMessageAuthenticator(b bool) ClientOption {
	return func(c *Client) {
		c.verifyMessageAuth = b
	}
}

// WithTransport sets the network transport protocol (UDP, TCP, or TLS).
// Default is TransportUDP.
func WithTransport(t ClientTransport) ClientOption {
	return func(c *Client) {
		c.transport = t
	}
}

// WithTLSConfig sets the TLS configuration for TransportTLS.
// Required when using TransportTLS.
func WithTLSConfig(cfg *tls.Config) ClientOption {
	return func(c *Client) {
		c.tlsConfig = cfg
	}
}

func NewClient(opts ...ClientOption) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Client{
		timeout:           3 * time.Second,
		useMessageAuth:    true,
		verifyMessageAuth: true,
		ctx:               ctx,
		cancel:            cancel,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Close closes the client, cancels any in-flight requests, and releases resources.
// After Close is called, any subsequent operations will return ErrClientClosed.
// Close is safe to call multiple times.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.cancel()
	return nil
}

// dial creates a connection based on the configured transport type.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	switch c.transport {
	case TransportTCP:
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "tcp", c.addr)

	case TransportTLS:
		dialer := tls.Dialer{
			Config: c.tlsConfig,
		}
		return dialer.DialContext(ctx, "tcp", c.addr)

	default: // TransportUDP
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "udp", c.addr)
	}
}

// readResponse reads a RADIUS response based on the transport type.
// UDP reads a single datagram, TCP/TLS reads a framed packet.
func (c *Client) readResponse(conn net.Conn) ([]byte, error) {
	if c.transport == TransportUDP {
		buffer := make([]byte, MaxPacketLength)
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		return buffer[:n], nil
	}

	// TCP/TLS: read framed packet using length field
	header := make([]byte, PacketHeaderLength)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[2:4])
	if length < MinPacketLength || length > MaxPacketLength {
		return nil, fmt.Errorf("invalid packet length: %d", length)
	}

	if length == PacketHeaderLength {
		return header, nil
	}

	data := make([]byte, length)
	copy(data, header)
	if _, err := io.ReadFull(conn, data[PacketHeaderLength:]); err != nil {
		return nil, err
	}

	return data, nil
}

func (c *Client) sendRequest(pkt *Packet) (*Packet, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	// Create request context with timeout
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()

	// Dial connection based on transport type
	conn, err := c.dial(ctx)
	if err != nil {
		if c.closed.Load() {
			return nil, ErrClientClosed
		}
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set deadline: %w", err)
		}
	}

	data, err := pkt.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode packet: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write packet: %w", err)
	}

	// Read response based on transport type
	respData, err := c.readResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	respPkt, err := Decode(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Verify response identifier matches request identifier (RFC 2865)
	if respPkt.Identifier != pkt.Identifier {
		return nil, fmt.Errorf("response identifier mismatch: expected %d, got %d", pkt.Identifier, respPkt.Identifier)
	}

	// Verify response authenticator (RFC 2865)
	expectedAuth := respPkt.CalculateResponseAuthenticator(c.secret, pkt.Authenticator)
	if !bytes.Equal(respPkt.Authenticator[:], expectedAuth[:]) {
		return nil, fmt.Errorf("response authenticator verification failed")
	}

	if c.dict != nil {
		respPkt.Dict = c.dict
	}

	if c.verifyMessageAuth {
		if !respPkt.VerifyMessageAuthenticator(c.secret, pkt.Authenticator) {
			return nil, fmt.Errorf("message authenticator verification failed")
		}
	}

	return respPkt, nil
}

// CoA sends a Change-of-Authorization Request packet per RFC 5176
func (c *Client) CoA(attributes map[string]interface{}) (*Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := NewPacket(CodeCoARequest, identifier[0])
	if c.dict != nil {
		pkt.Dict = c.dict
	}

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// RFC 5176: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
	// Add Message-Authenticator placeholder first if needed (affects packet length)
	if c.useMessageAuth {
		pkt.AddMessageAuthenticator(c.secret, [16]byte{})
	}

	// Calculate and set the computed Request Authenticator
	pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(c.secret))

	// Recalculate Message-Authenticator with the computed Request Authenticator
	if c.useMessageAuth {
		pkt.RemoveAttributes(AttributeTypeMessageAuthenticator)
		pkt.AddMessageAuthenticator(c.secret, pkt.Authenticator)
	}

	return c.sendRequest(pkt)
}

// Disconnect sends a Disconnect-Request packet per RFC 5176
func (c *Client) Disconnect(attributes map[string]interface{}) (*Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := NewPacket(CodeDisconnectRequest, identifier[0])
	if c.dict != nil {
		pkt.Dict = c.dict
	}

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// RFC 5176: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
	// Add Message-Authenticator placeholder first if needed (affects packet length)
	if c.useMessageAuth {
		pkt.AddMessageAuthenticator(c.secret, [16]byte{})
	}

	// Calculate and set the computed Request Authenticator
	pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(c.secret))

	// Recalculate Message-Authenticator with the computed Request Authenticator
	if c.useMessageAuth {
		pkt.RemoveAttributes(AttributeTypeMessageAuthenticator)
		pkt.AddMessageAuthenticator(c.secret, pkt.Authenticator)
	}

	return c.sendRequest(pkt)
}

// AccessRequest sends an Access-Request packet per RFC 2865
func (c *Client) AccessRequest(attributes map[string]interface{}) (*Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := NewPacket(CodeAccessRequest, identifier[0])
	if c.dict != nil {
		pkt.Dict = c.dict
	}

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// RFC 2865 Section 3: Request Authenticator is 16 octets of random data
	authenticator := make([]byte, 16)
	if _, err := rand.Read(authenticator); err != nil {
		return nil, fmt.Errorf("failed to generate authenticator: %w", err)
	}
	pkt.SetAuthenticator([16]byte(authenticator))

	if c.useMessageAuth {
		pkt.AddMessageAuthenticator(c.secret, pkt.Authenticator)
	}

	return c.sendRequest(pkt)
}

// AccountingRequest sends an Accounting-Request packet per RFC 2866
func (c *Client) AccountingRequest(attributes map[string]interface{}) (*Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := NewPacket(CodeAccountingRequest, identifier[0])
	if c.dict != nil {
		pkt.Dict = c.dict
	}

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// RFC 2866: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
	// Add Message-Authenticator placeholder first if needed (affects packet length)
	if c.useMessageAuth {
		pkt.AddMessageAuthenticator(c.secret, [16]byte{})
	}

	// Calculate and set the computed Request Authenticator
	pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(c.secret))

	// Recalculate Message-Authenticator with the computed Request Authenticator
	if c.useMessageAuth {
		pkt.RemoveAttributes(AttributeTypeMessageAuthenticator)
		pkt.AddMessageAuthenticator(c.secret, pkt.Authenticator)
	}

	return c.sendRequest(pkt)
}
