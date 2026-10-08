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

// WithVerifyMessageAuthenticator sets whether a Message-Authenticator must be
// present in responses to Access-Request and Status-Server (BlastRADIUS
// hardening). Responses to Accounting/CoA/Disconnect carry the attribute
// optionally per RFC 2866/5176, so servers that omit it keep working.
// Regardless of this setting, a Message-Authenticator that IS present is
// always verified and the response rejected on mismatch (RFC 3579 Section 3.2).
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

	// Close the connection as soon as the client is closed so Close()
	// unblocks an in-flight Write/Read instead of waiting for the deadline.
	// Hooked to the client context (not the request context) so a request
	// timeout still surfaces as a deadline error, not a closed connection.
	stop := context.AfterFunc(c.ctx, func() { conn.Close() })
	defer stop()

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
		if c.closed.Load() {
			return nil, ErrClientClosed
		}
		return nil, fmt.Errorf("failed to write packet: %w", err)
	}

	// Read until a verified response arrives. RFC 2865 Section 4.2: invalid
	// packets (undecodable, wrong Identifier, failed authenticators) are
	// silently discarded, so on UDP a stray or spoofed datagram must not
	// abort the exchange; the deadline bounds the wait. On TCP/TLS the
	// stream is framed by the server itself, so the first packet is
	// authoritative and a verification failure is fatal (RFC 6613).
	for {
		respData, err := c.readResponse(conn)
		if err != nil {
			if c.closed.Load() {
				return nil, ErrClientClosed
			}
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		respPkt, err := c.verifyResponse(pkt, respData)
		if err != nil {
			if c.transport == TransportUDP {
				continue
			}
			return nil, err
		}

		return respPkt, nil
	}
}

// verifyResponse decodes and authenticates a candidate response to req:
// Identifier match, Response Authenticator (RFC 2865 Section 3), and
// Message-Authenticator per the client policy. On success the returned
// packet carries the dictionary, the shared secret, and the request
// authenticator so encrypted attributes decrypt transparently.
func (c *Client) verifyResponse(req *Packet, respData []byte) (*Packet, error) {
	respPkt, err := Decode(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Verify response identifier matches request identifier (RFC 2865)
	if respPkt.Identifier != req.Identifier {
		return nil, fmt.Errorf("response identifier mismatch: expected %d, got %d", req.Identifier, respPkt.Identifier)
	}

	// Verify response authenticator (RFC 2865)
	expectedAuth := respPkt.CalculateResponseAuthenticator(c.secret, req.Authenticator)
	if !bytes.Equal(respPkt.Authenticator[:], expectedAuth[:]) {
		return nil, fmt.Errorf("response authenticator verification failed")
	}

	if c.dict != nil {
		respPkt.Dict = c.dict
	}

	// Carry the secret and the request's authenticator so encrypted reply
	// attributes (for example MPPE keys) decrypt transparently via
	// GetAttribute.
	respPkt.Secret = c.secret
	respPkt.bindRequestAuthenticator(req.Authenticator)

	// RFC 3579 Section 3.2: a Message-Authenticator present in the response
	// is always verified; verifyMessageAuth only governs whether its absence
	// is fatal, and that requirement covers the Access and Status-Server
	// exchanges, where BlastRADIUS-style forgery matters. Responses to
	// Accounting/CoA/Disconnect carry the attribute optionally (RFC
	// 2866/5176), so servers that omit it keep working.
	requireMsgAuth := c.verifyMessageAuth &&
		(req.Code == CodeAccessRequest || req.Code == CodeStatusServer)
	if requireMsgAuth || respPkt.hasMessageAuthenticator() {
		if !respPkt.VerifyMessageAuthenticator(c.secret, req.Authenticator) {
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
	pkt.Secret = c.secret

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// Encrypted attributes finalize transparently with a zero authenticator
	// (RFC 2868 Section 3.5 / RFC 5176) before the integrity values below are
	// computed.
	//
	// RFC 5176 Section 3.4: the Message-Authenticator is computed with the Request
	// Authenticator field zeroed and inserted first; the Request Authenticator is
	// then computed over the packet carrying the real Message-Authenticator value.
	if c.useMessageAuth {
		pkt.AddMessageAuthenticator(c.secret, [16]byte{})
	}

	// RFC 5176: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
	pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(c.secret))

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
	pkt.Secret = c.secret

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// Encrypted attributes finalize transparently with a zero authenticator
	// (RFC 2868 Section 3.5 / RFC 5176) before the integrity values below are
	// computed.
	//
	// RFC 5176 Section 3.4: the Message-Authenticator is computed with the Request
	// Authenticator field zeroed and inserted first; the Request Authenticator is
	// then computed over the packet carrying the real Message-Authenticator value.
	if c.useMessageAuth {
		pkt.AddMessageAuthenticator(c.secret, [16]byte{})
	}

	// RFC 5176: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
	pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(c.secret))

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
	pkt.Secret = c.secret

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// RFC 2865 Section 3: Request Authenticator is 16 octets of random data.
	// Encrypted attributes (User-Password, Tunnel-Password) finalize
	// transparently with this authenticator before the Message-Authenticator
	// HMAC and Encode render the packet (RFC 2865 Section 5.2 / RFC 2868).
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
	pkt.Secret = c.secret

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

	// Encrypted attributes finalize transparently with a zero authenticator
	// (RFC 2868 Section 3.5) before the integrity values below are computed.
	//
	// Message-Authenticator is computed with the Request Authenticator field zeroed
	// and inserted first, mirroring RFC 5176 Section 3.4; the Request Authenticator
	// is then computed over the packet carrying the real Message-Authenticator value.
	if c.useMessageAuth {
		pkt.AddMessageAuthenticator(c.secret, [16]byte{})
	}

	// RFC 2866: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
	pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(c.secret))

	return c.sendRequest(pkt)
}
