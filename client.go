package goradius

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"time"

)

type Client struct {
	addr              string
	secret            []byte
	dict              *Dictionary
	timeout           time.Duration
	useMessageAuth    bool
	verifyMessageAuth bool
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

func NewClient(opts ...ClientOption) (*Client, error) {
	c := &Client{
		timeout:           3 * time.Second,
		useMessageAuth:    true,
		verifyMessageAuth: true,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

func (c *Client) Close() error {
	return nil
}

func (c *Client) sendRequest(pkt *Packet) (*Packet, error) {
	// Create a new connection for each request to ensure concurrency safety
	udpAddr, err := net.ResolveUDPAddr("udp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	data, err := pkt.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode packet: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write packet: %w", err)
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	respPkt, err := Decode(buffer[:n])
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
