package client

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/packet"
)

type Client struct {
	addr              string
	secret            []byte
	dict              *dictionary.Dictionary
	timeout           time.Duration
	useMessageAuth    bool
	verifyMessageAuth bool
}

type Config struct {
	Addr                       string
	Secret                     []byte
	Dictionary                 *dictionary.Dictionary
	Timeout                    time.Duration
	UseMessageAuthenticator    *bool
	VerifyMessageAuthenticator *bool
}

func New(cfg Config) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second
	}

	useMessageAuth := true
	if cfg.UseMessageAuthenticator != nil {
		useMessageAuth = *cfg.UseMessageAuthenticator
	}

	verifyMessageAuth := true
	if cfg.VerifyMessageAuthenticator != nil {
		verifyMessageAuth = *cfg.VerifyMessageAuthenticator
	}

	return &Client{
		addr:              cfg.Addr,
		secret:            cfg.Secret,
		dict:              cfg.Dictionary,
		timeout:           cfg.Timeout,
		useMessageAuth:    useMessageAuth,
		verifyMessageAuth: verifyMessageAuth,
	}, nil
}

func (c *Client) Close() error {
	return nil
}

func (c *Client) sendRequest(pkt *packet.Packet) (*packet.Packet, error) {
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

	respPkt, err := packet.Decode(buffer[:n])
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

func (c *Client) CoA(attributes map[string]interface{}) (*packet.Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := packet.New(packet.CodeCoARequest, identifier[0])
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
		pkt.RemoveAttributes(packet.AttributeTypeMessageAuthenticator)
		pkt.AddMessageAuthenticator(c.secret, pkt.Authenticator)
	}

	return c.sendRequest(pkt)
}

func (c *Client) Disconnect(attributes map[string]interface{}) (*packet.Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := packet.New(packet.CodeDisconnectRequest, identifier[0])
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
		pkt.RemoveAttributes(packet.AttributeTypeMessageAuthenticator)
		pkt.AddMessageAuthenticator(c.secret, pkt.Authenticator)
	}

	return c.sendRequest(pkt)
}

func (c *Client) AccessRequest(attributes map[string]interface{}) (*packet.Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := packet.New(packet.CodeAccessRequest, identifier[0])
	if c.dict != nil {
		pkt.Dict = c.dict
	}

	for name, value := range attributes {
		if err := pkt.AddAttributeByName(name, value); err != nil {
			return nil, fmt.Errorf("failed to add attribute %q: %w", name, err)
		}
	}

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

func (c *Client) AccountingRequest(attributes map[string]interface{}) (*packet.Packet, error) {
	identifier := make([]byte, 1)
	if _, err := rand.Read(identifier); err != nil {
		return nil, fmt.Errorf("failed to generate identifier: %w", err)
	}

	pkt := packet.New(packet.CodeAccountingRequest, identifier[0])
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
		pkt.RemoveAttributes(packet.AttributeTypeMessageAuthenticator)
		pkt.AddMessageAuthenticator(c.secret, pkt.Authenticator)
	}

	return c.sendRequest(pkt)
}
