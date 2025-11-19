package client

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
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

	conn *net.UDPConn
	mu   sync.Mutex
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

func (c *Client) getConnection() (*net.UDPConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn, nil
	}

	udpAddr, err := net.ResolveUDPAddr("udp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	c.conn = conn
	return conn, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *Client) sendRequest(pkt *packet.Packet) (*packet.Packet, error) {
	conn, err := c.getConnection()
	if err != nil {
		return nil, err
	}

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
