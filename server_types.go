package goradius

import (
	"context"
	"net"
)

type Request struct {
	Context    context.Context
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	packet     *Packet // private - use GetAttribute() and ListAttributes()
	Secret     SecretResponse
}

// NewRequest creates a Request from a Packet and SecretResponse
func NewRequest(pkt *Packet, secret SecretResponse) *Request {
	return &Request{
		packet: pkt,
		Secret: secret,
	}
}

// GetAttribute returns all values for the given attribute name
func (r *Request) GetAttribute(name string) []AttributeValue {
	if r.packet == nil {
		return []AttributeValue{}
	}
	return r.packet.GetAttribute(name)
}

// ListAttributes returns a list of unique attribute names found in the request
func (r *Request) ListAttributes() []string {
	if r.packet == nil {
		return []string{}
	}
	return r.packet.ListAttributes()
}

// Code returns the packet code
func (r *Request) Code() Code {
	if r.packet == nil {
		return 0
	}
	return r.packet.Code
}

type Response struct {
	packet *Packet // private - use SetCode() and SetAttribute() methods
}

// Code returns the response packet code
func (r *Response) Code() Code {
	if r.packet == nil {
		return 0
	}
	return r.packet.Code
}

// GetAttribute returns all values for the given attribute name
func (r *Response) GetAttribute(name string) []AttributeValue {
	if r.packet == nil {
		return []AttributeValue{}
	}
	return r.packet.GetAttribute(name)
}

// ListAttributes returns a list of unique attribute names found in the response
func (r *Response) ListAttributes() []string {
	if r.packet == nil {
		return []string{}
	}
	return r.packet.ListAttributes()
}

type SecretRequest struct {
	Context    context.Context
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	// Attempt is the 0-based secret attempt index for secret rotation.
	// The server calls ServeSecret multiple times with increasing Attempt values
	// when the first secret fails to validate the packet.
	Attempt int
}

type SecretResponse struct {
	Secret   []byte
	Metadata map[string]any
	// Attempts is the total number of secrets available for rotation.
	// A value of 0 or 1 means no rotation (single secret).
	// When greater than 1, the server will try each secret in order
	// until one validates the packet.
	Attempts int
}

type Handler interface {
	ServeSecret(SecretRequest) (SecretResponse, error)
	ServeRADIUS(r *Request) (Response, error)
}

// Middleware wraps a Handler and returns a new Handler
type Middleware func(Handler) Handler

// HandlerFunc is an adapter to allow use of ordinary functions as RADIUS handlers
type HandlerFunc func(*Request) (Response, error)

// ServeSecret implements Handler interface for HandlerFunc (returns empty secret)
func (f HandlerFunc) ServeSecret(_ SecretRequest) (SecretResponse, error) {
	return SecretResponse{}, nil
}

// ServeRADIUS calls f(r)
func (f HandlerFunc) ServeRADIUS(r *Request) (Response, error) {
	return f(r)
}
