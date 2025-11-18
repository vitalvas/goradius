package server

import (
	"context"
	"net"

	"github.com/vitalvas/goradius/pkg/packet"
)

type Request struct {
	Context    context.Context
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	packet     *packet.Packet // private - use GetAttribute() and ListAttributes()
	Secret     SecretResponse
}

// GetAttribute returns all values for the given attribute name
func (r *Request) GetAttribute(name string) []packet.AttributeValue {
	if r.packet == nil {
		return []packet.AttributeValue{}
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
func (r *Request) Code() packet.Code {
	if r.packet == nil {
		return 0
	}
	return r.packet.Code
}

type Response struct {
	packet *packet.Packet // private - use SetCode() and SetAttribute() methods
}

// Code returns the response packet code
func (r *Response) Code() packet.Code {
	if r.packet == nil {
		return 0
	}
	return r.packet.Code
}

type SecretRequest struct {
	Context    context.Context
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

type SecretResponse struct {
	Secret   []byte
	Metadata map[string]interface{}
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
