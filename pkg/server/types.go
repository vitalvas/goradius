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
	Packet     *packet.Packet
	Secret     SecretResponse
}

type Response struct {
	Packet *packet.Packet
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
