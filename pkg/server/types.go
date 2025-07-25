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
