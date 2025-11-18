package server

import (
	"github.com/vitalvas/goradius/pkg/packet"
)

// NewResponse creates a new Response with the request identifier and appropriate default response code
func NewResponse(req *Request) Response {
	// Set default response code based on request type
	var responseCode packet.Code
	switch req.packet.Code {
	case packet.CodeAccessRequest:
		responseCode = packet.CodeAccessReject
	case packet.CodeAccountingRequest:
		responseCode = packet.CodeAccountingResponse
	case packet.CodeDisconnectRequest:
		responseCode = packet.CodeDisconnectNAK
	case packet.CodeCoARequest:
		responseCode = packet.CodeCoANAK
	default:
		responseCode = packet.CodeAccessReject // fallback
	}

	pkt := packet.New(responseCode, req.packet.Identifier)

	// Set dictionary from request packet
	if req.packet != nil && req.packet.Dict != nil {
		pkt.Dict = req.packet.Dict
	}

	return Response{
		packet: pkt,
	}
}

// SetCode sets the response packet code
func (r *Response) SetCode(code packet.Code) {
	if r.packet != nil {
		r.packet.Code = code
	}
}

// SetAttribute adds a single attribute to the response packet
func (r *Response) SetAttribute(name string, value interface{}) {
	if r.packet != nil {
		r.packet.AddAttributeByName(name, value)
	}
}

// SetAttributes adds multiple attributes to the response packet
func (r *Response) SetAttributes(attrs map[string]interface{}) {
	if r.packet != nil {
		for name, value := range attrs {
			r.packet.AddAttributeByName(name, value)
		}
	}
}
