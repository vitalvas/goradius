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

// SetAttribute sets a single attribute in the response packet.
// If the attribute already exists, it is removed first and then the new value is added.
// This ensures only one instance of the attribute exists.
// Returns an error if the attribute is not found in the dictionary.
func (r *Response) SetAttribute(name string, value interface{}) error {
	if r.packet == nil {
		return nil
	}

	r.packet.RemoveAttributeByName(name)
	return r.packet.AddAttributeByName(name, value)
}

// SetAttributes sets multiple attributes in the response packet.
// For each attribute, if it already exists, it is removed first and then the new values are added.
// Each attribute can have multiple values (array).
// Returns an error if any attribute is not found in the dictionary.
func (r *Response) SetAttributes(attrs map[string][]interface{}) error {
	if r.packet == nil {
		return nil
	}

	for name, values := range attrs {
		r.packet.RemoveAttributeByName(name)
		if err := r.packet.AddAttributeByName(name, values); err != nil {
			return err
		}
	}

	return nil
}

// AddAttribute adds a single attribute to the response packet.
// If the attribute already exists, the new value is appended (multiple values).
// Returns an error if the attribute is not found in the dictionary.
func (r *Response) AddAttribute(name string, value interface{}) error {
	if r.packet == nil {
		return nil
	}

	return r.packet.AddAttributeByName(name, value)
}

// AddAttributes adds multiple attributes to the response packet.
// For each attribute, if it already exists, the new values are appended (multiple values).
// Each attribute can have multiple values (array).
// Returns an error if any attribute is not found in the dictionary.
func (r *Response) AddAttributes(attrs map[string][]interface{}) error {
	if r.packet == nil {
		return nil
	}

	for name, values := range attrs {
		if err := r.packet.AddAttributeByName(name, values); err != nil {
			return err
		}
	}

	return nil
}

// DeleteAttribute removes all instances of the specified attribute from the response packet.
// Returns the number of attributes removed.
func (r *Response) DeleteAttribute(name string) int {
	if r.packet == nil {
		return 0
	}

	return r.packet.RemoveAttributeByName(name)
}
