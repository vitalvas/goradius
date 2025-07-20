package server

import (
	"strings"

	"github.com/vitalvas/goradius/pkg/packet"
)

// NewResponse creates a new Response with the request identifier and appropriate default response code
func NewResponse(req *Request) Response {
	// Set default response code based on request type
	var responseCode packet.Code
	switch req.Packet.Code {
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
	
	pkt := packet.New(responseCode, req.Packet.Identifier)
	
	// Set dictionary from request packet
	if req.Packet != nil && req.Packet.Dict != nil {
		pkt.Dict = req.Packet.Dict
	}
	
	return Response{
		Packet: pkt,
	}
}

// SetCode sets the response packet code
func (r *Response) SetCode(code packet.Code) {
	if r.Packet != nil {
		r.Packet.Code = code
	}
}

// SetAttribute adds a single attribute to the response packet using dictionary lookup
func (r *Response) SetAttribute(name string, value interface{}) {
	if r.Packet == nil || r.Packet.Dict == nil {
		return
	}

	// Look up attribute by name in dictionary
	attrDef, exists := r.Packet.Dict.LookupStandardByName(name)
	if !exists {
		return // Skip unknown attributes
	}

	// Encode value based on data type
	attrValue, err := packet.EncodeValue(value, attrDef.DataType)
	if err != nil {
		return // Skip invalid values
	}

	attr := packet.NewAttribute(uint8(attrDef.ID), attrValue)
	r.Packet.AddAttribute(attr)
}

// SetAttributes adds attributes to the response packet using dictionary lookup
func (r *Response) SetAttributes(attrs map[string]interface{}) {
	if r.Packet == nil || r.Packet.Dict == nil {
		return
	}

	for name, value := range attrs {
		// Handle vendor-specific attributes with tag notation (e.g., "ERX-Service-Activate:1")
		if strings.Contains(name, ":") {
			// This is a vendor attribute with tag or special format
			// For now, skip these - they need special handling
			continue
		}

		// Look up attribute by name in dictionary
		attrDef, exists := r.Packet.Dict.LookupStandardByName(name)
		if !exists {
			continue // Skip unknown attributes
		}

		// Encode value based on data type
		attrValue, err := packet.EncodeValue(value, attrDef.DataType)
		if err != nil {
			continue // Skip invalid values
		}

		attr := packet.NewAttribute(uint8(attrDef.ID), attrValue)
		r.Packet.AddAttribute(attr)
	}
}