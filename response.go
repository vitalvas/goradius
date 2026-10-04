package goradius

// NewResponse creates a new Response with the request identifier and appropriate default response code.
// A nil request (or one without a packet) yields a Response whose methods are all no-ops.
func NewResponse(req *Request) Response {
	if req == nil || req.packet == nil {
		return Response{}
	}

	// Set default response code based on request type
	var responseCode Code
	switch req.packet.Code {
	case CodeAccessRequest:
		responseCode = CodeAccessReject
	case CodeAccountingRequest:
		responseCode = CodeAccountingResponse
	case CodeDisconnectRequest:
		responseCode = CodeDisconnectNAK
	case CodeCoARequest:
		responseCode = CodeCoANAK
	default:
		responseCode = CodeAccessReject // fallback
	}

	pkt := NewPacket(responseCode, req.packet.Identifier)

	// Set dictionary from request packet
	if req.packet.Dict != nil {
		pkt.Dict = req.packet.Dict
	}

	// Carry the shared secret so encrypted reply attributes (for example MPPE
	// keys) are marked for encryption as they are added; the server finalizes
	// them with the request authenticator before sending.
	pkt.Secret = req.Secret.Secret

	return Response{
		packet: pkt,
	}
}

// SetCode sets the response packet code
func (r *Response) SetCode(code Code) {
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

// SetAttributes replaces the response packet's attributes with the given flat
// attribute map. Keys are attribute names (optionally "name:tag"); values are
// slices, with each element becoming one attribute instance. Container members
// are addressed by their own flat child name. Existing instances of each key
// are removed first so the result reflects exactly the supplied map.
func (r *Response) SetAttributes(attrs map[string][]any) error {
	if r.packet == nil {
		return nil
	}

	for name := range attrs {
		base, _ := splitAttributeTag(name)
		r.packet.RemoveAttributeByName(base)
	}
	return r.packet.SetAttributes(attrs)
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

// AddAttributes adds multiple attributes to the response packet from a flat
// attribute map, appending to any existing instances. Keys are attribute names
// (optionally "name:tag"); values are slices, with each element becoming one
// attribute instance. Container members are addressed by their own flat child
// name.
func (r *Response) AddAttributes(attrs map[string][]any) error {
	if r.packet == nil {
		return nil
	}

	return r.packet.SetAttributes(attrs)
}

// DeleteAttribute removes all instances of the specified attribute from the response packet.
// Returns the number of attributes removed.
func (r *Response) DeleteAttribute(name string) int {
	if r.packet == nil {
		return 0
	}

	return r.packet.RemoveAttributeByName(name)
}
