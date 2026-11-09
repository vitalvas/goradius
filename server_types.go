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

// GetAttributeStrings returns every request attribute name mapped to the
// string form of its values
func (r *Request) GetAttributeStrings() map[string][]string {
	if r.packet == nil {
		return map[string][]string{}
	}
	return r.packet.GetAttributeStrings()
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

// GetAttributeStrings returns every response attribute name mapped to the
// string form of its values
func (r *Response) GetAttributeStrings() map[string][]string {
	if r.packet == nil {
		return map[string][]string{}
	}
	return r.packet.GetAttributeStrings()
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

// MessageAuthPolicy controls when a Message-Authenticator (RFC 2869 Section
// 5.14) must be present. It is set server-wide with WithMessageAuthPolicy and
// overridden per device through SecretResponse.MessageAuthPolicy. Under every
// policy a Message-Authenticator that is present is verified and the packet
// dropped on mismatch (RFC 3579 Section 3.2), and Status-Server always
// requires one (RFC 5997 Section 4.2).
type MessageAuthPolicy uint8

const (
	// MessageAuthPolicyDefault defers to the server-wide policy. Passing it to
	// WithMessageAuthPolicy keeps the server default, MessageAuthPolicyAuto.
	MessageAuthPolicyDefault MessageAuthPolicy = 0
	// MessageAuthPolicyRequired is the strict mode: every request type,
	// including Accounting, CoA, and Disconnect, must carry a verified
	// Message-Authenticator.
	MessageAuthPolicyRequired MessageAuthPolicy = 1
	// MessageAuthPolicyOptional never requires the attribute.
	MessageAuthPolicyOptional MessageAuthPolicy = 2
	// MessageAuthPolicyAuto accepts Access-Requests without the attribute from
	// a device until that device has sent one that verified; from then on its
	// Access-Requests must carry one, matching FreeRADIUS
	// require_message_authenticator = auto. Devices are keyed by source IP and
	// the memory is in-process, so it starts empty on every server start.
	// Accounting, CoA, and Disconnect stay optional.
	MessageAuthPolicyAuto MessageAuthPolicy = 3
	// MessageAuthPolicyDisabled never requires the attribute and omits it from
	// replies, for devices that do not understand it. RFC 3579 Section 3.2
	// requires it in replies carrying EAP-Message, so reserve it for devices
	// that need it.
	MessageAuthPolicyDisabled MessageAuthPolicy = 4
)

type SecretResponse struct {
	Secret   []byte
	UserData map[string]string
	// Attempts is the total number of secrets available for rotation.
	// A value of 0 or 1 means no rotation (single secret).
	// When greater than 1, the server will try each secret in order
	// until one validates the packet.
	Attempts int
	// MessageAuthPolicy overrides the server-wide WithMessageAuthPolicy for
	// this device. Default defers to the server.
	MessageAuthPolicy MessageAuthPolicy
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
