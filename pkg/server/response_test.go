package server

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestNewResponse(t *testing.T) {
	tests := []struct {
		name         string
		requestCode  packet.Code
		expectedCode packet.Code
	}{
		{"Access-Request", packet.CodeAccessRequest, packet.CodeAccessReject},
		{"Accounting-Request", packet.CodeAccountingRequest, packet.CodeAccountingResponse},
		{"Disconnect-Request", packet.CodeDisconnectRequest, packet.CodeDisconnectNAK},
		{"CoA-Request", packet.CodeCoARequest, packet.CodeCoANAK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqPkt := packet.New(tt.requestCode, 42)
			req := &Request{
				Context:    context.Background(),
				LocalAddr:  &net.UDPAddr{},
				RemoteAddr: &net.UDPAddr{},
				packet:     reqPkt,
			}

			resp := NewResponse(req)

			assert.NotNil(t, resp.Packet)
			assert.Equal(t, tt.expectedCode, resp.Packet.Code)
			assert.Equal(t, uint8(42), resp.Packet.Identifier)
		})
	}
}

func TestNewResponseWithDictionary(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	assert.NotNil(t, resp.Packet)
	assert.NotNil(t, resp.Packet.Dict)
	assert.Equal(t, dict, resp.Packet.Dict)
}

func TestResponseSetCode(t *testing.T) {
	reqPkt := packet.New(packet.CodeAccessRequest, 1)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)
	assert.Equal(t, packet.CodeAccessReject, resp.Packet.Code)

	resp.SetCode(packet.CodeAccessAccept)
	assert.Equal(t, packet.CodeAccessAccept, resp.Packet.Code)

	resp.SetCode(packet.CodeAccessChallenge)
	assert.Equal(t, packet.CodeAccessChallenge, resp.Packet.Code)
}

func TestResponseSetAttribute(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)
	resp.SetAttribute("Reply-Message", "Welcome!")

	assert.Len(t, resp.Packet.Attributes, 1)

	attrs := resp.Packet.GetAttributes(18) // Reply-Message
	assert.Len(t, attrs, 1)
	assert.Equal(t, []byte("Welcome!"), attrs[0].Value)
}

func TestResponseSetAttributes(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)
	dict.AddVendor(dictionaries.ERXVendorDefinition)

	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	attrs := map[string]interface{}{
		"Reply-Message":      "Access granted",
		"Framed-IP-Address":  "192.0.2.10",
		"Session-Timeout":    3600,
		"ERX-Primary-Dns":    "8.8.8.8",
	}

	resp.SetAttributes(attrs)

	// Should have 4 attributes
	assert.Len(t, resp.Packet.Attributes, 4)
}

func TestResponseSetCodeNilPacket(_ *testing.T) {
	resp := Response{Packet: nil}

	// Should not crash
	resp.SetCode(packet.CodeAccessAccept)
}

func TestResponseSetAttributeNilPacket(_ *testing.T) {
	resp := Response{Packet: nil}

	// Should not crash
	resp.SetAttribute("Reply-Message", "test")
}

func TestResponseSetAttributesNilPacket(_ *testing.T) {
	resp := Response{Packet: nil}

	// Should not crash
	resp.SetAttributes(map[string]interface{}{
		"Reply-Message": "test",
	})
}

func TestResponseMultipleAttributes(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	// Add attributes one by one
	resp.SetAttribute("Reply-Message", "First message")
	resp.SetAttribute("Reply-Message", "Second message")
	resp.SetAttribute("Session-Timeout", 3600)

	// Should have 3 attributes
	assert.Len(t, resp.Packet.Attributes, 3)
}

func TestResponseFullWorkflow(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

	// Create request
	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 42, dict)
	req := &Request{
		Context:    context.Background(),
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 50000},
		packet:     reqPkt,
		Secret: SecretResponse{
			Secret: []byte("testing123"),
		},
	}

	// Create response
	resp := NewResponse(req)

	// Set code to accept
	resp.SetCode(packet.CodeAccessAccept)

	// Add attributes
	resp.SetAttributes(map[string]interface{}{
		"Reply-Message":      "Access granted",
		"Session-Timeout":    3600,
		"Framed-IP-Address":  "192.0.2.10",
	})

	// Verify response
	assert.Equal(t, packet.CodeAccessAccept, resp.Packet.Code)
	assert.Equal(t, uint8(42), resp.Packet.Identifier)
	assert.Len(t, resp.Packet.Attributes, 3)

	// Encode and verify
	resp.Packet.SetAuthenticator(resp.Packet.CalculateResponseAuthenticator(
		req.Secret.Secret,
		reqPkt.Authenticator,
	))

	data, err := resp.Packet.Encode()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
}
