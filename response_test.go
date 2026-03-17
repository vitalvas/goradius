package goradius

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewResponse(t *testing.T) {
	tests := []struct {
		name         string
		requestCode  Code
		expectedCode Code
	}{
		{"Access-Request", CodeAccessRequest, CodeAccessReject},
		{"Accounting-Request", CodeAccountingRequest, CodeAccountingResponse},
		{"Disconnect-Request", CodeDisconnectRequest, CodeDisconnectNAK},
		{"CoA-Request", CodeCoARequest, CodeCoANAK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqPkt := NewPacket(tt.requestCode, 42)
			req := &Request{
				Context:    context.Background(),
				LocalAddr:  &net.UDPAddr{},
				RemoteAddr: &net.UDPAddr{},
				packet:     reqPkt,
			}

			resp := NewResponse(req)

			assert.NotNil(t, resp.packet)
			assert.Equal(t, tt.expectedCode, resp.packet.Code)
			assert.Equal(t, uint8(42), resp.packet.Identifier)
		})
	}
}

func TestNewResponseWithDictionary(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	assert.NotNil(t, resp.packet)
	assert.NotNil(t, resp.packet.Dict)
	assert.Equal(t, dict, resp.packet.Dict)
}

func TestResponseSetCode(t *testing.T) {
	reqPkt := NewPacket(CodeAccessRequest, 1)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)
	assert.Equal(t, CodeAccessReject, resp.packet.Code)

	resp.SetCode(CodeAccessAccept)
	assert.Equal(t, CodeAccessAccept, resp.packet.Code)

	resp.SetCode(CodeAccessChallenge)
	assert.Equal(t, CodeAccessChallenge, resp.packet.Code)
}

func TestResponseSetAttribute(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)
	err := resp.SetAttribute("reply-message", "Welcome!")
	require.NoError(t, err)

	assert.Len(t, resp.packet.Attributes, 1)

	attrs := resp.packet.GetAttributes(18) // Reply-Message
	assert.Len(t, attrs, 1)
	assert.Equal(t, []byte("Welcome!"), attrs[0].Value)
}

func TestResponseSetAttributes(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))
	require.NoError(t, dict.AddVendor(ERXVendorDefinition))

	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	attrs := map[string][]interface{}{
		"reply-message":     {"Access granted"},
		"framed-ip-address": {"192.0.2.10"},
		"session-timeout":   {3600},
		"erx-primary-dns":   {"8.8.8.8"},
	}

	err := resp.SetAttributes(attrs)
	require.NoError(t, err)

	// Should have 4 attributes
	assert.Len(t, resp.packet.Attributes, 4)
}

func TestResponseSetCodeNilPacket(_ *testing.T) {
	resp := Response{packet: nil}

	// Should not crash
	resp.SetCode(CodeAccessAccept)
}

func TestResponseSetAttributeNilPacket(t *testing.T) {
	resp := Response{packet: nil}

	// Should not crash and return nil
	err := resp.SetAttribute("reply-message", "test")
	assert.NoError(t, err)
}

func TestResponseSetAttributesNilPacket(t *testing.T) {
	resp := Response{packet: nil}

	// Should not crash and return nil
	err := resp.SetAttributes(map[string][]interface{}{
		"reply-message": {"test"},
	})
	assert.NoError(t, err)
}

func TestResponseAddAttributeNilPacket(t *testing.T) {
	resp := Response{packet: nil}

	// Should not crash and return nil
	err := resp.AddAttribute("reply-message", "test")
	assert.NoError(t, err)
}

func TestResponseAddAttributesNilPacket(t *testing.T) {
	resp := Response{packet: nil}

	// Should not crash and return nil
	err := resp.AddAttributes(map[string][]interface{}{
		"reply-message": {"test"},
	})
	assert.NoError(t, err)
}

func TestResponseSetAttributesWithMultipleValues(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	// Set multiple values for the same attribute using array syntax
	err := resp.SetAttributes(map[string][]interface{}{
		"reply-message":   {"First message", "Second message", "Third message"},
		"session-timeout": {3600},
	})
	require.NoError(t, err)

	// Verify we have 4 attributes total (3 Reply-Message + 1 Session-Timeout)
	assert.Len(t, resp.packet.Attributes, 4)

	// Verify all Reply-Message values are present
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 3)
	assert.Equal(t, "First message", msgs[0].String())
	assert.Equal(t, "Second message", msgs[1].String())
	assert.Equal(t, "Third message", msgs[2].String())

	// Verify Session-Timeout
	timeouts := resp.GetAttribute("session-timeout")
	assert.Len(t, timeouts, 1)
	assert.Equal(t, "3600", timeouts[0].String())
}

func TestResponseMultipleAttributes(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	// Set attributes - SetAttribute now overwrites, so only last value remains
	require.NoError(t, resp.SetAttribute("reply-message", "First message"))
	require.NoError(t, resp.SetAttribute("reply-message", "Second message")) // This overwrites the first
	require.NoError(t, resp.SetAttribute("session-timeout", 3600))

	// Should have 2 attributes (Reply-Message with last value + Session-Timeout)
	assert.Len(t, resp.packet.Attributes, 2)

	// Verify Reply-Message has only the last value
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "Second message", msgs[0].String())
}

func TestResponseFullWorkflow(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

	// Create request
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 42, dict)
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
	resp.SetCode(CodeAccessAccept)

	// Add attributes
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":     {"Access granted"},
		"session-timeout":   {3600},
		"framed-ip-address": {"192.0.2.10"},
	}))

	// Verify response
	assert.Equal(t, CodeAccessAccept, resp.packet.Code)
	assert.Equal(t, uint8(42), resp.packet.Identifier)
	assert.Len(t, resp.packet.Attributes, 3)

	// Encode and verify
	resp.packet.SetAuthenticator(resp.packet.CalculateResponseAuthenticator(
		req.Secret.Secret,
		reqPkt.Authenticator,
	))

	data, err := resp.packet.Encode()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestResponseSetAttributeOverwrites(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Set attribute first time
	require.NoError(t, resp.SetAttribute("reply-message", "First message"))

	// Set attribute second time - should overwrite
	require.NoError(t, resp.SetAttribute("reply-message", "Second message"))

	// Verify only one instance exists
	attrs := resp.GetAttribute("reply-message")
	assert.Len(t, attrs, 1)
	assert.Equal(t, "Second message", attrs[0].String())
}

func TestResponseSetAttributeOverwritesFramedPool(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Exact scenario from user's question
	require.NoError(t, resp.SetAttribute("framed-pool", "dhcp-pool-cgnat"))

	// Verify first value is set
	attrs1 := resp.GetAttribute("framed-pool")
	assert.Len(t, attrs1, 1)
	assert.Equal(t, "dhcp-pool-cgnat", attrs1[0].String())

	// Set again - should overwrite
	require.NoError(t, resp.SetAttribute("framed-pool", "dhcp-pool-cgnat-v2"))

	// Verify only second value exists (overwrote first)
	attrs2 := resp.GetAttribute("framed-pool")
	assert.Len(t, attrs2, 1, "Should have exactly 1 Framed-Pool attribute after overwrite")
	assert.Equal(t, "dhcp-pool-cgnat-v2", attrs2[0].String(), "Should have the second (latest) value")
}

func TestResponseSetAttributesOverwrites(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Set attributes first time
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":   {"First message"},
		"session-timeout": {3600},
	}))

	// Set attributes second time - should overwrite
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":   {"Second message"},
		"session-timeout": {7200},
	}))

	// Verify only one instance of each exists
	replyMsgs := resp.GetAttribute("reply-message")
	assert.Len(t, replyMsgs, 1)
	assert.Equal(t, "Second message", replyMsgs[0].String())

	timeouts := resp.GetAttribute("session-timeout")
	assert.Len(t, timeouts, 1)
	assert.Equal(t, "7200", timeouts[0].String())
}

func TestResponseAddAttributeAppends(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Add attribute first time
	require.NoError(t, resp.AddAttribute("reply-message", "First message"))

	// Add attribute second time - should append
	require.NoError(t, resp.AddAttribute("reply-message", "Second message"))

	// Add attribute third time - should append
	require.NoError(t, resp.AddAttribute("reply-message", "Third message"))

	// Verify all three instances exist
	attrs := resp.GetAttribute("reply-message")
	assert.Len(t, attrs, 3)
	assert.Equal(t, "First message", attrs[0].String())
	assert.Equal(t, "Second message", attrs[1].String())
	assert.Equal(t, "Third message", attrs[2].String())
}

func TestResponseAddAttributesAppends(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Add attributes first time
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message": {"First message"},
	}))

	// Add attributes second time - should append
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message": {"Second message"},
	}))

	// Verify both instances exist
	attrs := resp.GetAttribute("reply-message")
	assert.Len(t, attrs, 2)
}

func TestResponseAddAttributesWithMultipleValues(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{
		Context: context.Background(),
		packet:  reqPkt,
	}

	resp := NewResponse(req)

	// Add multiple values for the same attribute using array syntax
	err := resp.AddAttributes(map[string][]interface{}{
		"reply-message":   {"First message", "Second message", "Third message"},
		"session-timeout": {3600},
	})
	require.NoError(t, err)

	// Verify we have 4 attributes total (3 Reply-Message + 1 Session-Timeout)
	assert.Len(t, resp.packet.Attributes, 4)

	// Verify all Reply-Message values are present
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 3)
	assert.Equal(t, "First message", msgs[0].String())
	assert.Equal(t, "Second message", msgs[1].String())
	assert.Equal(t, "Third message", msgs[2].String())

	// Verify Session-Timeout
	timeouts := resp.GetAttribute("session-timeout")
	assert.Len(t, timeouts, 1)
	assert.Equal(t, "3600", timeouts[0].String())
}

func TestResponseSetAttributesThenAddAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Set attributes first (removes any existing and adds new)
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":   {"First message", "Second message"},
		"session-timeout": {3600},
	}))

	// Should have 3 attributes (2 Reply-Message + 1 Session-Timeout)
	assert.Len(t, resp.packet.Attributes, 3)

	// Add attributes (should append to existing)
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":     {"Third message"},
		"framed-ip-address": {"192.0.2.1"},
	}))

	// Should have 5 attributes (3 Reply-Message + 1 Session-Timeout + 1 Framed-IP)
	assert.Len(t, resp.packet.Attributes, 5)

	// Verify Reply-Message has all 3 values
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 3)
	assert.Equal(t, "First message", msgs[0].String())
	assert.Equal(t, "Second message", msgs[1].String())
	assert.Equal(t, "Third message", msgs[2].String())

	// Verify Session-Timeout still exists
	timeouts := resp.GetAttribute("session-timeout")
	assert.Len(t, timeouts, 1)
	assert.Equal(t, "3600", timeouts[0].String())

	// Verify Framed-IP-Address was added
	ips := resp.GetAttribute("framed-ip-address")
	assert.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.1", ips[0].String())
}

func TestResponseAddAttributesThenSetAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add attributes first
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":   {"First message", "Second message", "Third message"},
		"session-timeout": {3600},
	}))

	// Should have 4 attributes (3 Reply-Message + 1 Session-Timeout)
	assert.Len(t, resp.packet.Attributes, 4)

	// Set attributes (should overwrite existing Reply-Message, keep Session-Timeout)
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":     {"Final message"},
		"framed-ip-address": {"192.0.2.1"},
	}))

	// Should have 3 attributes (1 Reply-Message + 1 Session-Timeout + 1 Framed-IP)
	assert.Len(t, resp.packet.Attributes, 3)

	// Verify Reply-Message was overwritten to single value
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "Final message", msgs[0].String())

	// Verify Session-Timeout still exists
	timeouts := resp.GetAttribute("session-timeout")
	assert.Len(t, timeouts, 1)
	assert.Equal(t, "3600", timeouts[0].String())

	// Verify Framed-IP-Address was added
	ips := resp.GetAttribute("framed-ip-address")
	assert.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.1", ips[0].String())
}

func TestResponseSetThenAddAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Set attribute (should have only one)
	require.NoError(t, resp.SetAttribute("reply-message", "Set message"))

	// Add attribute (should append)
	require.NoError(t, resp.AddAttribute("reply-message", "Added message"))

	// Verify two instances exist
	attrs := resp.GetAttribute("reply-message")
	assert.Len(t, attrs, 2)
	assert.Equal(t, "Set message", attrs[0].String())
	assert.Equal(t, "Added message", attrs[1].String())
}

func TestResponseAddThenSetAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Add attribute multiple times
	require.NoError(t, resp.AddAttribute("reply-message", "First message"))
	require.NoError(t, resp.AddAttribute("reply-message", "Second message"))
	require.NoError(t, resp.AddAttribute("reply-message", "Third message"))

	// Set attribute (should remove all and add one)
	require.NoError(t, resp.SetAttribute("reply-message", "Final message"))

	// Verify only one instance exists
	attrs := resp.GetAttribute("reply-message")
	assert.Len(t, attrs, 1)
	assert.Equal(t, "Final message", attrs[0].String())
}

func TestResponseSetAttributeNotInDictionary(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Try to set an attribute that doesn't exist in the dictionary
	err = resp.SetAttribute("NonExistent-Attribute", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestResponseSetAttributesNotInDictionary(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Try to set attributes where one doesn't exist in the dictionary
	err = resp.SetAttributes(map[string][]interface{}{
		"reply-message":         {"Valid attribute"},
		"NonExistent-Attribute": {"Invalid attribute"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestResponseAddAttributeNotInDictionary(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Try to add an attribute that doesn't exist in the dictionary
	err = resp.AddAttribute("NonExistent-Attribute", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestResponseAddAttributesNotInDictionary(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// Create a test request
	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Try to add attributes where one doesn't exist in the dictionary
	err = resp.AddAttributes(map[string][]interface{}{
		"reply-message":         {"Valid attribute"},
		"NonExistent-Attribute": {"Invalid attribute"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestResponseNoDictionary(t *testing.T) {
	// Create a test request without dictionary
	pkt := NewPacket(CodeAccessRequest, 1)
	req := &Request{packet: pkt}

	// Create response
	resp := NewResponse(req)

	// Try to set an attribute without a dictionary
	err := resp.SetAttribute("reply-message", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no dictionary loaded")
}

func TestResponseDeleteAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add some attributes
	require.NoError(t, resp.AddAttribute("reply-message", "First message"))
	require.NoError(t, resp.AddAttribute("reply-message", "Second message"))
	require.NoError(t, resp.AddAttribute("session-timeout", 3600))

	// Verify we have 3 attributes
	assert.Len(t, resp.packet.Attributes, 3)

	// Delete Reply-Message (should remove 2 instances)
	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 2, removed, "Should remove 2 Reply-Message attributes")

	// Verify only Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 1)
	attrs := resp.GetAttribute("session-timeout")
	assert.Len(t, attrs, 1)
	assert.Equal(t, "3600", attrs[0].String())

	// Verify Reply-Message is gone
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 0)
}

func TestResponseDeleteAttributeNonExistent(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add an attribute
	require.NoError(t, resp.AddAttribute("session-timeout", 3600))

	// Try to delete non-existent attribute
	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 0, removed, "Should remove 0 attributes")

	// Verify Session-Timeout still exists
	assert.Len(t, resp.packet.Attributes, 1)
}

func TestResponseDeleteAttributeNilPacket(t *testing.T) {
	resp := Response{packet: nil}

	// Should not crash and return 0
	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 0, removed)
}

func TestResponseDeleteAttributeThenAdd(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add, Delete, then Add again
	require.NoError(t, resp.AddAttribute("reply-message", "First message"))
	require.NoError(t, resp.AddAttribute("reply-message", "Second message"))

	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 2, removed)

	require.NoError(t, resp.AddAttribute("reply-message", "New message"))

	// Verify only new message exists
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "New message", msgs[0].String())
}

func TestResponseDeleteAttributeVSA(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add vendor-specific attribute
	require.NoError(t, resp.AddAttribute("erx-primary-dns", "8.8.8.8"))
	require.NoError(t, resp.AddAttribute("erx-primary-dns", "8.8.4.4"))
	require.NoError(t, resp.AddAttribute("session-timeout", 3600))

	// Verify we have 3 attributes
	assert.Len(t, resp.packet.Attributes, 3)

	// Delete VSA
	removed := resp.DeleteAttribute("erx-primary-dns")
	assert.Equal(t, 2, removed, "Should remove 2 ERX-Primary-Dns attributes")

	// Verify only Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 1)

	// Verify ERX-Primary-Dns is gone
	dns := resp.GetAttribute("erx-primary-dns")
	assert.Len(t, dns, 0)
}

// High Priority: Delete-related combinations

func TestResponseSetAttributeThenDelete(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Set → Delete
	require.NoError(t, resp.SetAttribute("reply-message", "Test message"))
	require.NoError(t, resp.SetAttribute("session-timeout", 3600))

	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 1, removed)

	// Verify only Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 1)
	attrs := resp.GetAttribute("session-timeout")
	assert.Len(t, attrs, 1)
}

func TestResponseAddAttributeThenDelete(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add → Delete
	require.NoError(t, resp.AddAttribute("reply-message", "First"))
	require.NoError(t, resp.AddAttribute("reply-message", "Second"))
	require.NoError(t, resp.AddAttribute("session-timeout", 3600))

	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 2, removed)

	// Verify only Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 1)
	attrs := resp.GetAttribute("session-timeout")
	assert.Len(t, attrs, 1)
}

func TestResponseDeleteThenSetAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Delete → Set
	require.NoError(t, resp.AddAttribute("reply-message", "Old message"))
	resp.DeleteAttribute("reply-message")
	require.NoError(t, resp.SetAttribute("reply-message", "New message"))

	// Verify only new message exists
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "New message", msgs[0].String())
}

func TestResponseDeleteThenDelete(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Delete → Delete (verify idempotent)
	require.NoError(t, resp.AddAttribute("reply-message", "Test"))
	require.NoError(t, resp.AddAttribute("session-timeout", 3600))

	removed1 := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 1, removed1)

	removed2 := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 0, removed2, "Second delete should return 0")

	// Verify Session-Timeout still exists
	assert.Len(t, resp.packet.Attributes, 1)
}

// Medium Priority: Bulk operations

func TestResponseSetAttributeThenSetAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Set → SetS
	require.NoError(t, resp.SetAttribute("reply-message", "Single"))
	require.NoError(t, resp.SetAttribute("session-timeout", 1800))

	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":     {"Bulk message"},
		"framed-ip-address": {"192.0.2.1"},
	}))

	// Reply-Message should be overwritten, Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 3)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "Bulk message", msgs[0].String())
}

func TestResponseSetAttributesThenSetAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// SetS → Set
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":   {"Bulk 1", "Bulk 2"},
		"session-timeout": {3600},
	}))

	require.NoError(t, resp.SetAttribute("reply-message", "Single"))

	// Reply-Message should be overwritten to single, Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 2)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "Single", msgs[0].String())
}

func TestResponseAddAttributeThenAddAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add → AddS
	require.NoError(t, resp.AddAttribute("reply-message", "Single"))
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":   {"Bulk 1", "Bulk 2"},
		"session-timeout": {3600},
	}))

	// All Reply-Messages should be present
	assert.Len(t, resp.packet.Attributes, 4)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 3)
	assert.Equal(t, "Single", msgs[0].String())
	assert.Equal(t, "Bulk 1", msgs[1].String())
	assert.Equal(t, "Bulk 2", msgs[2].String())
}

func TestResponseAddAttributesThenAddAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// AddS → Add
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":   {"Bulk 1", "Bulk 2"},
		"session-timeout": {3600},
	}))
	require.NoError(t, resp.AddAttribute("reply-message", "Single"))

	// All Reply-Messages should be present
	assert.Len(t, resp.packet.Attributes, 4)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 3)
	assert.Equal(t, "Bulk 1", msgs[0].String())
	assert.Equal(t, "Bulk 2", msgs[1].String())
	assert.Equal(t, "Single", msgs[2].String())
}

func TestResponseSetAttributesThenDelete(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// SetS → Del
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":   {"Msg 1", "Msg 2"},
		"session-timeout": {3600},
	}))

	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 2, removed)

	// Only Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 1)
	attrs := resp.GetAttribute("session-timeout")
	assert.Len(t, attrs, 1)
}

func TestResponseAddAttributesThenDelete(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// AddS → Del
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":   {"Msg 1", "Msg 2", "Msg 3"},
		"session-timeout": {3600},
	}))

	removed := resp.DeleteAttribute("reply-message")
	assert.Equal(t, 3, removed)

	// Only Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 1)
	attrs := resp.GetAttribute("session-timeout")
	assert.Len(t, attrs, 1)
}

// Low Priority: Cross bulk/single combinations

func TestResponseSetAttributeThenAddAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Set → AddS
	require.NoError(t, resp.SetAttribute("reply-message", "Single"))
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":     {"Bulk 1", "Bulk 2"},
		"framed-ip-address": {"192.0.2.1"},
	}))

	// All Reply-Messages should be present
	assert.Len(t, resp.packet.Attributes, 4)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 3)
	assert.Equal(t, "Single", msgs[0].String())
	assert.Equal(t, "Bulk 1", msgs[1].String())
	assert.Equal(t, "Bulk 2", msgs[2].String())
}

func TestResponseSetAttributesThenAddAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// SetS → Add
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":   {"Bulk 1", "Bulk 2"},
		"session-timeout": {3600},
	}))
	require.NoError(t, resp.AddAttribute("reply-message", "Single"))

	// All Reply-Messages should be present
	assert.Len(t, resp.packet.Attributes, 4)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 3)
	assert.Equal(t, "Bulk 1", msgs[0].String())
	assert.Equal(t, "Bulk 2", msgs[1].String())
	assert.Equal(t, "Single", msgs[2].String())
}

func TestResponseAddAttributeThenSetAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Add → SetS
	require.NoError(t, resp.AddAttribute("reply-message", "Single"))
	require.NoError(t, resp.AddAttribute("session-timeout", 1800))
	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":     {"Bulk"},
		"framed-ip-address": {"192.0.2.1"},
	}))

	// Reply-Message overwritten, Session-Timeout remains, Framed-IP added
	assert.Len(t, resp.packet.Attributes, 3)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "Bulk", msgs[0].String())
}

func TestResponseAddAttributesThenSetAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// AddS → Set
	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":   {"Bulk 1", "Bulk 2"},
		"session-timeout": {3600},
	}))
	require.NoError(t, resp.SetAttribute("reply-message", "Single"))

	// Reply-Message overwritten to single, Session-Timeout remains
	assert.Len(t, resp.packet.Attributes, 2)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 1)
	assert.Equal(t, "Single", msgs[0].String())
}

func TestResponseDeleteThenSetAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Del → SetS
	require.NoError(t, resp.AddAttribute("reply-message", "Old"))
	require.NoError(t, resp.AddAttribute("session-timeout", 1800))
	resp.DeleteAttribute("reply-message")

	require.NoError(t, resp.SetAttributes(map[string][]interface{}{
		"reply-message":     {"New 1", "New 2"},
		"framed-ip-address": {"192.0.2.1"},
	}))

	// New Reply-Messages + Session-Timeout + Framed-IP
	assert.Len(t, resp.packet.Attributes, 4)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 2)
	assert.Equal(t, "New 1", msgs[0].String())
	assert.Equal(t, "New 2", msgs[1].String())
}

func TestResponseDeleteThenAddAttributes(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: pkt}
	resp := NewResponse(req)

	// Del → AddS
	require.NoError(t, resp.AddAttribute("reply-message", "Old"))
	require.NoError(t, resp.AddAttribute("session-timeout", 1800))
	resp.DeleteAttribute("reply-message")

	require.NoError(t, resp.AddAttributes(map[string][]interface{}{
		"reply-message":     {"New 1", "New 2"},
		"framed-ip-address": {"192.0.2.1"},
	}))

	// New Reply-Messages + Session-Timeout + Framed-IP
	assert.Len(t, resp.packet.Attributes, 4)
	msgs := resp.GetAttribute("reply-message")
	assert.Len(t, msgs, 2)
	assert.Equal(t, "New 1", msgs[0].String())
	assert.Equal(t, "New 2", msgs[1].String())
}

// Benchmarks

func BenchmarkResponseSetAttribute(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}
	resp := NewResponse(req)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = resp.SetAttribute("session-timeout", uint32(3600))
	}
}

func BenchmarkResponseSetAttributes(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}

	attrs := map[string][]interface{}{
		"session-timeout":   {uint32(3600)},
		"framed-ip-address": {"10.0.0.1"},
		"framed-ip-netmask": {"255.255.255.0"},
		"service-type":      {uint32(2)},
		"framed-mtu":        {uint32(1500)},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp := NewResponse(req)
		_ = resp.SetAttributes(attrs)
	}
}

func BenchmarkResponseAddAttribute(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}
	resp := NewResponse(req)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = resp.AddAttribute("reply-message", "Welcome")
	}
}

func BenchmarkResponseAddAttributes(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}

	attrs := map[string][]interface{}{
		"reply-message":     {"Welcome"},
		"session-timeout":   {uint32(3600)},
		"framed-ip-address": {"10.0.0.1"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp := NewResponse(req)
		_ = resp.AddAttributes(attrs)
	}
}

func BenchmarkResponseSetCode(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}
	resp := NewResponse(req)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp.SetCode(CodeAccessAccept)
	}
}

func BenchmarkResponseGetAttribute(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}
	resp := NewResponse(req)
	_ = resp.SetAttribute("session-timeout", uint32(3600))

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = resp.GetAttribute("session-timeout")
		}
	})
}

func BenchmarkResponseListAttributes(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}
	resp := NewResponse(req)
	_ = resp.SetAttribute("session-timeout", uint32(3600))
	_ = resp.SetAttribute("framed-ip-address", "10.0.0.1")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = resp.ListAttributes()
		}
	})
}

func BenchmarkCompleteResponseCreation(b *testing.B) {
	dict, _ := NewDefault()
	reqPkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	req := &Request{packet: reqPkt}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp := NewResponse(req)
		resp.SetCode(CodeAccessAccept)
		_ = resp.SetAttribute("session-timeout", uint32(3600))
		_ = resp.SetAttribute("framed-ip-address", "10.0.0.1")
		_ = resp.SetAttribute("framed-ip-netmask", "255.255.255.0")
		_ = resp.AddAttribute("reply-message", "Authentication successful")
	}
}
