package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestClientContext(t *testing.T) {
	t.Run("client context creation", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
		config := &ClientConfig{
			Networks: []string{"192.168.1.0/24"},
			Secret:   "test-secret",
			Name:     "test-client",
		}

		ctx := &ClientContext{
			Addr:         addr,
			Config:       config,
			Transport:    TransportUDP,
			LocalAddr:    &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812},
			RemoteAddr:   addr,
			ReceivedAt:   time.Now(),
			RequestID:    123,
			SessionID:    "session-123",
			UserName:     "testuser",
			SharedSecret: []byte("test-secret"),
			Attributes:   make(map[string]interface{}),
		}

		assert.Equal(t, addr, ctx.Addr)
		assert.Equal(t, config, ctx.Config)
		assert.Equal(t, TransportUDP, ctx.Transport)
		assert.Equal(t, uint64(123), ctx.RequestID)
		assert.Equal(t, "session-123", ctx.SessionID)
		assert.Equal(t, "testuser", ctx.UserName)
		assert.Equal(t, []byte("test-secret"), ctx.SharedSecret)
		assert.NotNil(t, ctx.Attributes)
	})

	t.Run("NAS info", func(t *testing.T) {
		nasInfo := &NASInfo{
			Identifier: "nas-01",
			IPAddress:  net.ParseIP("10.0.0.1"),
			Port:       uint32Ptr(1812),
			PortType:   uint32Ptr(5),
		}

		assert.Equal(t, "nas-01", nasInfo.Identifier)
		assert.Equal(t, net.ParseIP("10.0.0.1"), nasInfo.IPAddress)
		assert.Equal(t, uint32(1812), *nasInfo.Port)
		assert.Equal(t, uint32(5), *nasInfo.PortType)
	})
}

func TestTransportType(t *testing.T) {
	assert.Equal(t, TransportType("udp"), TransportUDP)
	assert.Equal(t, TransportType("tcp"), TransportTCP)
	// RADSEC is now handled as TCP with TLS
}

func TestHandlerResult(t *testing.T) {
	t.Run("complete handler result", func(t *testing.T) {
		pkt := &packet.Packet{
			Code:       packet.CodeAccessAccept,
			Identifier: 1,
			Length:     packet.PacketHeaderLength,
			Attributes: []packet.Attribute{},
		}

		result := &HandlerResult{
			Response:       pkt,
			Send:           true,
			Attributes:     map[string]interface{}{"test": "value"},
			ProcessingTime: 50 * time.Millisecond,
			HandlerName:    "test-handler",
		}

		assert.Equal(t, pkt, result.Response)
		assert.True(t, result.Send)
		assert.Equal(t, "value", result.Attributes["test"])
		assert.Equal(t, 50*time.Millisecond, result.ProcessingTime)
		assert.Equal(t, "test-handler", result.HandlerName)
		assert.Nil(t, result.Error)
	})
}

func TestHandlerChain(t *testing.T) {
	t.Run("empty chain", func(t *testing.T) {
		finalHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			return &HandlerResult{Send: true}, nil
		}

		chain := NewHandlerChain(finalHandler)
		assert.NotNil(t, chain)

		ctx := context.Background()
		clientCtx := &ClientContext{RequestID: 1}
		req := &packet.Packet{Code: packet.CodeAccessRequest}

		result, err := chain.Execute(ctx, clientCtx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Send)
	})

	t.Run("chain with middleware", func(t *testing.T) {
		executionOrder := make([]string, 0)

		middleware1 := func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
			executionOrder = append(executionOrder, "middleware1_before")
			result, err := next(ctx, clientCtx, req)
			executionOrder = append(executionOrder, "middleware1_after")
			return result, err
		}

		middleware2 := func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
			executionOrder = append(executionOrder, "middleware2_before")
			result, err := next(ctx, clientCtx, req)
			executionOrder = append(executionOrder, "middleware2_after")
			return result, err
		}

		finalHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			executionOrder = append(executionOrder, "final_handler")
			return &HandlerResult{Send: true}, nil
		}

		chain := NewHandlerChain(finalHandler, middleware1, middleware2)

		ctx := context.Background()
		clientCtx := &ClientContext{RequestID: 1}
		req := &packet.Packet{Code: packet.CodeAccessRequest}

		result, err := chain.Execute(ctx, clientCtx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Send)

		expectedOrder := []string{
			"middleware1_before",
			"middleware2_before",
			"final_handler",
			"middleware2_after",
			"middleware1_after",
		}
		assert.Equal(t, expectedOrder, executionOrder)
	})
}

func TestResponseBuilder(t *testing.T) {
	t.Run("basic response", func(t *testing.T) {
		builder := NewResponseBuilder(uint8(packet.CodeAccessAccept), 123)
		pkt := builder.Build()

		assert.Equal(t, packet.CodeAccessAccept, pkt.Code)
		assert.Equal(t, uint8(123), pkt.Identifier)
		assert.Equal(t, uint16(packet.PacketHeaderLength), pkt.Length)
		assert.Empty(t, pkt.Attributes)
	})

	t.Run("response with attributes", func(t *testing.T) {
		builder := NewResponseBuilder(uint8(packet.CodeAccessAccept), 123)
		builder.AddStringAttribute(packet.AttrReplyMessage, "Welcome")
		builder.AddIntegerAttribute(packet.AttrSessionTimeout, 3600)
		builder.AddIPAddressAttribute(packet.AttrFramedIPAddress, net.ParseIP("10.0.0.100"))

		pkt := builder.Build()

		assert.Equal(t, packet.CodeAccessAccept, pkt.Code)
		assert.Equal(t, uint8(123), pkt.Identifier)
		assert.Len(t, pkt.Attributes, 3)

		// Check Reply-Message
		replyAttr, found := pkt.GetAttribute(packet.AttrReplyMessage)
		require.True(t, found)
		assert.Equal(t, "Welcome", replyAttr.GetString())

		// Check Session-Timeout
		timeoutAttr, found := pkt.GetAttribute(packet.AttrSessionTimeout)
		require.True(t, found)
		timeoutValue, err := timeoutAttr.GetInteger()
		require.NoError(t, err)
		assert.Equal(t, uint32(3600), timeoutValue)

		// Check Framed-IP-Address
		ipAttr, found := pkt.GetAttribute(packet.AttrFramedIPAddress)
		require.True(t, found)
		ipBytes, err := ipAttr.GetIPAddress()
		require.NoError(t, err)
		expectedIP := net.ParseIP("10.0.0.100").To4()
		assert.Equal(t, expectedIP, net.IP(ipBytes[:]))
	})

	t.Run("method chaining", func(t *testing.T) {
		pkt := NewResponseBuilder(uint8(packet.CodeAccessReject), 200).
			AddStringAttribute(packet.AttrReplyMessage, "Access denied").
			AddIntegerAttribute(packet.AttrSessionTimeout, 0).
			Build()

		assert.Equal(t, packet.CodeAccessReject, pkt.Code)
		assert.Equal(t, uint8(200), pkt.Identifier)
		assert.Len(t, pkt.Attributes, 2)
	})
}

func TestHandlerError(t *testing.T) {
	t.Run("basic error", func(t *testing.T) {
		err := NewHandlerError(ErrorCodeInvalidRequest, "test error", nil)

		assert.Equal(t, ErrorCodeInvalidRequest, err.Code)
		assert.Equal(t, "test error", err.Message)
		assert.Nil(t, err.Cause)
		assert.NotNil(t, err.Context)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("error with cause", func(t *testing.T) {
		cause := assert.AnError
		err := NewHandlerError(ErrorCodeInternalError, "wrapper error", cause)

		assert.Equal(t, ErrorCodeInternalError, err.Code)
		assert.Equal(t, "wrapper error", err.Message)
		assert.Equal(t, cause, err.Cause)
		assert.Contains(t, err.Error(), "wrapper error")
		assert.Contains(t, err.Error(), cause.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("error with context", func(t *testing.T) {
		err := NewHandlerError(ErrorCodeAuthenticationFailed, "auth failed", nil)
		err.WithContext("username", "testuser")
		err.WithContext("client_ip", "192.168.1.100")

		assert.Equal(t, "testuser", err.Context["username"])
		assert.Equal(t, "192.168.1.100", err.Context["client_ip"])
	})
}

func TestHandlerErrorCode(t *testing.T) {
	testCases := []struct {
		code     HandlerErrorCode
		expected string
	}{
		{ErrorCodeInvalidRequest, "invalid_request"},
		{ErrorCodeAuthenticationFailed, "authentication_failed"},
		{ErrorCodeAuthorizationFailed, "authorization_failed"},
		{ErrorCodeInvalidClient, "invalid_client"},
		{ErrorCodeInvalidSharedSecret, "invalid_shared_secret"},
		{ErrorCodeInternalError, "internal_error"},
		{ErrorCodeTimeout, "timeout"},
		{ErrorCodeRateLimited, "rate_limited"},
		{ErrorCodeUnsupportedRequest, "unsupported_request"},
		{ErrorCodeUnknown, "unknown"},
		{HandlerErrorCode(999), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.code.String())
		})
	}
}

func TestEnhancedHandlerInterface(t *testing.T) {
	t.Run("interface compliance", func(t *testing.T) {
		logger := log.NewDefaultLogger()
		config := DefaultHandlerConfig()
		handler := NewEnhancedDefaultHandler(logger, config)

		// Verify that it implements all required interfaces
		var _ Handler = handler
		var _ EnhancedHandler = handler

		// Test basic methods exist
		assert.NotNil(t, handler.Initialize)
		assert.NotNil(t, handler.Shutdown)
		assert.NotNil(t, handler.GetClientContext)
		assert.NotNil(t, handler.HandleRequestWithContext)
		assert.NotNil(t, handler.PreProcessRequest)
		assert.NotNil(t, handler.PostProcessResponse)
	})
}

// Helper function for tests
func uint32Ptr(v uint32) *uint32 {
	return &v
}
