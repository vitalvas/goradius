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

func TestDefaultHandlerConfig(t *testing.T) {
	t.Parallel()
	config := DefaultHandlerConfig()

	assert.Equal(t, 30*time.Second, config.RequestTimeout)
	assert.False(t, config.EnableRateLimit)
	assert.Equal(t, 1000, config.RequestsPerSecond)
	assert.Equal(t, 100, config.BurstSize)
	assert.True(t, config.EnableContextCache)
	assert.Equal(t, 5*time.Minute, config.ContextCacheTTL)
	assert.True(t, config.ValidateMessageAuth)
	assert.False(t, config.RequireMessageAuth)
	assert.True(t, config.LogRequests)
	assert.False(t, config.LogResponses)
	assert.True(t, config.LogSlowRequests)
	assert.Equal(t, 100*time.Millisecond, config.SlowRequestThreshold)
}

func TestNewEnhancedDefaultHandler(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		logger := log.NewDefaultLogger()
		handler := NewEnhancedDefaultHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.DefaultHandler)
		assert.NotNil(t, handler.config)
		assert.Empty(t, handler.middlewares)
		assert.NotNil(t, handler.clientContextCache)
		assert.False(t, handler.initialized)
		assert.False(t, handler.shutdown)
	})

	t.Run("with custom config", func(t *testing.T) {
		logger := log.NewDefaultLogger()
		config := &HandlerConfig{
			RequestTimeout:     60 * time.Second,
			EnableRateLimit:    true,
			RequestsPerSecond:  500,
			EnableContextCache: false,
		}
		handler := NewEnhancedDefaultHandler(logger, config)

		assert.NotNil(t, handler)
		assert.Equal(t, config, handler.config)
		assert.Equal(t, 60*time.Second, handler.config.RequestTimeout)
		assert.True(t, handler.config.EnableRateLimit)
		assert.Equal(t, 500, handler.config.RequestsPerSecond)
		assert.False(t, handler.config.EnableContextCache)
	})

	t.Run("with nil logger", func(t *testing.T) {
		handler := NewEnhancedDefaultHandler(nil, nil)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.DefaultHandler)
		assert.NotNil(t, handler.logger)
	})
}

func TestEnhancedHandlerLifecycle(t *testing.T) {
	logger := log.NewDefaultLogger()
	handler := NewEnhancedDefaultHandler(logger, nil)

	t.Run("initialize", func(t *testing.T) {
		ctx := context.Background()
		err := handler.Initialize(ctx)
		require.NoError(t, err)
		assert.True(t, handler.initialized)

		// Test double initialization
		err = handler.Initialize(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already initialized")
	})

	t.Run("shutdown", func(t *testing.T) {
		ctx := context.Background()
		err := handler.Shutdown(ctx)
		require.NoError(t, err)
		assert.True(t, handler.shutdown)

		// Test double shutdown
		err = handler.Shutdown(ctx)
		assert.NoError(t, err) // Should not error
	})
}

func TestEnhancedHandlerMiddleware(t *testing.T) {
	logger := log.NewDefaultLogger()
	handler := NewEnhancedDefaultHandler(logger, nil)

	// Add test middleware
	middleware1Called := false
	middleware1 := func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		middleware1Called = true
		return next(ctx, clientCtx, req)
	}

	middleware2Called := false
	middleware2 := func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		middleware2Called = true
		return next(ctx, clientCtx, req)
	}

	handler.AddMiddleware(middleware1)
	handler.AddMiddleware(middleware2)

	assert.Len(t, handler.middlewares, 2)
	assert.False(t, middleware1Called)
	assert.False(t, middleware2Called)
}

func TestGetClientContext(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultHandlerConfig()
	config.EnableContextCache = false // Disable cache for simpler testing
	handler := NewEnhancedDefaultHandler(logger, config)

	// Add a client configuration
	clientConfig := &ClientConfig{
		Networks: []string{"192.168.1.0/24"},
		Secret:   "test-secret",
		Name:     "test-client",
	}
	handler.AddClient(clientConfig)

	t.Run("valid client", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812}

		clientCtx, err := handler.GetClientContext(clientAddr, serverAddr, TransportUDP)
		require.NoError(t, err)
		require.NotNil(t, clientCtx)

		assert.Equal(t, clientAddr, clientCtx.Addr)
		assert.Equal(t, clientConfig, clientCtx.Config)
		assert.Equal(t, TransportUDP, clientCtx.Transport)
		assert.Equal(t, serverAddr, clientCtx.LocalAddr)
		assert.Equal(t, clientAddr, clientCtx.RemoteAddr)
		assert.Equal(t, []byte("test-secret"), clientCtx.SharedSecret)
		assert.NotNil(t, clientCtx.Attributes)
		assert.Greater(t, clientCtx.RequestID, uint64(0))
	})

	t.Run("invalid client", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("172.16.1.1"), Port: 12345}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812}

		clientCtx, err := handler.GetClientContext(clientAddr, serverAddr, TransportUDP)
		assert.Error(t, err)
		assert.Nil(t, clientCtx)
		assert.Contains(t, err.Error(), "no client configuration found")
	})

	t.Run("unsupported address type", func(t *testing.T) {
		clientAddr := &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812}

		clientCtx, err := handler.GetClientContext(clientAddr, serverAddr, TransportUDP)
		assert.Error(t, err)
		assert.Nil(t, clientCtx)
		assert.Contains(t, err.Error(), "unsupported address type")
	})
}

func TestGetClientContextWithCache(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultHandlerConfig()
	config.EnableContextCache = true
	config.ContextCacheTTL = 5 * time.Millisecond
	handler := NewEnhancedDefaultHandler(logger, config)

	// Add a client configuration
	clientConfig := &ClientConfig{
		Networks: []string{"192.168.1.0/24"},
		Secret:   "test-secret",
		Name:     "test-client",
	}
	handler.AddClient(clientConfig)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812}

	// First call should create and cache
	clientCtx1, err := handler.GetClientContext(clientAddr, serverAddr, TransportUDP)
	require.NoError(t, err)
	require.NotNil(t, clientCtx1)

	// Second call should return cached version
	clientCtx2, err := handler.GetClientContext(clientAddr, serverAddr, TransportUDP)
	require.NoError(t, err)
	require.NotNil(t, clientCtx2)

	// Should be the same object (from cache)
	assert.Equal(t, clientCtx1.RequestID, clientCtx2.RequestID)

	// Wait for cache to expire
	time.Sleep(10 * time.Millisecond)

	// Third call should create new context
	clientCtx3, err := handler.GetClientContext(clientAddr, serverAddr, TransportUDP)
	require.NoError(t, err)
	require.NotNil(t, clientCtx3)

	// Should be different object (cache expired)
	assert.NotEqual(t, clientCtx1.RequestID, clientCtx3.RequestID)
}

func TestHandleRequestWithContext(t *testing.T) {
	logger := log.NewDefaultLogger()
	handler := NewEnhancedDefaultHandler(logger, nil)

	// Initialize handler
	ctx := context.Background()
	err := handler.Initialize(ctx)
	require.NoError(t, err)

	// Create client context
	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	clientConfig := &ClientConfig{
		Networks: []string{"192.168.1.0/24"},
		Secret:   "test-secret",
		Name:     "test-client",
	}

	clientCtx := &ClientContext{
		Addr:         clientAddr,
		Config:       clientConfig,
		Transport:    TransportUDP,
		LocalAddr:    &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812},
		RemoteAddr:   clientAddr,
		ReceivedAt:   time.Now(),
		RequestID:    123,
		SharedSecret: []byte("test-secret"),
		Attributes:   make(map[string]interface{}),
	}

	t.Run("access request without username", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Length:     packet.PacketHeaderLength,
			Attributes: []packet.Attribute{},
		}

		result, err := handler.HandleRequestWithContext(ctx, clientCtx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.Response)

		assert.Equal(t, packet.CodeAccessReject, result.Response.Code)
		assert.True(t, result.Send)
		assert.Greater(t, result.ProcessingTime, time.Duration(0))
		assert.Equal(t, "enhanced_default", result.HandlerName)
	})

	t.Run("access request with username", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 2,
			Length:     packet.PacketHeaderLength,
			Attributes: []packet.Attribute{
				packet.NewStringAttribute(packet.AttrUserName, "testuser"),
			},
		}

		result, err := handler.HandleRequestWithContext(ctx, clientCtx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.Response)

		assert.Equal(t, packet.CodeAccessAccept, result.Response.Code)
		assert.True(t, result.Send)
		assert.Equal(t, "testuser", clientCtx.UserName)
	})

	t.Run("handler not initialized", func(t *testing.T) {
		uninitializedHandler := NewEnhancedDefaultHandler(logger, nil)
		req := &packet.Packet{Code: packet.CodeAccessRequest}

		result, err := uninitializedHandler.HandleRequestWithContext(ctx, clientCtx, req)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "not initialized")
	})

	t.Run("handler shutdown", func(t *testing.T) {
		shutdownHandler := NewEnhancedDefaultHandler(logger, nil)
		err := shutdownHandler.Initialize(ctx)
		require.NoError(t, err)
		err = shutdownHandler.Shutdown(ctx)
		require.NoError(t, err)

		req := &packet.Packet{Code: packet.CodeAccessRequest}

		result, err := shutdownHandler.HandleRequestWithContext(ctx, clientCtx, req)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "shutdown")
	})
}

func TestExtractNASInfo(t *testing.T) {
	handler := NewEnhancedDefaultHandler(nil, nil)

	t.Run("complete NAS info", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Attributes: []packet.Attribute{
				packet.NewStringAttribute(packet.AttrNASIdentifier, "nas-01"),
				packet.NewIPAddressAttribute(packet.AttrNASIPAddress, [4]byte{10, 0, 0, 1}),
				packet.NewIntegerAttribute(packet.AttrNASPort, 1812),
				packet.NewIntegerAttribute(packet.AttrNASPortType, 5),
			},
		}

		nasInfo := handler.extractNASInfo(req)
		require.NotNil(t, nasInfo)

		assert.Equal(t, "nas-01", nasInfo.Identifier)
		assert.True(t, net.ParseIP("10.0.0.1").Equal(nasInfo.IPAddress))
		assert.Equal(t, uint32(1812), *nasInfo.Port)
		assert.Equal(t, uint32(5), *nasInfo.PortType)
	})

	t.Run("empty NAS info", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Attributes: []packet.Attribute{},
		}

		nasInfo := handler.extractNASInfo(req)
		require.NotNil(t, nasInfo)

		assert.Empty(t, nasInfo.Identifier)
		assert.Nil(t, nasInfo.IPAddress)
		assert.Nil(t, nasInfo.Port)
		assert.Nil(t, nasInfo.PortType)
	})
}

func TestHandlerRequestCompatibility(t *testing.T) {
	// Test that the enhanced handler still works with the original Handler interface
	logger := log.NewDefaultLogger()
	handler := NewEnhancedDefaultHandler(logger, nil)

	// Add client configuration
	clientConfig := &ClientConfig{
		Networks: []string{"192.168.1.0/24"},
		Secret:   "test-secret",
		Name:     "test-client",
	}
	handler.AddClient(clientConfig)

	// Initialize handler
	ctx := context.Background()
	err := handler.Initialize(ctx)
	require.NoError(t, err)

	// Create legacy request
	req := &Request{
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
		ServerAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812},
		Packet: &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Attributes: []packet.Attribute{
				packet.NewStringAttribute(packet.AttrUserName, "testuser"),
			},
		},
		Client:     clientConfig,
		ReceivedAt: time.Now(),
	}

	// Test legacy HandleRequest method
	response, err := handler.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Equal(t, packet.CodeAccessAccept, response.Packet.Code)
	assert.True(t, response.Send)
}

func TestPrePostProcessing(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultHandlerConfig()
	config.ValidateMessageAuth = false // Disable for simpler testing
	handler := NewEnhancedDefaultHandler(logger, config)

	clientCtx := &ClientContext{
		Addr:         &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
		SharedSecret: []byte("test-secret"),
		RequestID:    123,
	}

	t.Run("pre-process request", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Length:     packet.PacketHeaderLength,
			Attributes: []packet.Attribute{},
		}

		err := handler.PreProcessRequest(context.Background(), clientCtx, req)
		assert.NoError(t, err)
	})

	t.Run("post-process response", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Attributes: []packet.Attribute{},
		}

		result := &HandlerResult{
			Response: &packet.Packet{
				Code:       packet.CodeAccessAccept,
				Identifier: 1,
				Attributes: []packet.Attribute{},
			},
			Send: true,
		}

		err := handler.PostProcessResponse(context.Background(), clientCtx, req, result)
		assert.NoError(t, err)
	})

	t.Run("post-process with EAP", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Attributes: []packet.Attribute{
				packet.NewAttribute(packet.AttrEAPMessage, []byte{1, 2, 3, 4}),
			},
		}

		result := &HandlerResult{
			Response: &packet.Packet{
				Code:       packet.CodeAccessChallenge,
				Identifier: 1,
				Attributes: []packet.Attribute{},
			},
			Send: true,
		}

		err := handler.PostProcessResponse(context.Background(), clientCtx, req, result)
		assert.NoError(t, err)

		// Should have added Message-Authenticator
		_, found := result.Response.GetAttribute(packet.AttrMessageAuthenticator)
		assert.True(t, found)
	})
}
