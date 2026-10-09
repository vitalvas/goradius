package goradius

import (
	"context"
	"net"
	"sync"
	"time"
)

// Server is a RADIUS server supporting UDP, TCP, and TLS transports
type Server struct {
	transports         []Transport
	handler            Handler
	dict               *Dictionary
	middlewares        []Middleware
	mu                 sync.RWMutex
	ready              chan struct{}
	readyClosed        bool
	requireMessageAuth bool
	useMessageAuth     bool
	requireRequestAuth bool
	requestTimeout     time.Duration // 0 means no timeout
}

func NewServer(opts ...ServerOption) (*Server, error) {
	s := &Server{
		ready:              make(chan struct{}),
		requireMessageAuth: true,
		useMessageAuth:     true,
		// RFC 5080 Section 2.3.3: servers MUST validate the computed Request
		// Authenticator of Accounting/CoA/Disconnect requests and silently
		// discard invalid packets. Every compliant device computes it from
		// the shared secret, so this is on by default.
		requireRequestAuth: true,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.dict == nil {
		var err error
		s.dict, err = NewDefault()
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Serve starts the server using the provided transport.
// Supports UDP, TCP, and TLS transports. Serve may be called once per
// transport to listen on several sockets with one server.
func (s *Server) Serve(transport Transport) error {
	s.mu.Lock()
	s.transports = append(s.transports, transport)
	// Guard against closing twice when Serve is called for multiple transports
	if !s.readyClosed {
		close(s.ready)
		s.readyClosed = true
	}
	s.mu.Unlock()

	// Bind this transport's address so each packet reports the local address
	// it actually arrived on, which keys per-listener secret lookup.
	localAddr := transport.LocalAddr()
	return transport.Serve(func(data []byte, remoteAddr net.Addr, respond ResponderFunc) {
		s.handlePacketFrom(localAddr, data, remoteAddr, respond)
	})
}

// Addr returns the local address the server is listening on. When Serve has
// been called for multiple transports, the first transport's address is
// returned. Blocks until the server is ready.
func (s *Server) Addr() net.Addr {
	<-s.ready
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.transports) == 0 {
		return nil
	}
	return s.transports[0].LocalAddr()
}

// ProcessRawPacket processes a single RADIUS packet from raw bytes and the
// source address, without owning a transport. It reuses the same pipeline as
// Serve: secret lookup, secret rotation, packet validation, and ServeRADIUS
// dispatch. remoteAddr is used as the client identity for secret lookup.
//
// It returns the raw reply bytes to send back to remoteAddr, or nil when the
// handler chooses not to respond (or the packet is dropped by validation).
// This works even when Serve has never been called and no transport is bound.
//
// The pipeline only reads data and never mutates it, but data is not copied.
// The caller must not modify data concurrently with this call. The returned
// reply is a freshly-allocated slice that does not alias data.
func (s *Server) ProcessRawPacket(data []byte, remoteAddr net.Addr) ([]byte, error) {
	var reply []byte
	respond := func(respData []byte) error {
		reply = respData
		return nil
	}

	s.handlePacket(data, remoteAddr, respond)

	return reply, nil
}

// Close stops the server and waits for in-flight requests to complete.
// Every transport passed to Serve is closed.
func (s *Server) Close() error {
	s.mu.Lock()
	transports := s.transports
	s.mu.Unlock()

	var firstErr error
	for _, transport := range transports {
		if err := transport.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// Use adds middleware to the server
// Middlewares are applied in the order they are added
func (s *Server) Use(middleware Middleware) {
	s.mu.Lock()
	s.middlewares = append(s.middlewares, middleware)
	s.mu.Unlock()
}

// buildHandler wraps the handler with all middlewares
func (s *Server) buildHandler() Handler {
	s.mu.RLock()
	middlewares := s.middlewares
	s.mu.RUnlock()

	handler := s.handler

	// Apply middlewares in reverse order (last added is outermost)
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	return handler
}

// handlePacket processes a single RADIUS packet using the first transport's
// local address (or none when no transport is bound).
func (s *Server) handlePacket(data []byte, remoteAddr net.Addr, respond ResponderFunc) {
	s.mu.RLock()
	var localAddr net.Addr
	if len(s.transports) > 0 {
		localAddr = s.transports[0].LocalAddr()
	}
	s.mu.RUnlock()

	s.handlePacketFrom(localAddr, data, remoteAddr, respond)
}

// handlePacketFrom processes a single RADIUS packet received on the transport
// bound to localAddr. Called by the transport for each received packet.
func (s *Server) handlePacketFrom(localAddr net.Addr, data []byte, remoteAddr net.Addr, respond ResponderFunc) {
	pkt, err := Decode(data)
	if err != nil {
		return
	}

	// RFC 2865 Section 3: packets with an invalid Code field are silently
	// discarded; only request codes are dispatched to the handler.
	if !pkt.Code.IsRequest() {
		return
	}

	// Set dictionary on decoded packet
	if s.dict != nil {
		pkt.Dict = s.dict
	}

	if s.handler == nil {
		return
	}

	// Create context with optional timeout
	var ctx context.Context
	var cancel context.CancelFunc
	if s.requestTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), s.requestTimeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	// Get secret (attempt 0)
	secretReq := SecretRequest{
		Context:    ctx,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Attempt:    0,
	}

	secretResp, err := s.handler.ServeSecret(secretReq)
	if err != nil {
		return
	}

	totalAttempts := max(secretResp.Attempts, 1)

	// Validate packet with secret rotation support
	if totalAttempts <= 1 {
		// Fast path: single secret
		if !s.validatePacketSecret(pkt, secretResp) {
			return
		}
	} else {
		// Rotation path: try multiple secrets
		secretResp = s.resolveSecret(resolveSecretParams{
			ctx:           ctx,
			localAddr:     localAddr,
			remoteAddr:    remoteAddr,
			pkt:           pkt,
			firstResp:     secretResp,
			totalAttempts: totalAttempts,
		})
		if secretResp.Secret == nil {
			return
		}
	}

	// Carry the resolved secret on the request packet so encrypted
	// attributes (for example User-Password) decrypt transparently when the
	// handler reads them.
	pkt.Secret = secretResp.Secret

	// Handle RADIUS request
	req := &Request{
		Context:    ctx,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		packet:     pkt,
		Secret:     secretResp,
	}

	// Build handler with middlewares
	handler := s.buildHandler()

	resp, err := handler.ServeRADIUS(req)
	if err != nil || resp.packet == nil {
		return
	}

	// RFC 2865 Section 5 / RFC 2868: reply attributes that are encrypted
	// (for example MPPE keys and Tunnel-Password) use the Request
	// Authenticator of the packet being answered. Binding it here keeps
	// encryption transparent even for handler-built response packets; the
	// attributes finalize automatically before the Message-Authenticator and
	// Response Authenticator are computed, which cover the encrypted bytes.
	resp.packet.Secret = secretResp.Secret
	resp.packet.bindRequestAuthenticator(pkt.Authenticator)

	if s.useMessageAuth {
		resp.packet.AddMessageAuthenticator(secretResp.Secret, pkt.Authenticator)
	}

	// Calculate response authenticator per RFC 2865 Section 3
	resp.packet.SetAuthenticator(resp.packet.CalculateResponseAuthenticator(secretResp.Secret, pkt.Authenticator))

	respData, err := resp.packet.Encode()
	if err != nil {
		return
	}

	// Send response via transport responder
	_ = respond(respData)
}

// validatePacketSecret validates the packet against the given secret
// using Message-Authenticator and/or Request Authenticator checks.
//
// Message-Authenticator handling follows RFC 3579 Section 3.2: when the
// attribute is present it is always verified, regardless of configuration;
// policy only governs whether its absence is fatal. The presence requirement
// covers Access-Request (BlastRADIUS hardening, overridable via
// WithRequireMessageAuthenticator and the per-secret policy) and is
// unconditional for Status-Server (RFC 5997 Section 4.2). Accounting, CoA,
// and Disconnect requests carry the attribute optionally (RFC 2866/5176), so
// devices that do not send it keep working; a per-secret
// MessageAuthPolicyRequired still enforces presence for every request type.
func (s *Server) validatePacketSecret(pkt *Packet, secretResp SecretResponse) bool {
	secret := secretResp.Secret

	// Access-Request and Status-Server carry a random authenticator (RFC
	// 2865 Section 3, RFC 5997 Section 3), so the computed-hash check only
	// applies to Accounting/CoA/Disconnect requests (RFC 2866 Section 3,
	// RFC 5176 Section 3.3).
	if s.requireRequestAuth && pkt.Code != CodeAccessRequest && pkt.Code != CodeStatusServer {
		expectedAuth := pkt.CalculateRequestAuthenticator(secret)
		if pkt.Authenticator != expectedAuth {
			return false
		}
	}

	requireMsgAuth := false
	switch pkt.Code {
	case CodeAccessRequest:
		requireMsgAuth = s.requireMessageAuth
		switch secretResp.MessageAuthPolicy {
		case MessageAuthPolicyRequired:
			requireMsgAuth = true
		case MessageAuthPolicyOptional:
			requireMsgAuth = false
		}
	case CodeStatusServer:
		// RFC 5997: all Status-Server packets MUST include Message-Authenticator
		requireMsgAuth = true
	default:
		if secretResp.MessageAuthPolicy == MessageAuthPolicyRequired {
			requireMsgAuth = true
		}
	}

	if requireMsgAuth || pkt.hasMessageAuthenticator() {
		if !pkt.VerifyMessageAuthenticator(secret, pkt.Authenticator) {
			return false
		}
	}

	return true
}

type resolveSecretParams struct {
	ctx           context.Context
	localAddr     net.Addr
	remoteAddr    net.Addr
	pkt           *Packet
	firstResp     SecretResponse
	totalAttempts int
}

// resolveSecret tries each secret in order until one validates the packet.
// Returns the SecretResponse with the resolved secret, or one with nil Secret
// if all attempts fail.
func (s *Server) resolveSecret(params resolveSecretParams) SecretResponse {
	// Try first secret (already fetched)
	if s.validatePacketSecret(params.pkt, params.firstResp) {
		return params.firstResp
	}

	// Try remaining secrets
	for i := 1; i < params.totalAttempts; i++ {
		resp, err := s.handler.ServeSecret(SecretRequest{
			Context:    params.ctx,
			LocalAddr:  params.localAddr,
			RemoteAddr: params.remoteAddr,
			Attempt:    i,
		})
		if err != nil {
			continue
		}

		if s.validatePacketSecret(params.pkt, resp) {
			return resp
		}
	}

	// All secrets failed
	return SecretResponse{}
}
