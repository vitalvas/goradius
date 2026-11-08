package goradius

import "time"

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithHandler sets the request handler for the server.
func WithHandler(h Handler) ServerOption {
	return func(s *Server) {
		s.handler = h
	}
}

// WithDictionary sets the RADIUS dictionary for the server.
func WithDictionary(d *Dictionary) ServerOption {
	return func(s *Server) {
		s.dict = d
	}
}

// WithMessageAuthPolicy sets the server-wide Message-Authenticator policy.
// The default is MessageAuthPolicyAuto; MessageAuthPolicyDefault keeps it.
// Replies carry a Message-Authenticator under every policy except
// MessageAuthPolicyDisabled.
func WithMessageAuthPolicy(policy MessageAuthPolicy) ServerOption {
	return func(s *Server) {
		if policy != MessageAuthPolicyDefault {
			s.messageAuthPolicy = policy
		}
	}
}

// WithRequireRequestAuthenticator sets whether the computed Request
// Authenticator of Accounting-Request, CoA-Request, and Disconnect-Request
// packets is validated (RFC 2866 Section 3, RFC 5176 Section 3.3, RFC 5080
// Section 2.3.3). Default is true; disable only for devices that compute it
// incorrectly. Access-Request and Status-Server carry a random authenticator
// and are never subject to this check.
func WithRequireRequestAuthenticator(b bool) ServerOption {
	return func(s *Server) {
		s.requireRequestAuth = b
	}
}

// WithRequestTimeout sets the timeout for request processing.
func WithRequestTimeout(d time.Duration) ServerOption {
	return func(s *Server) {
		s.requestTimeout = d
	}
}
