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

// WithRequireMessageAuthenticator sets whether a Message-Authenticator must be
// present in Access-Request packets (BlastRADIUS hardening). The requirement
// covers only the Access exchange: Accounting, CoA, and Disconnect requests
// carry the attribute optionally per RFC 2866/5176, so devices that do not
// support it keep working, and Status-Server always requires it per RFC 5997.
// Regardless of this setting, a Message-Authenticator that IS present is
// always verified and the packet dropped on mismatch (RFC 3579 Section 3.2).
func WithRequireMessageAuthenticator(b bool) ServerOption {
	return func(s *Server) {
		s.requireMessageAuth = b
	}
}

// WithUseMessageAuthenticator sets whether to add Message-Authenticator to responses.
func WithUseMessageAuthenticator(b bool) ServerOption {
	return func(s *Server) {
		s.useMessageAuth = b
	}
}

// WithRequireRequestAuthenticator sets whether to validate Request Authenticator
// for non-Access-Request packets (RFC 2866, RFC 5176).
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
