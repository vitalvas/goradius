// Package goradius implements RADIUS server and client functionality
// as defined in RFC 2865, RFC 2866, RFC 2868, and RFC 2869.
//
// It provides packet encoding and decoding with attribute type safety,
// a built-in dictionary covering standard RFC attributes and vendor-specific
// attributes (Juniper, ERX, Ascend, Mikrotik, WISPr), password encryption
// (User-Password, Tunnel-Password, Ascend-Secret), Message-Authenticator
// (HMAC-MD5), middleware support, per-client secret management with rotation,
// Dynamic Authorization (CoA/Disconnect, RFC 3576), and transport support for
// UDP, TCP, and TLS (RadSec).
package goradius
