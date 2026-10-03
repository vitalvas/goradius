// Package goradius implements RADIUS server and client functionality
// as defined in RFC 2865, RFC 2866, RFC 2868, RFC 2869, RFC 3162,
// RFC 5176, RFC 6613, RFC 6614, and RFC 6929.
//
// It provides packet encoding and decoding with attribute type safety,
// a built-in dictionary covering standard RFC attributes and vendor-specific
// attributes (Juniper, ERX, Ascend, Mikrotik, WISPr, Cisco), IPv6 attribute
// types (RFC 3162), complex attribute types (TLV, struct, and RFC 6929
// extended, long-extended, and vendor-specific EVS attributes), password
// encryption (User-Password, Tunnel-Password, Ascend-Secret),
// Message-Authenticator (HMAC-MD5), middleware support, per-client secret
// management with rotation, Dynamic Authorization (CoA/Disconnect, RFC 5176),
// and transport support for UDP, TCP (RFC 6613), and TLS/RadSec (RFC 6614).
package goradius
