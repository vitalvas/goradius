package packet

// Code represents a RADIUS packet code as defined in RFC 2865
type Code uint8

// RADIUS packet codes as defined in RFC 2865 and related RFCs
const (
	// Access-Request packets (RFC 2865)
	CodeAccessRequest Code = 1
	// Access-Accept packets (RFC 2865)
	CodeAccessAccept Code = 2
	// Access-Reject packets (RFC 2865)
	CodeAccessReject Code = 3
	// Accounting-Request packets (RFC 2866)
	CodeAccountingRequest Code = 4
	// Accounting-Response packets (RFC 2866)
	CodeAccountingResponse Code = 5
	// Access-Challenge packets (RFC 2865)
	CodeAccessChallenge Code = 11
	// Status-Server packets (RFC 2865)
	CodeStatusServer Code = 12
	// Status-Client packets (RFC 2865)
	CodeStatusClient Code = 13
	// Disconnect-Request packets (RFC 3576 - CoA)
	CodeDisconnectRequest Code = 40
	// Disconnect-ACK packets (RFC 3576 - CoA)
	CodeDisconnectACK Code = 41
	// Disconnect-NAK packets (RFC 3576 - CoA)
	CodeDisconnectNAK Code = 42
	// Change-of-Authorization-Request packets (RFC 3576 - CoA)
	CodeCoARequest Code = 43
	// Change-of-Authorization-ACK packets (RFC 3576 - CoA)
	CodeCoAACK Code = 44
	// Change-of-Authorization-NAK packets (RFC 3576 - CoA)
	CodeCoANAK Code = 45
)

// String returns the string representation of the packet code
func (c Code) String() string {
	switch c {
	case CodeAccessRequest:
		return "Access-Request"
	case CodeAccessAccept:
		return "Access-Accept"
	case CodeAccessReject:
		return "Access-Reject"
	case CodeAccountingRequest:
		return "Accounting-Request"
	case CodeAccountingResponse:
		return "Accounting-Response"
	case CodeAccessChallenge:
		return "Access-Challenge"
	case CodeStatusServer:
		return "Status-Server"
	case CodeStatusClient:
		return "Status-Client"
	case CodeDisconnectRequest:
		return "Disconnect-Request"
	case CodeDisconnectACK:
		return "Disconnect-ACK"
	case CodeDisconnectNAK:
		return "Disconnect-NAK"
	case CodeCoARequest:
		return "CoA-Request"
	case CodeCoAACK:
		return "CoA-ACK"
	case CodeCoANAK:
		return "CoA-NAK"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the code is a valid RADIUS packet code
func (c Code) IsValid() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse, CodeAccessChallenge,
		CodeStatusServer, CodeStatusClient,
		CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAACK, CodeCoANAK:
		return true
	default:
		return false
	}
}