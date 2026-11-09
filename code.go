package goradius

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

var CodeByName = map[string]Code{
	"access-request":      CodeAccessRequest,
	"access-accept":       CodeAccessAccept,
	"access-reject":       CodeAccessReject,
	"accounting-request":  CodeAccountingRequest,
	"accounting-response": CodeAccountingResponse,
	"access-challenge":    CodeAccessChallenge,
	"status-server":       CodeStatusServer,
	"status-client":       CodeStatusClient,
	"disconnect-request":  CodeDisconnectRequest,
	"disconnect-ack":      CodeDisconnectACK,
	"disconnect-nak":      CodeDisconnectNAK,
	"coa-request":         CodeCoARequest,
	"coa-ack":             CodeCoAACK,
	"coa-nak":             CodeCoANAK,
}

// String returns the lowercase packet code name, matching the lowercase
// convention of dictionary attribute and value names
func (c Code) String() string {
	switch c {
	case CodeAccessRequest:
		return "access-request"
	case CodeAccessAccept:
		return "access-accept"
	case CodeAccessReject:
		return "access-reject"
	case CodeAccountingRequest:
		return "accounting-request"
	case CodeAccountingResponse:
		return "accounting-response"
	case CodeAccessChallenge:
		return "access-challenge"
	case CodeStatusServer:
		return "status-server"
	case CodeStatusClient:
		return "status-client"
	case CodeDisconnectRequest:
		return "disconnect-request"
	case CodeDisconnectACK:
		return "disconnect-ack"
	case CodeDisconnectNAK:
		return "disconnect-nak"
	case CodeCoARequest:
		return "coa-request"
	case CodeCoAACK:
		return "coa-ack"
	case CodeCoANAK:
		return "coa-nak"
	default:
		return "unknown"
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

// IsRequest returns true if the code represents a request packet
func (c Code) IsRequest() bool {
	switch c {
	case CodeAccessRequest, CodeAccountingRequest, CodeStatusServer,
		CodeDisconnectRequest, CodeCoARequest:
		return true
	default:
		return false
	}
}

// IsReply returns true if the code represents a reply packet
func (c Code) IsReply() bool {
	switch c {
	case CodeAccessAccept, CodeAccessReject, CodeAccessChallenge,
		CodeAccountingResponse, CodeStatusClient,
		CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoAACK, CodeCoANAK:
		return true
	default:
		return false
	}
}
