package packet

import "fmt"

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
	// CoA-Request packets (RFC 3576)
	CodeCoARequest Code = 43
	// CoA-ACK packets (RFC 3576)
	CodeCoAAck Code = 44
	// CoA-NAK packets (RFC 3576)
	CodeCoANak Code = 45
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
	case CodeCoAAck:
		return "CoA-ACK"
	case CodeCoANak:
		return "CoA-NAK"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// IsValid checks if the packet code is valid
func (c Code) IsValid() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse,
		CodeAccessChallenge, CodeStatusServer, CodeStatusClient,
		CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAAck, CodeCoANak:
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

// IsResponse returns true if the code represents a response packet
func (c Code) IsResponse() bool {
	switch c {
	case CodeAccessAccept, CodeAccessReject, CodeAccessChallenge,
		CodeAccountingResponse, CodeStatusClient,
		CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoAAck, CodeCoANak:
		return true
	default:
		return false
	}
}

// IsAccounting returns true if the code is related to accounting
func (c Code) IsAccounting() bool {
	switch c {
	case CodeAccountingRequest, CodeAccountingResponse:
		return true
	default:
		return false
	}
}

// IsAuthentication returns true if the code is related to authentication
func (c Code) IsAuthentication() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject, CodeAccessChallenge:
		return true
	default:
		return false
	}
}

// IsCoA returns true if the code is related to Change of Authorization
func (c Code) IsCoA() bool {
	switch c {
	case CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAAck, CodeCoANak:
		return true
	default:
		return false
	}
}

// ExpectedResponseCode returns the expected response code for a request
func (c Code) ExpectedResponseCode() []Code {
	switch c {
	case CodeAccessRequest:
		return []Code{CodeAccessAccept, CodeAccessReject, CodeAccessChallenge}
	case CodeAccountingRequest:
		return []Code{CodeAccountingResponse}
	case CodeStatusServer:
		return []Code{CodeStatusClient}
	case CodeDisconnectRequest:
		return []Code{CodeDisconnectACK, CodeDisconnectNAK}
	case CodeCoARequest:
		return []Code{CodeCoAAck, CodeCoANak}
	default:
		return nil
	}
}
