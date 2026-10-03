package goradius

// AttributeUsage is a bitmask of the packet types an attribute may appear in,
// following the "Table of Attributes" sections of the defining RFCs. The zero
// value means unrestricted: the attribute is allowed in any packet type.
// The width leaves room for future packet kinds such as Status-Server
// (RFC 5997) and Protocol-Error (RFC 7930).
type AttributeUsage uint32

const (
	// UsageAccessRequest allows the attribute in Access-Request packets
	UsageAccessRequest AttributeUsage = 1 << iota
	// UsageAccessAccept allows the attribute in Access-Accept packets
	UsageAccessAccept
	// UsageAccessReject allows the attribute in Access-Reject packets
	UsageAccessReject
	// UsageAccessChallenge allows the attribute in Access-Challenge packets
	UsageAccessChallenge
	// UsageAccountingRequest allows the attribute in Accounting-Request packets
	UsageAccountingRequest
	// UsageAccountingResponse allows the attribute in Accounting-Response packets
	UsageAccountingResponse
	// UsageCoARequest allows the attribute in CoA-Request packets
	UsageCoARequest
	// UsageCoAACK allows the attribute in CoA-ACK packets
	UsageCoAACK
	// UsageCoANAK allows the attribute in CoA-NAK packets
	UsageCoANAK
	// UsageDisconnectRequest allows the attribute in Disconnect-Request packets
	UsageDisconnectRequest
	// UsageDisconnectACK allows the attribute in Disconnect-ACK packets
	UsageDisconnectACK
	// UsageDisconnectNAK allows the attribute in Disconnect-NAK packets
	UsageDisconnectNAK
)

const (
	// UsageAccessAll allows the attribute in every Access packet type
	UsageAccessAll = UsageAccessRequest | UsageAccessAccept | UsageAccessReject | UsageAccessChallenge
	// UsageAccountingAll allows the attribute in both Accounting packet types
	UsageAccountingAll = UsageAccountingRequest | UsageAccountingResponse
	// UsageCoAAll allows the attribute in every CoA packet type
	UsageCoAAll = UsageCoARequest | UsageCoAACK | UsageCoANAK
	// UsageDisconnectAll allows the attribute in every Disconnect packet type
	UsageDisconnectAll = UsageDisconnectRequest | UsageDisconnectACK | UsageDisconnectNAK
	// UsageAllRequests allows the attribute in every request packet type
	UsageAllRequests = UsageAccessRequest | UsageAccountingRequest | UsageCoARequest | UsageDisconnectRequest
	// UsageAllResponses allows the attribute in every response packet type
	UsageAllResponses = UsageAccessAccept | UsageAccessReject | UsageAccessChallenge |
		UsageAccountingResponse | UsageCoAACK | UsageCoANAK | UsageDisconnectACK | UsageDisconnectNAK
	// UsageAll allows the attribute in every supported packet type
	UsageAll = UsageAllRequests | UsageAllResponses
)

// UsageForCode returns the usage bit matching a packet code, or 0 for codes
// without a dedicated bit (such as Status-Server).
func UsageForCode(code Code) AttributeUsage {
	switch code {
	case CodeAccessRequest:
		return UsageAccessRequest
	case CodeAccessAccept:
		return UsageAccessAccept
	case CodeAccessReject:
		return UsageAccessReject
	case CodeAccessChallenge:
		return UsageAccessChallenge
	case CodeAccountingRequest:
		return UsageAccountingRequest
	case CodeAccountingResponse:
		return UsageAccountingResponse
	case CodeCoARequest:
		return UsageCoARequest
	case CodeCoAACK:
		return UsageCoAACK
	case CodeCoANAK:
		return UsageCoANAK
	case CodeDisconnectRequest:
		return UsageDisconnectRequest
	case CodeDisconnectACK:
		return UsageDisconnectACK
	case CodeDisconnectNAK:
		return UsageDisconnectNAK
	}
	return 0
}

// AllowedIn reports whether the attribute may appear in packets of the given
// code. A zero Usage mask means unrestricted, and codes without a usage bit
// (such as Status-Server) are never restricted.
func (a *AttributeDefinition) AllowedIn(code Code) bool {
	if a.Usage == 0 {
		return true
	}

	bit := UsageForCode(code)
	if bit == 0 {
		return true
	}

	return a.Usage&bit != 0
}
