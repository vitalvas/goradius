package packet

const (
	// PacketHeaderLength is the length of the RADIUS packet header in bytes
	PacketHeaderLength = 20
	// MaxPacketLength is the maximum allowed RADIUS packet length
	MaxPacketLength = 4096
	// MinPacketLength is the minimum allowed RADIUS packet length
	MinPacketLength = PacketHeaderLength
	// AuthenticatorLength is the length of the authenticator field
	AuthenticatorLength = 16
	// AttributeHeaderLength is the length of attribute header (Type + Length)
	AttributeHeaderLength = 2
	// VendorSpecificHeaderLength is the length of VSA header (Type + Length + Vendor-Id)
	VendorSpecificHeaderLength = 6
)

const (
	// AttributeTypeVendorSpecific is the type for Vendor-Specific Attributes (RFC 2865)
	AttributeTypeVendorSpecific = 26
	// AttributeTypeMessageAuthenticator is the type for Message-Authenticator (RFC 2869)
	AttributeTypeMessageAuthenticator = 80
)
