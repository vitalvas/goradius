package goradius

// RADIUS packet structure constants per RFC 2865 Section 3
const (
	// PacketHeaderLength is the length of the RADIUS packet header (Code + ID + Length + Authenticator)
	PacketHeaderLength = 20
	// MaxPacketLength is the maximum allowed RADIUS packet length per RFC 2865 Section 3
	MaxPacketLength = 4096
	// MinPacketLength is the minimum allowed RADIUS packet length (header only)
	MinPacketLength = PacketHeaderLength
	// AuthenticatorLength is the length of the authenticator field per RFC 2865 Section 3
	AuthenticatorLength = 16
	// AttributeHeaderLength is the length of attribute header (Type + Length) per RFC 2865 Section 5
	AttributeHeaderLength = 2
	// VendorSpecificHeaderLength is the length of VSA header (Type + Length + Vendor-Id) per RFC 2865 Section 5.26
	VendorSpecificHeaderLength = 6
	// MaxAttributeValueLength is the maximum value length for a standard attribute (255 - 2 for header)
	MaxAttributeValueLength = 253
	// MaxVSAValueLength is the maximum vendor data length for a VSA (255 - 2 - 4 - 2 for headers)
	MaxVSAValueLength = 247
	// MaxUserPasswordLength is the maximum User-Password length per RFC 2865 Section 5.2
	MaxUserPasswordLength = 128
	// MaxAttributeTag is the highest valid tag value for tagged attributes per RFC 2868 Section 3;
	// a first octet above this value is part of the attribute data, not a tag
	MaxAttributeTag = 0x1F
)

const (
	// AttributeTypeVendorSpecific is the type for Vendor-Specific Attributes (RFC 2865)
	AttributeTypeVendorSpecific = 26
	// AttributeTypeMessageAuthenticator is the type for Message-Authenticator (RFC 2869)
	AttributeTypeMessageAuthenticator = 80
)
