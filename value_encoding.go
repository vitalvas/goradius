package goradius

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// EncodeString encodes a string value for RADIUS attributes per RFC 2865 Section 5
func EncodeString(value string) []byte {
	return []byte(value)
}

// DecodeString decodes a string value from RADIUS attributes per RFC 2865 Section 5
func DecodeString(data []byte) string {
	return string(data)
}

// EncodeInteger encodes a 32-bit integer value for RADIUS attributes per RFC 2865 Section 5
func EncodeInteger(value uint32) []byte {
	data := make([]byte, 4)
	data[0] = byte(value >> 24)
	data[1] = byte(value >> 16)
	data[2] = byte(value >> 8)
	data[3] = byte(value)
	return data
}

// EncodeIntegerTo encodes a 32-bit integer into a pre-allocated buffer (must be at least 4 bytes)
func EncodeIntegerTo(dst []byte, value uint32) {
	dst[0] = byte(value >> 24)
	dst[1] = byte(value >> 16)
	dst[2] = byte(value >> 8)
	dst[3] = byte(value)
}

// DecodeInteger decodes a 32-bit integer value from RADIUS attributes per RFC 2865 Section 5
func DecodeInteger(data []byte) (uint32, error) {
	if len(data) != 4 {
		return 0, fmt.Errorf("invalid integer length: %d", len(data))
	}
	return binary.BigEndian.Uint32(data), nil
}

// EncodeIPAddr encodes an IPv4 address for RADIUS attributes per RFC 2865 Section 5
func EncodeIPAddr(ip net.IP) ([]byte, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("not an IPv4 address")
	}
	return []byte(ipv4), nil
}

// DecodeIPAddr decodes an IPv4 address from RADIUS attributes per RFC 2865 Section 5
func DecodeIPAddr(data []byte) (net.IP, error) {
	if len(data) != 4 {
		return nil, fmt.Errorf("invalid IP address length: %d", len(data))
	}
	return net.IP(data), nil
}

// EncodeIPv6Addr encodes an IPv6 address for RADIUS attributes per RFC 6929
func EncodeIPv6Addr(ip net.IP) ([]byte, error) {
	ipv6 := ip.To16()
	if ipv6 == nil {
		return nil, fmt.Errorf("not an IPv6 address")
	}
	return []byte(ipv6), nil
}

// DecodeIPv6Addr decodes an IPv6 address from RADIUS attributes per RFC 6929
func DecodeIPv6Addr(data []byte) (net.IP, error) {
	if len(data) != 16 {
		return nil, fmt.Errorf("invalid IPv6 address length: %d", len(data))
	}
	return net.IP(data), nil
}

// EncodeIPv6Prefix encodes an IPv6 prefix per RFC 3162 Section 2.3:
// Reserved(1, zero) + Prefix-Length(1) + Prefix (enough octets to hold the prefix bits).
func EncodeIPv6Prefix(prefix *net.IPNet) ([]byte, error) {
	if prefix == nil {
		return nil, fmt.Errorf("nil IPv6 prefix")
	}

	ones, bits := prefix.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("not an IPv6 prefix: mask is %d bits", bits)
	}

	ip := prefix.IP.To16()
	if ip == nil {
		return nil, fmt.Errorf("not an IPv6 prefix address")
	}

	octets := (ones + 7) / 8
	out := make([]byte, 2+octets)
	out[1] = byte(ones)
	copy(out[2:], ip[:octets])
	return out, nil
}

// DecodeIPv6Prefix decodes an IPv6 prefix per RFC 3162 Section 2.3.
// The prefix field may carry fewer than 16 octets; missing octets are zero.
func DecodeIPv6Prefix(data []byte) (*net.IPNet, error) {
	if len(data) < 2 || len(data) > 18 {
		return nil, fmt.Errorf("invalid IPv6 prefix length: %d", len(data))
	}

	prefixLen := int(data[1])
	if prefixLen > 128 {
		return nil, fmt.Errorf("invalid IPv6 prefix length value: %d", prefixLen)
	}

	if len(data)-2 < (prefixLen+7)/8 {
		return nil, fmt.Errorf("IPv6 prefix field too short for prefix length %d", prefixLen)
	}

	ip := make(net.IP, net.IPv6len)
	copy(ip, data[2:])

	// RFC 3162 Section 2.3: bits outside the Prefix-Length must be zero;
	// normalize so decoded prefixes are canonical
	mask := net.CIDRMask(prefixLen, 128)

	return &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}, nil
}

// EncodeIfID encodes an IPv6 interface identifier per RFC 3162 Section 2.2 (8 octets).
func EncodeIfID(ifid []byte) ([]byte, error) {
	if len(ifid) != 8 {
		return nil, fmt.Errorf("invalid interface identifier length: %d", len(ifid))
	}
	out := make([]byte, 8)
	copy(out, ifid)
	return out, nil
}

// DecodeIfID decodes an IPv6 interface identifier per RFC 3162 Section 2.2 (8 octets).
func DecodeIfID(data []byte) ([]byte, error) {
	if len(data) != 8 {
		return nil, fmt.Errorf("invalid interface identifier length: %d", len(data))
	}
	out := make([]byte, 8)
	copy(out, data)
	return out, nil
}

// EncodeDate encodes a Unix timestamp for RADIUS attributes per RFC 2865 Section 5
func EncodeDate(t time.Time) []byte {
	timestamp := uint32(t.Unix())
	data := make([]byte, 4)
	data[0] = byte(timestamp >> 24)
	data[1] = byte(timestamp >> 16)
	data[2] = byte(timestamp >> 8)
	data[3] = byte(timestamp)
	return data
}

// DecodeDate decodes a Unix timestamp from RADIUS attributes per RFC 2865 Section 5
func DecodeDate(data []byte) (time.Time, error) {
	timestamp, err := DecodeInteger(data)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(timestamp), 0), nil
}

// EncodeOctets encodes raw octets for RADIUS attributes
func EncodeOctets(data []byte) []byte {
	return data
}

// DecodeOctets decodes raw octets from RADIUS attributes
func DecodeOctets(data []byte) []byte {
	return data
}

// EncodeValue encodes a value based on the attribute data type
func EncodeValue(value any, dataType DataType) ([]byte, error) {
	switch dataType {
	case DataTypeString:
		if s, ok := value.(string); ok {
			return EncodeString(s), nil
		}
		return nil, fmt.Errorf("expected string for string data type")

	case DataTypeInteger:
		switch v := value.(type) {
		case uint32:
			return EncodeInteger(v), nil
		case int:
			return EncodeInteger(uint32(v)), nil
		case int32:
			return EncodeInteger(uint32(v)), nil
		default:
			return nil, fmt.Errorf("expected integer for integer data type")
		}

	case DataTypeIPAddr:
		if ip, ok := value.(net.IP); ok {
			return EncodeIPAddr(ip)
		}
		if s, ok := value.(string); ok {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", s)
			}
			return EncodeIPAddr(ip)
		}
		return nil, fmt.Errorf("expected net.IP or string for ipaddr data type")

	case DataTypeIPv6Addr:
		if ip, ok := value.(net.IP); ok {
			return EncodeIPv6Addr(ip)
		}
		if s, ok := value.(string); ok {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid IPv6 address: %s", s)
			}
			return EncodeIPv6Addr(ip)
		}
		return nil, fmt.Errorf("expected net.IP or string for ipv6addr data type")

	case DataTypeIPv6Prefix:
		if prefix, ok := value.(*net.IPNet); ok {
			return EncodeIPv6Prefix(prefix)
		}
		if s, ok := value.(string); ok {
			_, prefix, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv6 prefix %q: %w", s, err)
			}
			return EncodeIPv6Prefix(prefix)
		}
		return nil, fmt.Errorf("expected *net.IPNet or string for ipv6prefix data type")

	case DataTypeIfID:
		if ifid, ok := value.([]byte); ok {
			return EncodeIfID(ifid)
		}
		return nil, fmt.Errorf("expected []byte for ifid data type")

	case DataTypeDate:
		if t, ok := value.(time.Time); ok {
			return EncodeDate(t), nil
		}
		return nil, fmt.Errorf("expected time.Time for date data type")

	case DataTypeOctets, DataTypeABinary:
		if data, ok := value.([]byte); ok {
			return EncodeOctets(data), nil
		}
		return nil, fmt.Errorf("expected []byte for octets/abinary data type")

	default:
		return nil, fmt.Errorf("unsupported data type: %s", dataType)
	}
}

// DecodeValue decodes a value based on the attribute data type
func DecodeValue(data []byte, dataType DataType) (any, error) {
	switch dataType {
	case DataTypeString:
		return DecodeString(data), nil

	case DataTypeInteger:
		return DecodeInteger(data)

	case DataTypeIPAddr:
		return DecodeIPAddr(data)

	case DataTypeIPv6Addr:
		return DecodeIPv6Addr(data)

	case DataTypeIPv6Prefix:
		return DecodeIPv6Prefix(data)

	case DataTypeIfID:
		return DecodeIfID(data)

	case DataTypeDate:
		return DecodeDate(data)

	case DataTypeOctets, DataTypeABinary:
		return DecodeOctets(data), nil

	default:
		return nil, fmt.Errorf("unsupported data type: %s", dataType)
	}
}
