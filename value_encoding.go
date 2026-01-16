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

	case DataTypeDate:
		return DecodeDate(data)

	case DataTypeOctets, DataTypeABinary:
		return DecodeOctets(data), nil

	default:
		return nil, fmt.Errorf("unsupported data type: %s", dataType)
	}
}
