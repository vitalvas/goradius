package packet

import (
	"encoding/binary"
	"net"
	"time"
)

// EncodeUint32 encodes a uint32 value as a 4-byte big-endian slice
func EncodeUint32(value uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return buf
}

// EncodeUint64 encodes a uint64 value as an 8-byte big-endian slice
func EncodeUint64(value uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	return buf
}

// EncodeIPAddress encodes an IPv4 address as a 4-byte slice
func EncodeIPAddress(ipStr string) []byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return []byte{0, 0, 0, 0}
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return []byte{0, 0, 0, 0}
	}
	return []byte(ipv4)
}

// EncodeTime encodes a time.Time as a Unix timestamp (uint32)
func EncodeTime(t time.Time) []byte {
	return EncodeUint32(uint32(t.Unix()))
}

// DecodeUint32 decodes a 4-byte big-endian slice to uint32
func DecodeUint32(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(data[:4])
}

// DecodeUint64 decodes an 8-byte big-endian slice to uint64
func DecodeUint64(data []byte) uint64 {
	if len(data) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(data[:8])
}

// DecodeIPAddress decodes a 4-byte slice to an IPv4 address string
func DecodeIPAddress(data []byte) string {
	if len(data) < 4 {
		return "0.0.0.0"
	}
	return net.IP(data[:4]).String()
}

// DecodeTime decodes a 4-byte slice to time.Time (Unix timestamp)
func DecodeTime(data []byte) time.Time {
	timestamp := DecodeUint32(data)
	return time.Unix(int64(timestamp), 0)
}
