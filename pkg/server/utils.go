package server

import "net"

// isIPInNetwork checks if an IP is in the specified network (IP or CIDR)
func isIPInNetwork(ip net.IP, network string) bool {
	// Try parsing as CIDR first
	_, ipNet, err := net.ParseCIDR(network)
	if err == nil {
		return ipNet.Contains(ip)
	}

	// Try parsing as single IP
	allowedIP := net.ParseIP(network)
	if allowedIP != nil {
		return ip.Equal(allowedIP)
	}

	return false
}
