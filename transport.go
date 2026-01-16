package goradius

import "net"

// Transport abstracts the network transport layer for RADIUS packets.
// Implementations handle protocol-specific details (UDP datagram vs TCP stream).
type Transport interface {
	// Serve starts accepting and processing packets.
	// Calls handler for each received
	// Blocks until the transport is closed or an error occurs.
	Serve(handler TransportHandler) error

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// Close stops the transport and releases resources.
	// Blocks until all in-flight handlers complete.
	Close() error
}

// TransportHandler is called for each received RADIUS
// data contains the raw packet bytes.
// remoteAddr is the client's address.
// respond sends a reply back to the client.
type TransportHandler func(data []byte, remoteAddr net.Addr, respond ResponderFunc)

// ResponderFunc sends response data back to the client.
// Returns an error if the response could not be sent.
type ResponderFunc func(data []byte) error
