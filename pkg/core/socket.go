package core

// SocketInterface represents a socket interface for connecting to the host network.
type SocketInterface interface {
	// Start starts the socket interface.
	Start() error

	// Stop stops the socket interface.
	Stop() error

	// Metrics returns metrics for the socket interface.
	Metrics() SocketMetrics
}

// SocketMetrics contains metrics for a socket interface.
type SocketMetrics struct {
	// ConnectionsCreated is the number of connections created.
	ConnectionsCreated uint64

	// ConnectionsClosed is the number of connections closed.
	ConnectionsClosed uint64

	// PacketsSent is the number of packets sent.
	PacketsSent uint64

	// PacketsReceived is the number of packets received.
	PacketsReceived uint64

	// BytesSent is the number of bytes sent.
	BytesSent uint64

	// BytesReceived is the number of bytes received.
	BytesReceived uint64

	// Errors is the number of errors encountered.
	Errors uint64
}
