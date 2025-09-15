package core

// Router represents the userspace WireGuard router.
type Router interface {
	// Start starts the router.
	Start() error

	// Stop stops the router.
	Stop() error

	// Metrics returns metrics for the router.
	Metrics() RouterMetrics
}

// RouterMetrics contains metrics for the router.
type RouterMetrics struct {
	// TUN contains metrics for the TUN device.
	TUN TUNMetrics

	// Socket contains metrics for the socket interface.
	Socket SocketMetrics

	// PacketsRouted is the number of packets routed.
	PacketsRouted uint64

	// PacketsDropped is the number of packets dropped.
	PacketsDropped uint64

	// NATTranslations is the number of NAT translations performed.
	NATTranslations uint64
}
