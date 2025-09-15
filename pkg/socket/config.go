package socket

// Config contains configuration for the socket interface
type Config struct {
    // IP address for the socket interface
    IPAddress string

    // MTU for the socket interface
    MTU int

    // Enable debug logging
    Debug bool

    // Protocol to use for the socket interface (ip4:icmp, ip4:tcp, ip4:udp)
    // Default is ip4:icmp
    Protocol string

    // TCPAckDelayMs controls delayed ACK scheduling (milliseconds).
    TCPAckDelayMs int

    // TCPFlowLifetimeSec controls idle TCP flow timeout (seconds).
    TCPFlowLifetimeSec int

    // UDPFlowLifetimeSec controls idle UDP flow timeout (seconds).
    UDPFlowLifetimeSec int

    // TCPReassemblyCapBytes caps buffered out-of-order bytes per TCP flow.
    TCPReassemblyCapBytes int

    // MaxTCPFlows limits active TCP flows (0 = unlimited).
    MaxTCPFlows int

    // MaxUDPFlows limits active UDP flows (0 = unlimited).
    MaxUDPFlows int
}

// DefaultConfig returns the default configuration for the socket interface
func DefaultConfig() Config {
    return Config{
        IPAddress: "0.0.0.0",
        MTU:       1500,
        Debug:     false,
        Protocol:  "ip4:icmp",
        TCPAckDelayMs:         25,
        TCPFlowLifetimeSec:    120,
        UDPFlowLifetimeSec:    60,
        TCPReassemblyCapBytes: 128 * 1024,
        MaxTCPFlows:           0,
        MaxUDPFlows:           0,
    }
}
