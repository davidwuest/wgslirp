package core

// RouterConfig contains configuration for the router.
type RouterConfig struct {
	// TUNName is the name of the TUN device.
	TUNName string `json:"tun_name" yaml:"tunName"`

	// TUNIP is the IP address of the TUN device.
	TUNIP string `json:"tun_ip" yaml:"tunIP"`

	// TUNSubnet is the subnet in CIDR notation (e.g., "192.168.1.0/24").
	TUNSubnet string `json:"tun_subnet" yaml:"tunSubnet"`

	// TUNMTU is the Maximum Transmission Unit (MTU) of the TUN device.
	TUNMTU int `json:"tun_mtu" yaml:"tunMTU"`

	// SocketIP is the IP address of the socket interface.
	SocketIP string `json:"socket_ip" yaml:"socketIP"`

	// Debug enables debug logging.
	Debug bool `json:"debug" yaml:"debug"`

	// EnableNAT enables Network Address Translation.
	EnableNAT bool `json:"enable_nat" yaml:"enableNAT"`

	// NATMasqueradeIP is the IP address to use for NAT masquerading.
	// If empty, the TUN IP address will be used.
	NATMasqueradeIP string `json:"nat_masquerade_ip" yaml:"natMasqueradeIP"`
}

// WireGuardConfig contains configuration for WireGuard.
type WireGuardConfig struct {
	// PrivateKey is the WireGuard private key.
	PrivateKey string `json:"private_key" yaml:"privateKey"`

	// ListenPort is the port to listen on for WireGuard connections.
	ListenPort int `json:"listen_port" yaml:"listenPort"`

	// Peers is a list of WireGuard peers.
	Peers []WireGuardPeer `json:"peers" yaml:"peers"`

	// DisableSourceValidation disables source address validation for packets.
	// This is useful when clients need to send packets with source addresses
	// that don't match their allowed IPs (e.g., when routing all traffic through the VPN).
	// WARNING: This reduces security by bypassing WireGuard's source address validation.
	DisableSourceValidation bool `json:"disable_source_validation" yaml:"disableSourceValidation"`
}

// WireGuardPeer represents a WireGuard peer.
type WireGuardPeer struct {
	// PublicKey is the peer's public key.
	PublicKey string `json:"public_key" yaml:"publicKey"`

	// AllowedIPs is a list of IP ranges that are allowed for this peer.
	AllowedIPs []string `json:"allowed_ips" yaml:"allowedIPs"`

	// Endpoint is the peer's endpoint address.
	Endpoint string `json:"endpoint" yaml:"endpoint"`

	// PersistentKeepalive is the interval in seconds for sending keepalive packets.
	PersistentKeepalive int `json:"persistent_keepalive" yaml:"persistentKeepalive"`
}
