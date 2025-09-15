package core

import (
	"testing"
)

// TestRouterConfig tests the RouterConfig structure.
func TestRouterConfig(t *testing.T) {
	// Create a router configuration
	config := RouterConfig{
		TUNName:   "test-tun",
		TUNIP:     "192.168.1.1",
		TUNSubnet: "192.168.1.0/24",
		TUNMTU:    1500,
		SocketIP:  "10.0.0.1",
		Debug:     true,
	}

	// Test field values
	if config.TUNName != "test-tun" {
		t.Errorf("Expected TUNName to be 'test-tun', got '%s'", config.TUNName)
	}

	if config.TUNIP != "192.168.1.1" {
		t.Errorf("Expected TUNIP to be '192.168.1.1', got '%s'", config.TUNIP)
	}

	if config.TUNSubnet != "192.168.1.0/24" {
		t.Errorf("Expected TUNSubnet to be '192.168.1.0/24', got '%s'", config.TUNSubnet)
	}

	if config.TUNMTU != 1500 {
		t.Errorf("Expected TUNMTU to be 1500, got %d", config.TUNMTU)
	}

	if config.SocketIP != "10.0.0.1" {
		t.Errorf("Expected SocketIP to be '10.0.0.1', got '%s'", config.SocketIP)
	}

	if !config.Debug {
		t.Errorf("Expected Debug to be true, got %v", config.Debug)
	}
}

// TestWireGuardConfig tests the WireGuardConfig structure.
func TestWireGuardConfig(t *testing.T) {
	// Create a WireGuard configuration
	config := WireGuardConfig{
		PrivateKey: "private-key",
		ListenPort: 51820,
		Peers: []WireGuardPeer{
			{
				PublicKey:           "public-key-1",
				AllowedIPs:          []string{"192.168.1.0/24"},
				Endpoint:            "192.168.1.2:51820",
				PersistentKeepalive: 25,
			},
			{
				PublicKey:           "public-key-2",
				AllowedIPs:          []string{"10.0.0.0/24", "172.16.0.0/24"},
				Endpoint:            "10.0.0.2:51820",
				PersistentKeepalive: 0,
			},
		},
	}

	// Test field values
	if config.PrivateKey != "private-key" {
		t.Errorf("Expected PrivateKey to be 'private-key', got '%s'", config.PrivateKey)
	}

	if config.ListenPort != 51820 {
		t.Errorf("Expected ListenPort to be 51820, got %d", config.ListenPort)
	}

	// Test peers
	if len(config.Peers) != 2 {
		t.Errorf("Expected 2 peers, got %d", len(config.Peers))
	}

	// Test first peer
	peer1 := config.Peers[0]
	if peer1.PublicKey != "public-key-1" {
		t.Errorf("Expected PublicKey to be 'public-key-1', got '%s'", peer1.PublicKey)
	}

	if len(peer1.AllowedIPs) != 1 || peer1.AllowedIPs[0] != "192.168.1.0/24" {
		t.Errorf("Expected AllowedIPs to be ['192.168.1.0/24'], got %v", peer1.AllowedIPs)
	}

	if peer1.Endpoint != "192.168.1.2:51820" {
		t.Errorf("Expected Endpoint to be '192.168.1.2:51820', got '%s'", peer1.Endpoint)
	}

	if peer1.PersistentKeepalive != 25 {
		t.Errorf("Expected PersistentKeepalive to be 25, got %d", peer1.PersistentKeepalive)
	}

	// Test second peer
	peer2 := config.Peers[1]
	if peer2.PublicKey != "public-key-2" {
		t.Errorf("Expected PublicKey to be 'public-key-2', got '%s'", peer2.PublicKey)
	}

	if len(peer2.AllowedIPs) != 2 || peer2.AllowedIPs[0] != "10.0.0.0/24" || peer2.AllowedIPs[1] != "172.16.0.0/24" {
		t.Errorf("Expected AllowedIPs to be ['10.0.0.0/24', '172.16.0.0/24'], got %v", peer2.AllowedIPs)
	}

	if peer2.Endpoint != "10.0.0.2:51820" {
		t.Errorf("Expected Endpoint to be '10.0.0.2:51820', got '%s'", peer2.Endpoint)
	}

	if peer2.PersistentKeepalive != 0 {
		t.Errorf("Expected PersistentKeepalive to be 0, got %d", peer2.PersistentKeepalive)
	}
}
