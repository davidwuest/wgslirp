package wireguard

import (
    "fmt"
    "os"
    "strconv"
    "strings"
)

// PeerConfig holds a single WireGuard peer configuration.
type PeerConfig struct {
    PublicKey                string   // base64
    AllowedIPs               []string // CIDRs
    Endpoint                 string   // host:port
    PersistentKeepaliveSec   int      // optional
}

// DeviceConfig holds the WireGuard device configuration for WG-only mode.
type DeviceConfig struct {
    ListenPort   int
    PrivateKey   string   // base64
    MTU          int      // plaintext MTU for wg tun
    Peers        []PeerConfig
}

// LoadFromEnv builds a DeviceConfig from environment variables.
//
// Required:
//   WG_PRIVATE_KEY  (base64)
// Optional:
//   WG_LISTEN_PORT (default 51820)
//   WG_MTU (default 1380)
//   WG_PEERS (comma-separated peer indices, e.g., "0,1")
// For each index i in WG_PEERS, read:
//   WG_PEER_i_PUBLIC_KEY
//   WG_PEER_i_ALLOWED_IPS (comma-separated CIDRs)
//   WG_PEER_i_ENDPOINT (host:port)
//   WG_PEER_i_KEEPALIVE (seconds, optional)
func (c *DeviceConfig) LoadFromEnv() error {
    pk := strings.TrimSpace(os.Getenv("WG_PRIVATE_KEY"))
    if pk == "" {
        return fmt.Errorf("WG_PRIVATE_KEY is required")
    }
    c.PrivateKey = pk
    lp := 51820
    if v := os.Getenv("WG_LISTEN_PORT"); v != "" {
        if x, err := strconv.Atoi(v); err == nil { lp = x }
    }
    c.ListenPort = lp
    mtu := 1380
    if v := os.Getenv("WG_MTU"); v != "" {
        if x, err := strconv.Atoi(v); err == nil && x > 0 { mtu = x }
    }
    c.MTU = mtu

    var peers []PeerConfig
    idxs := strings.TrimSpace(os.Getenv("WG_PEERS"))
    if idxs != "" {
        for _, s := range strings.Split(idxs, ",") {
            i := strings.TrimSpace(s)
            if i == "" { continue }
            p := PeerConfig{}
            p.PublicKey = strings.TrimSpace(os.Getenv("WG_PEER_"+i+"_PUBLIC_KEY"))
            allowed := strings.TrimSpace(os.Getenv("WG_PEER_"+i+"_ALLOWED_IPS"))
            if allowed != "" { p.AllowedIPs = splitCSV(allowed) }
            p.Endpoint = strings.TrimSpace(os.Getenv("WG_PEER_"+i+"_ENDPOINT"))
            if ka := strings.TrimSpace(os.Getenv("WG_PEER_"+i+"_KEEPALIVE")); ka != "" {
                if x, err := strconv.Atoi(ka); err == nil { p.PersistentKeepaliveSec = x }
            }
            if p.PublicKey != "" {
                peers = append(peers, p)
            }
        }
    }
    c.Peers = peers
    return nil
}

func splitCSV(s string) []string {
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p != "" { out = append(out, p) }
    }
    return out
}

