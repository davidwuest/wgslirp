package socket

import (
    "encoding/binary"
    "net"
    "testing"
)

// Build a minimal IPv4+UDP packet and verify parsing and reconstruction.
func TestBuildIPv4UDP(t *testing.T) {
    var a, b [4]byte
    copy(a[:], net.IPv4(10, 0, 0, 2).To4())
    copy(b[:], net.IPv4(8, 8, 8, 8).To4())
    payload := []byte{1, 2, 3, 4, 5}

    pkt := buildIPv4UDP(a, b, 12345, 53, payload)
    if pkt == nil {
        t.Fatal("nil pkt")
    }
    if len(pkt) != 20+8+len(payload) {
        t.Fatalf("unexpected length: %d", len(pkt))
    }
    // Check IP fields
    if pkt[0]>>4 != 4 || int(pkt[0]&0x0f)*4 != 20 {
        t.Fatalf("bad version/ihl: 0x%02x", pkt[0])
    }
    total := int(pkt[2])<<8 | int(pkt[3])
    if total != len(pkt) {
        t.Fatalf("bad total length: %d want %d", total, len(pkt))
    }
    // Check UDP ports
    off := 20
    sport := binary.BigEndian.Uint16(pkt[off : off+2])
    dport := binary.BigEndian.Uint16(pkt[off+2 : off+4])
    if sport != 12345 || dport != 53 {
        t.Fatalf("ports mismatch: %d->%d", sport, dport)
    }
}

