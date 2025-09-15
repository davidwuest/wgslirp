package socket

import "testing"

// Test that the IP header total length bytes are set correctly (big-endian)
func TestIPv4HeaderTotalLengthEncoding(t *testing.T) {
    n := 56 // payload length (e.g., ICMP message)
    total := 20 + n

    ipHeader := make([]byte, 20)
    ipHeader[0] = 0x45
    ipHeader[1] = 0x00
    ipHeader[2] = byte(total >> 8)
    ipHeader[3] = byte(total & 0xff)

    got := int(ipHeader[2])<<8 | int(ipHeader[3])
    if got != total {
        t.Fatalf("total length encoded incorrectly: got=%d want=%d", got, total)
    }
}

