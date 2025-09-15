package wireguard

import (
    "os"
    "fmt"
    "net"
    "github.com/irctrakz/wgslirp/pkg/core"
    "github.com/irctrakz/wgslirp/pkg/logging"
    wtun "golang.zx2c4.com/wireguard/tun"
    "sync/atomic"
)

// File returns nil; userspace WGTun does not back with an os.File.
func (t *WGTun) File() *os.File { return nil }

// Read with offset compatibility for wireguard-go; offset is ignored.
func (t *WGTun) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
    select {
    case <-t.closed:
        return 0, fmt.Errorf("wg tun closed")
    case pkt := <-t.outCh:
        if len(buffs) == 0 { return 0, nil }
        b := buffs[0]
        if offset >= len(b) { return 0, fmt.Errorf("offset beyond buffer") }
        dst := b[offset:]
        n := len(pkt)
        if n > len(dst) { n = len(dst) }
        copy(dst, pkt[:n])
        if sizes != nil && len(sizes) > 0 { sizes[0] = n }
        return 1, nil
    }
}

// Write with offset compatibility for wireguard-go; offset is ignored.
func (t *WGTun) Write(buffs [][]byte, offset int) (int, error) {
    // forward each buffer as a packet either back into WG (overlay) or to slirp
    sent := 0
    var totalFromWG uint64
    var totalToWG uint64
    for _, b := range buffs {
        if b == nil { continue }
        if offset >= len(b) { continue }
        pkt := b[offset:]
        // Handle non-IPv4 frames (e.g., WireGuard control or IPv6): count as consumed
        // but do not forward to the slirp writer which expects IPv4 packets.
        if !IsIPv4(pkt) {
            logging.Debugf("WGTun received non-IPv4/control frame: len=%d", len(pkt))
            sent++
            continue
        }
        // Optional PCAP tee of plaintext guest->server packet
        pcapWriteIPv4(pkt)
        dst := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
        // Exclusion first: always egress via slirp
        if t.dstInExclude(dst) {
            cp := append([]byte(nil), pkt...)
            if err := t.writer.WritePacket(core.NewPacket(cp)); err != nil { return sent, err }
            sent++
            totalFromWG += uint64(len(pkt))
            continue
        }
        // Overlay re-route: back into WG if destination is inside a peer prefix
        if t.dstInPeerCIDR(dst) {
            if err := t.InjectToPeer(pkt); err != nil { return sent, err }
            sent++
            totalToWG += uint64(len(pkt))
            continue
        }
        // Default: egress via slirp
        cp := append([]byte(nil), pkt...)
        if err := t.writer.WritePacket(core.NewPacket(cp)); err != nil { return sent, err }
        sent++
        totalFromWG += uint64(len(pkt))
    }
    if totalFromWG > 0 { atomic.AddUint64(&t.metrics.PlaintextFromWG, totalFromWG) }
    if totalToWG > 0 { atomic.AddUint64(&t.metrics.PlaintextToWG, totalToWG) }
    return sent, nil
}

// Flush is a no-op for userspace WGTun.
func (t *WGTun) Flush() error { return nil }

// Events provides a wtun.Event channel mapped from the internal event stream.
func (t *WGTun) Events() <-chan wtun.Event {
    ch := make(chan wtun.Event, 2)
    go func() {
        for e := range t.events {
            switch e {
            case EventUp:
                ch <- wtun.EventUp
            case EventDown:
                ch <- wtun.EventDown
            default:
            }
        }
        close(ch)
    }()
    return ch
}

// BatchSize returns 1 to indicate minimal batch support.
func (t *WGTun) BatchSize() int { return 1 }
