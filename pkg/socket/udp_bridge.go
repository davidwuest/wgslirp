package socket

import (
    "encoding/binary"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/irctrakz/wgslirp/pkg/core"
    "github.com/irctrakz/wgslirp/pkg/logging"
    "sync/atomic"
)

// udpBridge implements a simple slirp-style UDP translator.
// It maps guest UDP 5-tuples to host UDP sockets and relays payloads.
type udpBridge struct {
    parent   *SocketInterface
    flowsMu  sync.RWMutex
    flows    map[string]*udpFlow
    stopCh   chan struct{}
    lifetime time.Duration

    metrics core.SocketMetrics
    maxFlows int

    // (FlowManager removed)
}

type udpFlow struct {
    key            string
    srcIP          [4]byte
    dstIP          [4]byte
    srcPort        uint16
    dstPort        uint16
    conn           *net.UDPConn
    lastActivityMu sync.Mutex
    lastActivity   time.Time

    // Preserve DSCP/ECN (TOS) and TTL from outbound packet for replies
    tos byte
    ttl byte
}

func newUDPBridge(parent *SocketInterface) *udpBridge {
    b := &udpBridge{
        parent:   parent,
        flows:    make(map[string]*udpFlow),
        stopCh:   make(chan struct{}),
        lifetime: 60 * time.Second,
    }
    if parent != nil {
        if parent.config.UDPFlowLifetimeSec > 0 {
            b.lifetime = time.Duration(parent.config.UDPFlowLifetimeSec) * time.Second
        }
        b.maxFlows = parent.config.MaxUDPFlows
    }
    go b.reaper()
    return b
}

func (b *udpBridge) Name() string { return "udp" }

func (b *udpBridge) stop() {
    close(b.stopCh)
    b.flowsMu.Lock()
    defer b.flowsMu.Unlock()
    for k, f := range b.flows {
        _ = f.conn.Close()
        delete(b.flows, k)
    }
}

// HandleOutbound parses an IPv4+UDP packet and forwards the UDP payload via a host UDP socket.
// It creates a flow if needed and writes the payload. The flow's read goroutine sends replies
// back to the netstack as synthesized IPv4+UDP packets.
func (b *udpBridge) HandleOutbound(pkt []byte) error {
    if len(pkt) < 28 { // IPv4(20)+UDP(8)
        return fmt.Errorf("udp: packet too short")
    }

    // Parse IPv4 header (no options assumed)
    ihl := int(pkt[0]&0x0f) * 4
    if ihl < 20 || len(pkt) < ihl+8 {
        return fmt.Errorf("udp: invalid IHL or too short")
    }
    var srcIP, dstIP [4]byte
    copy(srcIP[:], pkt[12:16])
    copy(dstIP[:], pkt[16:20])
    tos := pkt[1]
    ttl := pkt[8]

    // Parse UDP header
    udpOff := ihl
    srcPort := binary.BigEndian.Uint16(pkt[udpOff : udpOff+2])
    dstPort := binary.BigEndian.Uint16(pkt[udpOff+2 : udpOff+4])
    // length := binary.BigEndian.Uint16(pkt[udpOff+4 : udpOff+6]) // total UDP length

    payload := pkt[udpOff+8:]

    key := b.flowKey(srcIP, srcPort, dstIP, dstPort)

    // Reject unspecified destination addresses
    if net.IP(dstIP[:]).IsUnspecified() {
        if b.parent != nil && b.parent.processor != nil {
            icmp := buildICMPUnreachable(dstIP, srcIP, 3 /*port unreachable*/, pkt)
            if icmp != nil {
                p := WrapPacket(icmp)
                _ = b.parent.processor.ProcessPacket(p)
            }
        }
        return fmt.Errorf("udp: unspecified destination address")
    }

    // Get or create flow
    b.flowsMu.RLock()
    flow := b.flows[key]
    b.flowsMu.RUnlock()
    if flow == nil {
        // Dial UDP to destination outside of lock
        raddr := &net.UDPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
        conn, err := net.DialUDP("udp", nil, raddr)
        if err != nil {
            // ICMP error mapping: port unreachable back to client
            if b.parent != nil && b.parent.processor != nil {
                icmpPkt := buildICMPUnreachable(dstIP, srcIP, 3 /*Port Unreachable*/, pkt)
                if icmpPkt != nil {
                    p := WrapPacket(icmpPkt)
                    _ = b.parent.processor.ProcessPacket(p)
                }
            }
            atomic.AddUint64(&b.parent.metrics.Errors, 1)
            return fmt.Errorf("udp: dial %v: %w", raddr, err)
        }
        candidate := &udpFlow{
            key:     key,
            srcIP:   srcIP,
            dstIP:   dstIP,
            srcPort: srcPort,
            dstPort: dstPort,
            conn:    conn,
            tos:     tos,
            ttl:     ttl,
        }
        candidate.touch()
        // Insert under write lock with double-check
        b.flowsMu.Lock()
        if exist := b.flows[key]; exist != nil {
            b.flowsMu.Unlock()
            _ = conn.Close()
            flow = exist
        } else {
            if b.maxFlows > 0 && len(b.flows) >= b.maxFlows {
                b.flowsMu.Unlock()
                _ = conn.Close()
                if b.parent != nil && b.parent.processor != nil {
                    icmp := buildICMPUnreachable(dstIP, srcIP, 1, pkt)
                    if icmp != nil {
                        p := WrapPacket(icmp)
                        _ = b.parent.processor.ProcessPacket(p)
                    }
                }
                return fmt.Errorf("udp: flow cap reached")
            }
            b.flows[key] = candidate
            b.flowsMu.Unlock()
            flow = candidate
            go b.reader(flow)
            logging.Debugf("UDP flow created %s:%d -> %s:%d", net.IP(srcIP[:]), srcPort, net.IP(dstIP[:]), dstPort)
            atomic.AddUint64(&b.metrics.ConnectionsCreated, 1)
            atomic.AddUint64(&b.parent.metrics.ConnectionsCreated, 1)
        }
    }

    flow.touch()

    // Write payload to remote
    if len(payload) > 0 {
        if n, err := flow.conn.Write(payload); err != nil {
            atomic.AddUint64(&b.parent.metrics.Errors, 1)
            return fmt.Errorf("udp: write: %w", err)
        } else {
            atomic.AddUint64(&b.metrics.PacketsSent, 1)
            atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
            atomic.AddUint64(&b.parent.metrics.PacketsSent, 1)
            atomic.AddUint64(&b.parent.metrics.BytesSent, uint64(n))
        }
    }
    return nil
}

func (b *udpBridge) reader(f *udpFlow) {
    buf := make([]byte, 65535)
    for {
        n, _, err := f.conn.ReadFrom(buf)
        if err != nil {
            // Closed or error; remove flow
            b.removeFlow(f.key)
            return
        }
        f.touch()
        payload := buf[:n]
        // Build IPv4+UDP back to guest: src=dstIP:dstPort, dst=srcIP:srcPort
        // Use socket policy for TOS/TTL (optionally preserve, or normalize)
        mtu := 0
        tosOut, ttlOut := f.tos, f.ttl
        if b.parent != nil {
            mtu = b.parent.EffectiveMTU()
            tosOut, ttlOut = b.parent.effTosTTL(f.tos, f.ttl)
        }
        if mtu <= 0 { mtu = 1500 }
        // Compute total length if unfragmented
        total := 20 + 8 + len(payload)
        frags := [][]byte{}
        if total > mtu {
            // Fragment the UDP datagram into IPv4 fragments obeying 8-byte boundaries
            frags = buildIPv4UDPFragmentsWith(f.dstIP, f.srcIP, f.dstPort, f.srcPort, payload, tosOut, ttlOut, mtu)
        } else {
            p := buildIPv4UDPWith(f.dstIP, f.srcIP, f.dstPort, f.srcPort, payload, tosOut, ttlOut)
            if p != nil { frags = [][]byte{p} }
        }
        if len(frags) == 0 { continue }
        // Deliver fragments back to processor inline.
        for _, pkt := range frags {
            out := pkt
            udpDebugEnqueue()
            if poolingEnabled() && !poolWrapEnabled() {
                out = append([]byte(nil), pkt...)
            }
            if b.parent.processor != nil {
                _ = b.parent.processor.ProcessPacket(WrapPacket(out))
                udpDebugProcessed()
            }
            atomic.AddUint64(&b.metrics.PacketsReceived, 1)
            atomic.AddUint64(&b.metrics.BytesReceived, uint64(len(pkt)))
            atomic.AddUint64(&b.parent.metrics.PacketsReceived, 1)
            atomic.AddUint64(&b.parent.metrics.BytesReceived, uint64(len(pkt)))
        }
    }
}

func (b *udpBridge) removeFlow(key string) {
    b.flowsMu.Lock()
    defer b.flowsMu.Unlock()
    if f, ok := b.flows[key]; ok {
        _ = f.conn.Close()
        delete(b.flows, key)
        atomic.AddUint64(&b.metrics.ConnectionsClosed, 1)
        atomic.AddUint64(&b.parent.metrics.ConnectionsClosed, 1)
    }
}

func (b *udpBridge) reaper() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-b.stopCh:
            return
        case <-ticker.C:
            deadline := time.Now().Add(-b.lifetime)
            b.flowsMu.Lock()
            for k, f := range b.flows {
                if f.lastActive().Before(deadline) {
                    _ = f.conn.Close()
                    delete(b.flows, k)
                    logging.Debugf("UDP flow expired and removed: %s", k)
                }
            }
            b.flowsMu.Unlock()
        }
    }
}

func (b *udpBridge) flowKey(src [4]byte, sport uint16, dst [4]byte, dport uint16) string {
    return fmt.Sprintf("%d.%d.%d.%d:%d-%d.%d.%d.%d:%d",
        src[0], src[1], src[2], src[3], sport,
        dst[0], dst[1], dst[2], dst[3], dport,
    )
}

func (f *udpFlow) touch() {
    f.lastActivityMu.Lock()
    f.lastActivity = time.Now()
    f.lastActivityMu.Unlock()
}

func (f *udpFlow) lastActive() time.Time {
    f.lastActivityMu.Lock()
    defer f.lastActivityMu.Unlock()
    return f.lastActivity
}

// buildIPv4UDP builds an IPv4+UDP packet with given addresses, ports and payload.
func buildIPv4UDP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
    return buildIPv4UDPWith(srcIP, dstIP, srcPort, dstPort, payload, 0x00, 64)
}

// buildIPv4UDPWith builds an IPv4+UDP packet with specified TOS and TTL.
func buildIPv4UDPWith(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte, tos byte, ttl byte) []byte {
    ihl := 20
    udpLen := 8 + len(payload)
    totalLen := ihl + udpLen
    pkt := make([]byte, totalLen)

    // IPv4 header
    pkt[0] = 0x45 // version=4, IHL=5
    pkt[1] = tos  // DSCP/ECN
    pkt[2] = byte(totalLen >> 8)
    pkt[3] = byte(totalLen & 0xff)
    // Identification: incrementing ID to avoid zero-ID issues on some paths
    id := nextIPID()
    pkt[4] = byte(id >> 8)
    pkt[5] = byte(id)
    pkt[6], pkt[7] = 0, 0           // flags/frag offset
    pkt[8] = ttl                    // TTL
    pkt[9] = 17                     // UDP
    copy(pkt[12:16], srcIP[:])
    copy(pkt[16:20], dstIP[:])
    csum := calculateChecksum(pkt[:20])
    pkt[10] = byte(csum >> 8)
    pkt[11] = byte(csum & 0xff)

    // UDP header
    off := 20
    binary.BigEndian.PutUint16(pkt[off:off+2], srcPort)
    binary.BigEndian.PutUint16(pkt[off+2:off+4], dstPort)
    binary.BigEndian.PutUint16(pkt[off+4:off+6], uint16(udpLen))
    copy(pkt[off+8:], payload)

    // UDP checksum with pseudo-header (optional for IPv4 but we compute it)
    ucsum := udpChecksum(pkt[off:off+udpLen], srcIP, dstIP)
    binary.BigEndian.PutUint16(pkt[off+6:off+8], ucsum)

    return pkt
}

// buildIPv4UDPFragmentsWith fragments a UDP datagram into multiple IPv4
// fragments if needed to fit the provided MTU. The first fragment contains the
// UDP header; subsequent fragments carry only UDP payload bytes. Fragment sizes
// are aligned to 8-byte boundaries per IPv4 requirements.
func buildIPv4UDPFragmentsWith(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte, tos byte, ttl byte, mtu int) [][]byte {
    if mtu <= 28 { return nil }
    // Prepare full UDP datagram (header + payload)
    udpLen := 8 + len(payload)
    full := make([]byte, udpLen)
    // UDP header
    binary.BigEndian.PutUint16(full[0:2], srcPort)
    binary.BigEndian.PutUint16(full[2:4], dstPort)
    binary.BigEndian.PutUint16(full[4:6], uint16(udpLen))
    copy(full[8:], payload)
    // Checksum over full datagram
    ucsum := udpChecksum(full[:udpLen], srcIP, dstIP)
    binary.BigEndian.PutUint16(full[6:8], ucsum)

    // Max data per fragment after 20-byte IP header
    maxFrag := mtu - 20
    if maxFrag < 8 { return nil }
    // Align to 8-byte multiples
    maxFrag &= ^7
    if maxFrag <= 0 { return nil }

    var frags [][]byte
    // Fragment loop over full UDP datagram
    offset := 0
    id := nextIPID()
    for offset < udpLen {
        size := udpLen - offset
        if size > maxFrag { size = maxFrag }
        // total packet length = IP header + fragment data
        total := 20 + size
        pkt := make([]byte, total)
        // IPv4 header
        pkt[0] = 0x45
        pkt[1] = tos
        pkt[2] = byte(total >> 8)
        pkt[3] = byte(total & 0xff)
        pkt[4] = byte(id >> 8)
        pkt[5] = byte(id)
        // flags+frag offset
        // Offset in 8-byte units
        offUnits := offset / 8
        // More Fragments flag if not last
        flags := 0
        if offset+size < udpLen { flags = 0x2000 } // MF bit
        // Combine flags and offset
        fo := uint16(flags) | uint16(offUnits)
        pkt[6] = byte(fo >> 8)
        pkt[7] = byte(fo)
        pkt[8] = ttl
        pkt[9] = 17 // UDP
        copy(pkt[12:16], srcIP[:])
        copy(pkt[16:20], dstIP[:])
        // Copy fragment data (slice of UDP datagram)
        copy(pkt[20:], full[offset:offset+size])
        // IP header checksum
        csum := calculateChecksum(pkt[:20])
        pkt[10] = byte(csum >> 8)
        pkt[11] = byte(csum & 0xff)
        frags = append(frags, pkt)
        offset += size
    }
    return frags
}

func udpChecksum(udp []byte, srcIP, dstIP [4]byte) uint16 {
    // Pseudo-header: src(4) dst(4) zero(1) proto(1) udpLen(2)
    sum := uint32(0)
    var pseudo [12]byte
    copy(pseudo[0:4], srcIP[:])
    copy(pseudo[4:8], dstIP[:])
    pseudo[8] = 0
    pseudo[9] = 17
    binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))

    // Sum pseudo-header
    for i := 0; i < len(pseudo); i += 2 {
        sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
    }

    // Sum UDP header+payload
    for i := 0; i+1 < len(udp); i += 2 {
        sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
    }
    if len(udp)%2 == 1 {
        sum += uint32(uint16(udp[len(udp)-1]) << 8)
    }

    for (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16)
    }
    return ^uint16(sum)
}
