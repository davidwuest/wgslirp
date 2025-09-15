package socket

import (
    "sync"
    "github.com/irctrakz/wgslirp/pkg/core"
)

// captureProcessor records packets sent back from bridges for assertions.
type captureProcessor struct {
    mu   sync.Mutex
    pkts [][]byte
}

func (c *captureProcessor) ProcessPacket(p core.Packet) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    d := make([]byte, p.Length())
    copy(d, p.Data())
    c.pkts = append(c.pkts, d)
    return nil
}

// localCapture is a minimal PacketProcessor that stores copies of packets.
type localCapture struct{ pkts [][]byte }

func (c *localCapture) ProcessPacket(p core.Packet) error {
    d := make([]byte, p.Length())
    copy(d, p.Data())
    c.pkts = append(c.pkts, d)
    return nil
}
