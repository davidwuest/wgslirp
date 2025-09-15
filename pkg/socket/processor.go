package socket

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

const ipv4MinHeaderSize = 20

// SocketWriter is an interface for writing packets to a socket
type SocketWriter interface {
	WritePacket(packet core.Packet) error
}

// SocketPacketProcessor implements core.PacketProcessor
type SocketPacketProcessor struct {
	// The socket interface
	socket SocketWriter

	// Worker pool
	workerCount int
	packetCh    chan core.Packet
	stopCh      chan struct{}
	wg          sync.WaitGroup

    // Metrics
    packetsProcessed uint64
    packetsDropped   uint64
    queueFullDrops   uint64
}

// NewSocketPacketProcessor creates a new socket packet processor
func NewSocketPacketProcessor(socket SocketWriter, workerCount int) core.PacketProcessor {
    if workerCount <= 0 { workerCount = 4 }
    // Env overrides for workers and queue capacity.
    if v := strings.TrimSpace(os.Getenv("PROCESSOR_WORKERS")); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 { workerCount = n }
    }
    qcap := 1000
    if v := strings.TrimSpace(os.Getenv("PROCESSOR_QUEUE_CAP")); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 { qcap = n }
    }

    return &SocketPacketProcessor{
        socket:      socket,
        workerCount: workerCount,
        packetCh:    make(chan core.Packet, qcap),
        stopCh:      make(chan struct{}),
    }
}

// Start starts the packet processor
func (p *SocketPacketProcessor) Start() error {
	// Start the worker pool
	p.wg.Add(p.workerCount)
	for i := 0; i < p.workerCount; i++ {
		go p.worker(i)
	}

	logging.Infof("Socket packet processor started with %d workers", p.workerCount)
	return nil
}

// Stop stops the packet processor
func (p *SocketPacketProcessor) Stop() error {
	close(p.stopCh)
	p.wg.Wait()
	close(p.packetCh)

	logging.Infof("Socket packet processor stopped")
	return nil
}

// ProcessPacket implements core.PacketProcessor
func (p *SocketPacketProcessor) ProcessPacket(packet core.Packet) error {
	// Basic validation
	data := packet.Data()
	if len(data) < ipv4MinHeaderSize {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("packet too short")
	}

	// Check IP version
	ver := data[0] >> 4
	if ver != 4 {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("unsupported IP version: %d", ver)
	}

    // Try to send the packet to the worker pool without copying.
    // Packet safety is handled by core.NewPacket at creation time, and
    // each packet is processed by a single worker.
    select {
    case p.packetCh <- packet:
        // Packet sent to worker pool
        atomic.AddUint64(&p.packetsProcessed, 1)
    default:
        // Channel is full, drop the packet
        atomic.AddUint64(&p.packetsDropped, 1)
        atomic.AddUint64(&p.queueFullDrops, 1)
        return fmt.Errorf("packet dropped: worker pool is full")
    }

	return nil
}

// worker processes packets from the channel
func (p *SocketPacketProcessor) worker(id int) {
	defer p.wg.Done()

	logging.Debugf("Socket packet processor worker %d started", id)

	for {
		select {
		case <-p.stopCh:
			logging.Debugf("Socket packet processor worker %d stopped", id)
			return
		case packet, ok := <-p.packetCh:
			if !ok {
				// Channel closed
				return
			}

			// Process the packet
			err := p.processPacketInternal(packet)
			if err != nil {
				logging.Errorf("Failed to process packet in worker %d: %v", id, err)
			}
		}
	}
}

// processPacketInternal processes a packet in a worker
func (p *SocketPacketProcessor) processPacketInternal(packet core.Packet) error {
    // Ensure any pooled packet buffer is released after processing completes.
    defer core.ReleasePacket(packet)
    // Forward the packet to the socket interface
    err := p.socket.WritePacket(packet)
    if err != nil {
        return fmt.Errorf("failed to write packet to socket: %v", err)
    }

	logging.Debugf("Forwarded packet to socket: length=%d", packet.Length())
	return nil
}

// Metrics returns metrics for the packet processor
func (p *SocketPacketProcessor) Metrics() map[string]uint64 {
    return map[string]uint64{
        "packetsProcessed": atomic.LoadUint64(&p.packetsProcessed),
        "packetsDropped":   atomic.LoadUint64(&p.packetsDropped),
        "queueFullDrops":   atomic.LoadUint64(&p.queueFullDrops),
    }
}
