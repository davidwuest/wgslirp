package socket

import (
    "sync/atomic"
    "github.com/irctrakz/wgslirp/pkg/core"
)

// Metrics is an alias for core.SocketMetrics
type Metrics = core.SocketMetrics

// Reset resets all metrics to zero
func ResetMetrics(m *Metrics) {
    m.PacketsReceived = 0
    m.PacketsSent = 0
    m.BytesReceived = 0
    m.BytesSent = 0
    m.Errors = 0
    m.ConnectionsCreated = 0
    m.ConnectionsClosed = 0
}

// UDP debug counters for server->guest delivery path.
var udpTxEnqueued uint64
var udpTxProcessed uint64

func udpDebugEnqueue() { atomic.AddUint64(&udpTxEnqueued, 1) }
func udpDebugProcessed() { atomic.AddUint64(&udpTxProcessed, 1) }
func getUDPTxDebug() (enq, proc uint64) {
    return atomic.LoadUint64(&udpTxEnqueued), atomic.LoadUint64(&udpTxProcessed)
}
