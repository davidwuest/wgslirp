package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

// TCP slirp bridge for host networking.
//
// Overview (generic, protocol-agnostic):
// - Performs a full TCP handshake to a host socket on initial SYN.
// - Parses and honors client MSS and Window Scale options.
// - Handles guest out-of-order data with a per-flow reassembly buffer that
//   merges/compacts segments until missing data arrives.
// - Segments server→guest payloads respecting advertised window and MSS.
// - Implements delayed-ACK scheduling and wakes senders on ACK/window updates
//   via a per-flow notifier, without protocol-specific heuristics.
// - Implements basic loss recovery:
//   * Fast retransmit on 3 duplicate ACKs.
//   * Simple RTO with exponential backoff and a retransmission queue.
// - Applies backpressure end-to-end:
//   * Reader pauses when per-flow queues exceed a high watermark and resumes
//     on a low watermark.
//   * Scheduler cooperates with downstream (e.g., WG TUN) backpressure by
//     requeueing and yielding briefly instead of dropping.
//
// The goal is a robust, generic TCP bridge that relies on TCP flow control and
// retransmission rather than protocol-specific tweaks.

type tcpBridge struct {
	parent   *SocketInterface
	mu       sync.RWMutex
	flows    map[string]*tcpFlow
	stopCh   chan struct{}
	lifetime time.Duration

	metrics  core.SocketMetrics
	maxFlows int
	ackDelay time.Duration
	reasmCap int
	// How to signal guest on outbound connect failures: "icmp" (default), "rst", or "none"
	errorSignal string
	// Optional ACK-idle gating configuration
	ackIdleGate        time.Duration // 0 = disabled; gate reads when no ACK for >= this
	ackIdleMinInflight int           // only gate if inFlight > this (bytes); 0 -> auto = MSS
	// Optional ACK-idle fail threshold: if no ACK progress for >= this duration
	// while there is in-flight data, treat the flow as hung and actively reset
	// it (policy-controlled) to avoid indefinite stalls. 0 disables.
	ackIdleFail time.Duration

    // debug removed (was verbose per-flow tracing)

	// Optional MSS clamp (bytes). When >0, we clamp advertised MSS in
	// SYN-ACK and the effective segmentation MSS to min(client, clamp, MTU-40).
	mssClamp int

	// Optional lightweight pacing between segments (microseconds). When >0,
	// we sleep this long between enqueued segments to reduce burst loss on
	// marginal paths.
	paceUS int

	// RTO retransmissions observed (for diagnostics/metrics)
	rtoCount uint64

	// RTO metrics tracking
	rtoMu              sync.Mutex
	rtoActiveFlows     map[string]bool // Tracks flows currently in RTO retransmission
	rtoMetricsDumped   bool            // Flag to prevent repeated dumps for the same event
	rtoMetricsDumpTime time.Time       // Last time metrics were dumped

	// ACK classification counters (userspace visibility for return path)
	ackAdv     uint64 // ACK advanced sndUna
	ackDup     uint64 // Duplicate ACK (no payload, ack==sndUna)
	ackWndOnly uint64 // Pure window update (ack==sndUna, window increased)

	// Optional per-ACK trace (debug)
	ackTrace bool

	// Async dial + pending buffering instrumentation
	dialStart    uint64
	dialOk       uint64
	dialFail     uint64
	dialInflight int64

	pendEnq   uint64
	pendFlush uint64
	pendDrop  uint64

	// Default per-flow pre-connect pending cap (bytes)
	defaultPendCap int

	// Handshake logging toggle (SYN-ACK MSS). Enable via TCP_LOG_HANDSHAKE=1|true|on|yes
	logHandshake bool

	// Send-gate logging controls
	gateLogDisabled bool // disable "TCP send-gated" logs entirely
	gateLogDebug    bool // log send-gated at debug level instead of info
}

type tcpState int

const (
	tcpSynRcvd tcpState = iota
	tcpEstablished
	tcpFinWait
	tcpClosed
)

type tcpFlow struct {
	key     string
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16

	conn *net.TCPConn
	// Deferred connect support
	connecting   bool
	pendMu       sync.Mutex
	pending      [][]byte
	pendingBytes int
	pendCap      int // max bytes to buffer before connect (per flow)

	// Sequence tracking
	clientISN uint32
	serverISN uint32
	clientNxt uint32 // next expected from client
	serverNxt uint32 // next to send to client
	sndUna    uint32 // lowest unacknowledged seq we sent

	state tcpState

	lastMu       sync.Mutex
	lastActivity time.Time
	lastAckTime  time.Time

	finSent bool

	mu sync.Mutex
	// Out-of-order reassembly buffer (sorted by seq, merged)
	ooo []struct {
		seq  uint32
		data []byte
	}
	futureBytes int

	// Peer receive window information (from client)
	clientMSS uint16
	wsIn      uint8  // peer's window scale (client SYN option)
	wsOut     uint8  // our advertised window scale (SYN-ACK)
	advWnd    uint32 // latest advertised peer window in bytes

	// delayed ack scheduling
	ackMu        sync.Mutex
	ackScheduled bool

	// Preserve DSCP/ECN and TTL for host->guest data segments
	tos byte
	ttl byte

	// Per-flow accounting for post-mortem analysis
	toSrvBytes uint64 // guest->server bytes written on host socket
	toSrvPkts  uint64 // guest->server write operations
	toCliBytes uint64 // server->guest bytes emitted toward guest
	toCliPkts  uint64 // server->guest segments emitted

	// Send tracking for retransmissions
	txMu    sync.Mutex
	txQueue []struct {
		seq     uint32
		data    []byte
		sentAt  time.Time
		retries int
		rtx     bool
	}
	dupAckCnt int
	lastAck   uint32
	// RTT/RTO estimation (RFC 6298)
	srtt    time.Duration
	rttvar  time.Duration
	rto     time.Duration
	rtoStop chan struct{}

	// Notify sender when ACK/window updates arrive.
	ackCh chan struct{}

	// handshake state
	synAckSent bool

	// SACK loss recovery (RFC 6675 simplified)
	sackRecovery bool
	recover      uint32
	pipeBytes    int

	// SACK support
	sackPermitted bool
	// scoreboard of SACKed ranges (left,right), normalized and compacted
	sackMu   sync.Mutex
	sackList []struct {
		left  uint32
		right uint32
	}

	// Congestion control (server->guest)
	cc        congestionControl
	ccEnabled bool
	mss       int

	// Throttled logging for send-gated (zero-window/cwnd) messages
	gateMu          sync.Mutex
	lastGateLog     time.Time
	suppressedGates int
}

// newTCPBridge constructs a TCP bridge instance and wires optional per-flow
// scheduling/backpressure via the parent's FlowManager when present.
func newTCPBridge(parent *SocketInterface) *tcpBridge {
	b := &tcpBridge{
		parent:   parent,
		flows:    make(map[string]*tcpFlow),
		stopCh:   make(chan struct{}),
		lifetime: 2 * time.Minute,
		ackDelay: 10 * time.Millisecond,
		reasmCap: 128 * 1024,
		// Defaults: proactively gate reads after 6s of no ACK progress,
		// and fail/reset truly stuck flows after 120s.
		ackIdleGate:    6 * time.Second,
		ackIdleFail:    120 * time.Second,
		rtoActiveFlows: make(map[string]bool),
	}
	// Allow tuning of ACK delay via env (milliseconds).
	if v := strings.TrimSpace(os.Getenv("TCP_ACK_DELAY_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			b.ackDelay = time.Duration(n) * time.Millisecond
		}
	}
	// ACK-idle gate threshold (ms); 0 disables
	if v := strings.TrimSpace(os.Getenv("TCP_ACK_IDLE_GATE_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			b.ackIdleGate = time.Duration(n) * time.Millisecond
		}
	}
	if v := strings.TrimSpace(os.Getenv("TCP_ACK_IDLE_MIN_INFLIGHT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			b.ackIdleMinInflight = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("TCP_ACK_IDLE_FAIL_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			b.ackIdleFail = time.Duration(n) * time.Second
		}
	}
	if v := strings.TrimSpace(os.Getenv("TCP_ACK_TRACE")); v == "1" || strings.ToLower(v) == "true" {
		b.ackTrace = true
	}
	// MSS clamp (bytes)
	if v := strings.TrimSpace(os.Getenv("TCP_MSS_CLAMP")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			b.mssClamp = n
		}
	}
	// Segment pacing (microseconds)
	if v := strings.TrimSpace(os.Getenv("TCP_PACE_US")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			b.paceUS = n
		}
	}
	// Clean mode removed (EMERGENCY_DISABLED no longer used)
	// Configure error signaling policy
	es := strings.ToLower(strings.TrimSpace(os.Getenv("TCP_ERROR_SIGNAL")))
	switch es {
	case "", "icmp":
		b.errorSignal = "icmp"
	case "rst":
		b.errorSignal = "rst"
	case "none":
		b.errorSignal = "none"
	default:
		b.errorSignal = "icmp"
	}

	// Optional handshake log toggle
	if v := strings.TrimSpace(os.Getenv("TCP_LOG_HANDSHAKE")); v != "" {
		vv := strings.ToLower(v)
		if vv == "1" || vv == "true" || vv == "on" || vv == "yes" {
			b.logHandshake = true
		}
	}

	// Send-gated logging controls
	// TCP_GATE_LOG values:
	//   off/0/false -> disable send-gated logs
	//   debug       -> log at debug level
	//   info/1/true -> log at info (default)
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("TCP_GATE_LOG"))); v != "" {
		switch v {
		case "off", "0", "false", "no":
			b.gateLogDisabled = true
		case "debug":
			b.gateLogDebug = true
		case "info", "1", "true", "yes":
			// default; keep info
		default:
			// unknown -> default
		}
	}

	// Log the creation of the TCP bridge
	logging.Infof("Creating TCP bridge: lifetime=%v, ackDelay=%v, reasmCap=%d, errSignal=%s",
		b.lifetime, b.ackDelay, b.reasmCap, b.errorSignal)

	// Default per-flow pending cap (bytes) before host connect completes
	b.defaultPendCap = 64 * 1024
	if v := strings.TrimSpace(os.Getenv("TCP_PEND_CAP_BYTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			b.defaultPendCap = n
		}
	}

	go b.reaper()
	// Start connection health monitor
	go b.monitorConnectionHealth()
	return b
}

// sendToGuest attempts to deliver a synthesized packet toward the guest.
// If a per-flow scheduler is available, route via the FlowManager to gain
// backpressure-aware retries on WG queue-full; otherwise, send inline via
// the parent's processor. Returns true if the packet was accepted for send.
func (b *tcpBridge) sendToGuest(f *tcpFlow, pkt []byte) bool {
	if pkt == nil {
		return false
	}
	// Prefer per-flow scheduler; if enqueue fails (queue full), fall back to inline send.
	if b.parent != nil && b.parent.processor != nil {
		if err := b.parent.processor.ProcessPacket(WrapPacket(pkt)); err == nil {
			return true
		}
	}
	return false
}

// monitorConnectionHealth periodically checks for stalled connections and resets them.
// This helps prevent indefinite stalls that can exhaust resources.
func (b *tcpBridge) monitorConnectionHealth() {
	// Check every 15 seconds for stalled connections
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Configure stall detection parameters
	stallThreshold := 30 * time.Second // Consider connection stalled after 30s without ACK progress
	minInFlight := 1024                // Only check connections with at least 1KB in flight

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.mu.RLock()
			now := time.Now()
			stalledFlows := make([]string, 0)

			// Identify stalled flows
			for k, f := range b.flows {
				// Only check established connections with in-flight data
				if f.state == tcpEstablished {
					inFlight := int(f.serverNxt - f.sndUna)
					idleTime := now.Sub(f.lastAckTime)

					// Connection is stalled if:
					// 1. It has meaningful in-flight data
					// 2. No ACK progress for a significant period
					if inFlight >= minInFlight && idleTime >= stallThreshold {
						stalledFlows = append(stalledFlows, k)
						logging.Warnf("Stalled connection detected: flow=%s idle=%v inFlight=%d bytes",
							k, idleTime.Round(time.Second), inFlight)
					}
				}
			}
			b.mu.RUnlock()

			// Reset stalled flows
			for _, k := range stalledFlows {
				logging.Warnf("Health monitor resetting stalled flow: %s", k)
				b.removeFlow(k)
			}

			// Log health check summary if any issues found
			if len(stalledFlows) > 0 {
				logging.Infof("Connection health check: reset %d stalled flows", len(stalledFlows))
			}
		}
	}
}

// SetMSSClamp updates the runtime MSS clamp (bytes). 0 disables the clamp.
func (b *tcpBridge) SetMSSClamp(n int) {
	if n < 0 {
		n = 0
	}
	b.mssClamp = n
	logging.Infof("TCP MSS clamp set to %d (0=disabled)", n)
}

// SetPaceUS updates the per-segment pacing interval in microseconds (0 disables).
func (b *tcpBridge) SetPaceUS(us int) {
	if us < 0 {
		us = 0
	}
	b.paceUS = us
	logging.Infof("TCP pacing set to %d us (0=disabled)", us)
}

func (b *tcpBridge) stop() {
	close(b.stopCh)
	// Snapshot keys, then remove flows using removeFlow to ensure all
	// per-flow goroutines and scheduler state are cleaned up.
	b.mu.Lock()
	keys := make([]string, 0, len(b.flows))
	for k := range b.flows {
		keys = append(keys, k)
	}
	b.mu.Unlock()
	for _, k := range keys {
		b.removeFlow(k)
	}
}

func (b *tcpBridge) Name() string { return "tcp" }

func (b *tcpBridge) HandleOutbound(pkt []byte) error {
	if len(pkt) < 40 { // IPv4(20)+TCP(20)
		return fmt.Errorf("tcp: packet too short")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return fmt.Errorf("tcp: invalid IHL/length")
	}

	var srcIP, dstIP [4]byte
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])

	tcpOff := ihl
	dataOff := int((pkt[tcpOff+12] >> 4) * 4)
	if len(pkt) < tcpOff+dataOff {
		return fmt.Errorf("tcp: header length invalid")
	}
	flags := pkt[tcpOff+13]
	seq := binary.BigEndian.Uint32(pkt[tcpOff+4 : tcpOff+8])
	ack := binary.BigEndian.Uint32(pkt[tcpOff+8 : tcpOff+12])
	srcPort := binary.BigEndian.Uint16(pkt[tcpOff : tcpOff+2])
	dstPort := binary.BigEndian.Uint16(pkt[tcpOff+2 : tcpOff+4])
	payload := pkt[tcpOff+dataOff:]

	key := fmt.Sprintf("%d.%d.%d.%d:%d-%d.%d.%d.%d:%d",
		srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort,
		dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort,
	)

	// SYN: create flow and respond with SYN-ACK after dialing host
	const (
		fFIN = 0x01
		fSYN = 0x02
		fRST = 0x04
		fPSH = 0x08
		fACK = 0x10
	)

	if flags&fRST != 0 {
		// Remove flow if exists
		b.removeFlow(key)
		return nil
	}

	// Fast path: lookup existing flow under read lock
	b.mu.RLock()
	flow := b.flows[key]
	b.mu.RUnlock()
	if flow == nil && (flags&fSYN) != 0 && (flags&fACK) == 0 {
		// Early cap check
		if b.maxFlows > 0 {
			b.mu.RLock()
			cur := len(b.flows)
			b.mu.RUnlock()
			if cur >= b.maxFlows {
				rst := buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, 0x04|0x10, nil)
				if rst != nil && b.parent.processor != nil {
					_ = b.parent.processor.ProcessPacket(WrapPacket(rst))
				}
				return fmt.Errorf("tcp: flow cap reached")
			}
		}
		// Fast pre-dial to detect immediate refusal before emitting SYN-ACK; fallback to async otherwise
		var preConn *net.TCPConn
		{
			raddr := &net.TCPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
			fastT := 5 * time.Millisecond
			if v := strings.TrimSpace(os.Getenv("TCP_FAST_DIAL_MS")); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n >= 0 {
					fastT = time.Duration(n) * time.Millisecond
				}
			}
			d := net.Dialer{Timeout: fastT}
			if c, err := d.Dial("tcp", raddr.String()); err == nil {
				if tc, ok := c.(*net.TCPConn); ok {
					preConn = tc
				} else {
					_ = c.Close()
				}
			} else {
				if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
					// Hard failure: signal guest per policy and abort without SYN-ACK
					if b.parent != nil && b.parent.processor != nil {
						switch b.errorSignal {
						case "icmp":
							if icmp := buildICMPUnreachable(dstIP, srcIP, 1, pkt); icmp != nil {
								_ = b.parent.processor.ProcessPacket(WrapPacket(icmp))
							}
						case "rst":
							rst := buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, 0x04|0x10, nil)
							if rst != nil {
								_ = b.parent.processor.ProcessPacket(WrapPacket(rst))
							}
						case "none":
						}
					}
					atomic.AddUint64(&b.parent.metrics.Errors, 1)
					return nil
				}
			}
		}
		serverISN := rand.Uint32()
		candidate := &tcpFlow{
			key:        key,
			srcIP:      srcIP,
			dstIP:      dstIP,
			srcPort:    srcPort,
			dstPort:    dstPort,
			conn:       preConn,
			connecting: preConn == nil,
			clientISN:  seq,
			serverISN:  serverISN,
			clientNxt:  seq + 1,
			serverNxt:  serverISN + 1,
			sndUna:     serverISN + 1,
			state:      tcpSynRcvd,
			ooo:        nil,
			tos:        pkt[1],
			ttl:        pkt[8],
			ackCh:      make(chan struct{}, 1),
			pendCap:    b.defaultPendCap,
		}
		// Default MSS from effective MTU (respects runtime override)
		defMSS := 1460
		if b.parent != nil {
			mtu := b.parent.EffectiveMTU()
			if mtu <= 0 {
				mtu = b.parent.config.MTU
			}
			v := mtu - 40
			if v < 536 {
				v = 536
			}
			if v > 1460 {
				v = 1460
			}
			defMSS = v
		}
		// Apply MSS clamp (if configured) and MTU-derived cap
		eff := defMSS
		if b.mssClamp > 0 && b.mssClamp < eff {
			eff = b.mssClamp
		}
		candidate.clientMSS = uint16(eff)
		candidate.mss = eff
		// Parse client SYN options for MSS, Window Scale, and SACK
		if dataOff > 20 {
			opts := pkt[tcpOff+20 : tcpOff+dataOff]
			for i := 0; i < len(opts); {
				kind := opts[i]
				switch kind {
				case 0: // EOL
					i = len(opts)
					continue
				case 1: // NOP
					i++
					continue
				default:
					if i+1 >= len(opts) {
						i = len(opts)
						continue
					}
					l := int(opts[i+1])
					if l < 2 || i+l > len(opts) {
						i = len(opts)
						continue
					}
					if kind == 2 && l == 4 { // MSS
						m := int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
						if b.mssClamp > 0 && m > b.mssClamp {
							m = b.mssClamp
						}
						if m > eff {
							m = eff
						}
						candidate.clientMSS = uint16(m)
						candidate.mss = m
					} else if kind == 3 && l == 3 { // Window scale
						candidate.wsIn = opts[i+2]
					} else if kind == 4 && l == 2 { // SACK Permitted
						candidate.sackPermitted = true
					}
					i += l
				}
			}
		}
		candidate.touch()
		candidate.lastAckTime = time.Now()
		// Congestion control initialization (default enable NewReno; disable with TCP_CC=off)
		if algo := strings.TrimSpace(os.Getenv("TCP_CC")); strings.ToLower(algo) == "off" {
			// disabled
		} else {
			if algo == "" {
				algo = "newreno"
			}
			candidate.ccEnabled = true
			candidate.cc = newCongestionControl(algo, candidate.mss)
		}
		// Insert under write lock with double-check
		b.mu.Lock()
		if exist := b.flows[key]; exist != nil {
			b.mu.Unlock()
			flow = exist
		} else {
			b.flows[key] = candidate
			b.mu.Unlock()
			flow = candidate
			// Kick off async host dial; on success, attach conn, emit SYN-ACK (if not already), start reader, and flush pending
			if flow.connecting {
				go func(f *tcpFlow) {
					atomic.AddUint64(&b.dialStart, 1)
					atomic.AddInt64(&b.dialInflight, 1)
					raddr := &net.TCPAddr{IP: net.IP(f.dstIP[:]), Port: int(f.dstPort)}
					conn, err := net.DialTCP("tcp", nil, raddr)
					if err != nil {
						// Signal guest per policy
						if b.parent != nil && b.parent.processor != nil {
							switch b.errorSignal {
							case "icmp":
								if icmp := buildICMPUnreachable(f.dstIP, f.srcIP, 1, pkt); icmp != nil {
									_ = b.parent.processor.ProcessPacket(WrapPacket(icmp))
								}
							case "rst":
								rst := buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, 0, f.clientISN+1, 0x04|0x10, nil)
								if rst != nil {
									_ = b.parent.processor.ProcessPacket(WrapPacket(rst))
								}
							case "none":
							}
						}
						atomic.AddUint64(&b.dialFail, 1)
						atomic.AddUint64(&b.parent.metrics.Errors, 1)
						atomic.AddInt64(&b.dialInflight, -1)
						// Remove the flow on dial failure
						b.removeFlow(f.key)
						return
					}
					// Configure socket options
					_ = conn.SetNoDelay(true)
					_ = conn.SetKeepAlive(true)
					_ = conn.SetKeepAlivePeriod(30 * time.Second)
					if v := strings.TrimSpace(os.Getenv("TCP_SOCK_RCVBUF")); v != "" {
						if n, err := strconv.Atoi(v); err == nil && n > 0 {
							_ = conn.SetReadBuffer(n)
						}
					}
					if v := strings.TrimSpace(os.Getenv("TCP_SOCK_SNDBUF")); v != "" {
						if n, err := strconv.Atoi(v); err == nil && n > 0 {
							_ = conn.SetWriteBuffer(n)
						}
					}
					f.conn = conn
					f.connecting = false
					f.lastAckTime = time.Now()
					atomic.AddUint64(&b.dialOk, 1)
					atomic.AddInt64(&b.dialInflight, -1)
					// Send SYN-ACK now that dial succeeded (with MSS/WS/SACK options) unless already sent
					{
						mss := uint16(1460)
						effMTU := 1500
						if b.parent != nil {
							effMTU = b.parent.EffectiveMTU()
							if effMTU <= 0 {
								effMTU = b.parent.config.MTU
							}
							val := effMTU - 40
							if val < 536 {
								val = 536
							}
							if val > 1460 {
								val = 1460
							}
							if b.mssClamp > 0 && val > b.mssClamp {
								val = b.mssClamp
							}
							mss = uint16(val)
						} else if b.mssClamp > 0 && int(mss) > b.mssClamp {
							mss = uint16(b.mssClamp)
						}
						synOpts := make([]byte, 0, 8)
						synOpts = append(synOpts, 2, 4, byte(mss>>8), byte(mss))
						wsOut := uint8(7)
						if v := strings.TrimSpace(os.Getenv("TCP_WS_OUT")); v != "" {
							if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 14 {
								wsOut = uint8(n)
							}
						}
						f.wsOut = wsOut
						synOpts = append(synOpts, 3, 3, byte(wsOut))
						if f.sackPermitted || strings.TrimSpace(os.Getenv("TCP_ENABLE_SACK")) == "1" {
							synOpts = append(synOpts, 4, 2)
						}
						synAck := buildIPv4TCPOpts(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverISN, f.clientISN+1, fSYN|fACK, nil, synOpts)
						if !f.synAckSent {
							f.synAckSent = true
							if b.logHandshake {
								logging.Infof("TCP SYN-ACK MSS: flow=%s effMTU=%d clamp=%d clientMSS=%d advMSS=%d",
									f.key, effMTU, b.mssClamp, int(f.clientMSS), int(mss))
							}
							_ = b.sendToGuest(f, synAck)
						}
					}
					// Start reader now that conn exists
					go b.reader(f)
					// Flush any pre-connect pending data and contiguous reassembly
					b.flushPending(f)
				}(flow)
			}
			// Emit SYN-ACK immediately; if dial later succeeds, the goroutine will avoid duplicate send.
			if !flow.synAckSent {
				mss := uint16(1460)
				effMTU := 1500
				if b.parent != nil {
					effMTU = b.parent.EffectiveMTU()
					if effMTU <= 0 {
						effMTU = b.parent.config.MTU
					}
					val := effMTU - 40
					if val < 536 {
						val = 536
					}
					if val > 1460 {
						val = 1460
					}
					if b.mssClamp > 0 && val > b.mssClamp {
						val = b.mssClamp
					}
					mss = uint16(val)
				} else if b.mssClamp > 0 && int(mss) > b.mssClamp {
					mss = uint16(b.mssClamp)
				}
				synOpts := make([]byte, 0, 8)
				synOpts = append(synOpts, 2, 4, byte(mss>>8), byte(mss))
				wsOut := uint8(7)
				if v := strings.TrimSpace(os.Getenv("TCP_WS_OUT")); v != "" {
					if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 14 {
						wsOut = uint8(n)
					}
				}
				flow.wsOut = wsOut
				synOpts = append(synOpts, 3, 3, byte(wsOut))
				if flow.sackPermitted || strings.TrimSpace(os.Getenv("TCP_ENABLE_SACK")) == "1" {
					synOpts = append(synOpts, 4, 2)
				}
				synAck := buildIPv4TCPOpts(dstIP, srcIP, dstPort, srcPort, serverISN, seq+1, fSYN|fACK, nil, synOpts)
				if b.logHandshake {
					logging.Infof("TCP SYN-ACK MSS: flow=%s effMTU=%d clamp=%d clientMSS=%d advMSS=%d",
						key, effMTU, b.mssClamp, int(flow.clientMSS), int(mss))
				}
				_ = b.sendToGuest(flow, synAck)
				flow.synAckSent = true
			}
			atomic.AddUint64(&b.metrics.ConnectionsCreated, 1)
			atomic.AddUint64(&b.parent.metrics.ConnectionsCreated, 1)
			// If already connected (fast pre-dial), start reader immediately
			if flow.conn != nil {
				go b.reader(flow)
			}
			return nil
		}
	}

	if flow == nil {
		// No flow: send RST per RFC depending on ACK flag
		const fACK = 0x10
		const fRST = 0x04
		if (flags & fACK) != 0 {
			// RST with seq = ack
			rst := buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, ack, 0, fRST, nil)
			if rst != nil {
				_ = b.sendToGuest(flow, rst)
			}
		} else {
			// RST|ACK with ack = seq + len
			segLen := uint32(len(payload))
			// SYN/FIN consume 1 sequence number
			if (flags & 0x02) != 0 { // SYN
				segLen++
			}
			if (flags & 0x01) != 0 { // FIN
				segLen++
			}
			rst := buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+segLen, fRST|fACK, nil)
			if rst != nil {
				_ = b.sendToGuest(flow, rst)
			}
		}
		return nil
	}

	flow.touch()

	switch flow.state {
	case tcpSynRcvd:
		if (flags&fACK) != 0 && ack == flow.serverISN+1 {
			flow.state = tcpEstablished
			// Seed advertised window from this ACK
			wnd := uint32(binary.BigEndian.Uint16(pkt[tcpOff+14 : tcpOff+16]))
			if flow.wsIn > 0 {
				wnd = wnd << flow.wsIn
			}
			if wnd == 0 {
				wnd = 65535
			}
			flow.advWnd = wnd
		}
		return nil
	case tcpEstablished:
		// Handle ACK updates and possible FIN teardown
		if (flags & fACK) != 0 {
			// dupACK detection
			if ack == flow.sndUna && len(payload) == 0 {
				flow.dupAckCnt++
				atomic.AddUint64(&b.ackDup, 1)
			} else {
				flow.dupAckCnt = 0
			}
			if ack != 0 && ack <= flow.serverNxt && ack > flow.sndUna {
				prevUna := flow.sndUna
				flow.sndUna = ack
				flow.lastAckTime = time.Now()
				atomic.AddUint64(&b.ackAdv, 1)
				// drop acknowledged segments from txQueue and update RTT/RTO
				now := time.Now()
				flow.txMu.Lock()
				for len(flow.txQueue) > 0 {
					head := flow.txQueue[0]
					if head.seq+uint32(len(head.data)) <= ack {
						// RTT sample (Karn's algorithm: only if not retransmitted)
						if head.retries == 0 && !head.sentAt.IsZero() {
							sample := now.Sub(head.sentAt)
							if sample > 0 {
								if flow.srtt == 0 {
									// RFC 6298 init
									flow.srtt = sample
									flow.rttvar = sample / 2
								} else {
									// RFC 6298 update
									err := flow.srtt - sample
									if err < 0 {
										err = -err
									}
									flow.rttvar = (3*flow.rttvar + err) / 4
									flow.srtt = (7*flow.srtt + sample) / 8
								}
								// RTO = SRTT + 4*RTTVAR, with bounds
								rto := flow.srtt + 4*flow.rttvar
								if rto < 200*time.Millisecond {
									rto = 200 * time.Millisecond
								}
								if rto > 60*time.Second {
									rto = 60 * time.Second
								}
								flow.rto = rto
							}
						}
						flow.txQueue = flow.txQueue[1:]
					} else {
						break
					}
				}
				flow.txMu.Unlock()
				// Notify CC of ACKed bytes
				if flow.ccEnabled && flow.cc != nil {
					diff := int(ack - prevUna)
					if diff > 0 {
						flow.cc.OnAck(diff)
					}
				}
				// trimmed: per-flow verbose ack debug removed
				// Notify sender waiters
				select {
				case flow.ackCh <- struct{}{}:
				default:
				}
			}
			// Track previous window to detect pure window updates that should wake senders.
			prevWnd := flow.advWnd
			wnd := uint32(binary.BigEndian.Uint16(pkt[tcpOff+14 : tcpOff+16]))
			if flow.wsIn > 0 {
				wnd = wnd << flow.wsIn
			}
			flow.advWnd = wnd
			// If the peer opened its window without advancing ACK, wake senders.
			if wnd > prevWnd {
				// Treat as progress for idle tracking to avoid false ACK-idle.
				flow.lastAckTime = time.Now()
				// Count as window-only update if ACK did not advance
				if ack <= flow.sndUna {
					atomic.AddUint64(&b.ackWndOnly, 1)
				}
				select {
				case flow.ackCh <- struct{}{}:
				default:
				}
			}
			if b.ackTrace {
				class := "adv"
				if ack == flow.sndUna && len(payload) == 0 {
					class = "dup"
				} else if ack <= flow.sndUna && wnd > prevWnd {
					class = "wnd"
				}
				logging.Infof("TCP ACK trace: flow=%s class=%s ack=%d sndUna=%d nxt=%d wnd=%d ws=%d txq=%d",
					flow.key, class, ack, flow.sndUna, flow.serverNxt, flow.advWnd, flow.wsIn, len(flow.txQueue))
			}
			// Parse SACK blocks if any and SACK permitted
			if flow.sackPermitted || strings.TrimSpace(os.Getenv("TCP_ENABLE_SACK")) == "1" {
				if dataOff > 20 {
					opts := pkt[tcpOff+20 : tcpOff+dataOff]
					parseSACKBlocks(flow, opts)
						// trimmed: verbose SACK block debug removed
				}
			}
			if len(payload) == 0 {
				if flow.finSent && ack == flow.serverNxt {
					b.removeFlow(flow.key)
					return nil
				}
				// Pure ACK otherwise falls through
			}
			// Fast retransmit on 3 dupACKs
			if flow.dupAckCnt >= 3 {
				flow.dupAckCnt = 0
				// Enter SACK recovery and retransmit a hole if available
				flow.sackRecovery = true
				if flow.serverNxt > 0 {
					flow.recover = flow.serverNxt - 1
				}
				b.retransmitNextHole(flow)
			}
			// Partial ACK handling: in recovery, keep sending next hole
			if flow.sackRecovery {
				if ack >= flow.recover {
					flow.sackRecovery = false
				} else {
					b.retransmitNextHole(flow)
				}
			}
		}

		// Out-of-order tolerance: duplicate or future segments -> send dup ACK
		if seq < flow.clientNxt {
			// Duplicate segment; ACK current next expected
			dupAck := buildIPv4TCP(flow.dstIP, flow.srcIP, flow.dstPort, flow.srcPort, flow.serverNxt, flow.clientNxt, fACK, nil)
			_ = b.sendToGuest(flow, dupAck)
			return nil
		}
		if seq > flow.clientNxt {
			// Future segment; store for reassembly with simple merging
			flow.mu.Lock()
			cp := make([]byte, len(payload))
			copy(cp, payload)
			inserted := false
			for i := 0; i < len(flow.ooo); i++ {
				s := &flow.ooo[i]
				if seq+uint32(len(cp)) < s.seq { // insert before
					flow.ooo = append(flow.ooo[:i], append([]struct {
						seq  uint32
						data []byte
					}{{seq: seq, data: cp}}, flow.ooo[i:]...)...)
					inserted = true
					break
				}
				// overlap/adjacent
				if seq <= s.seq+uint32(len(s.data)) && seq+uint32(len(cp)) >= s.seq {
					// merge into s
					start := minU32(seq, s.seq)
					end := maxU32(seq+uint32(len(cp)), s.seq+uint32(len(s.data)))
					merged := make([]byte, int(end-start))
					copy(merged[s.seq-start:], s.data)
					copy(merged[seq-start:], cp)
					s.seq = start
					s.data = merged
					// merge following overlaps
					j := i + 1
					for j < len(flow.ooo) {
						ns := flow.ooo[j]
						if s.seq+uint32(len(s.data)) < ns.seq {
							break
						}
						newEnd := maxU32(s.seq+uint32(len(s.data)), ns.seq+uint32(len(ns.data)))
						if int(newEnd-s.seq) > len(s.data) {
							grow := make([]byte, int(newEnd-s.seq))
							copy(grow, s.data)
							s.data = grow
						}
						copy(s.data[ns.seq-s.seq:], ns.data)
						flow.ooo = append(flow.ooo[:j], flow.ooo[j+1:]...)
					}
					inserted = true
					break
				}
			}
			if !inserted {
				flow.ooo = append(flow.ooo, struct {
					seq  uint32
					data []byte
				}{seq: seq, data: cp})
			}
			flow.futureBytes += len(cp)
			if flow.futureBytes > b.reasmCap {
				flow.ooo = nil
				flow.futureBytes = 0
			}
			flow.mu.Unlock()

			// Request retransmit with current ACK
			dupAck := buildIPv4TCP(flow.dstIP, flow.srcIP, flow.dstPort, flow.srcPort, flow.serverNxt, flow.clientNxt, fACK, nil)
			_ = b.sendToGuest(flow, dupAck)
			return nil
		}

		// In-order data
		if len(payload) > 0 {
			// Log the payload for debugging
			logging.Debugf("TCP bridge handling client->server data: %d bytes, data: %q",
				len(payload), string(payload[:minInt(len(payload), 50)]))

			// If not yet connected, enqueue into bounded pending buffer and ACK
			if flow.conn == nil {
				flow.pendMu.Lock()
				if flow.pendCap <= 0 || flow.pendingBytes+len(payload) <= flow.pendCap {
					cp := append([]byte(nil), payload...)
					flow.pending = append(flow.pending, cp)
					flow.pendingBytes += len(cp)
					atomic.AddUint64(&b.pendEnq, 1)
				} else {
					atomic.AddUint64(&b.pendDrop, 1)
					// Do not advance clientNxt for dropped bytes; let client retransmit later
					flow.pendMu.Unlock()
					// Send immediate ACK for already accepted bytes only
					b.scheduleAck(flow)
					return nil
				}
				flow.pendMu.Unlock()
				// Accept bytes from client: advance ack and ACK back (even before server write)
				flow.clientNxt += uint32(len(payload))
				b.scheduleAck(flow)
				return nil
			}

			if n, err := flow.conn.Write(payload); err != nil {
				atomic.AddUint64(&b.parent.metrics.Errors, 1)
				logging.Errorf("TCP bridge write error: %v", err)
				return fmt.Errorf("tcp: write: %w", err)
			} else {
				atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
				atomic.AddUint64(&b.metrics.PacketsSent, 1)
				atomic.AddUint64(&b.parent.metrics.BytesSent, uint64(n))
				atomic.AddUint64(&b.parent.metrics.PacketsSent, 1)
				logging.Debugf("TCP bridge successfully wrote %d bytes to server", n)
			}
			flow.clientNxt += uint32(len(payload))
			// Flush any contiguous buffered segments
			flow.mu.Lock()
			for len(flow.ooo) > 0 {
				s := flow.ooo[0]
				if s.seq != flow.clientNxt {
					break
				}
				if n, err := flow.conn.Write(s.data); err != nil {
					flow.mu.Unlock()
					atomic.AddUint64(&b.parent.metrics.Errors, 1)
					return fmt.Errorf("tcp: write (reassembly): %w", err)
				} else {
					atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
					atomic.AddUint64(&b.metrics.PacketsSent, 1)
					atomic.AddUint64(&b.parent.metrics.BytesSent, uint64(n))
					atomic.AddUint64(&b.parent.metrics.PacketsSent, 1)
					flow.toSrvBytes += uint64(n)
					flow.toSrvPkts += 1
				}
				flow.ooo = flow.ooo[1:]
				flow.futureBytes -= len(s.data)
				flow.clientNxt += uint32(len(s.data))
			}
			flow.mu.Unlock()
			// delayed ACK
			b.scheduleAck(flow)
		}
		if (flags & fFIN) != 0 {
			// Client closing; FIN consumes one seq
			if seq == flow.clientNxt {
				flow.clientNxt += 1
			}
			if flow.conn != nil {
				_ = flow.conn.CloseWrite()
			}
			finAck := buildIPv4TCP(flow.dstIP, flow.srcIP, flow.dstPort, flow.srcPort, flow.serverNxt, flow.clientNxt, fACK, nil)
			_ = b.sendToGuest(flow, finAck)
			flow.state = tcpFinWait
		}
		return nil
	case tcpFinWait:
		// Await final ACK from client; if received, close
		if (flags&fACK) != 0 && (!flow.finSent || ack == flow.serverNxt) {
			if flow.finSent && ack == flow.serverNxt {
				b.removeFlow(flow.key)
			}
			// else still waiting for host side close
		}
		return nil
	default:
		return nil
	}
}

func (b *tcpBridge) reader(f *tcpFlow) {
	buf := make([]byte, 32*1024)
	// Initialize retransmission timer parameters
	f.txMu.Lock()
	if f.rto == 0 {
		f.rto = 1 * time.Second
	}
	if f.rtoStop == nil {
		f.rtoStop = make(chan struct{})
	}
	f.txMu.Unlock()
	// Start simple RTO goroutine
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-f.rtoStop:
				return
			case <-ticker.C:
				f.txMu.Lock()
				if len(f.txQueue) == 0 {
					f.txMu.Unlock()
					continue
				}
				// Find first timed-out unsacked segment (skip SACKed head)
				idx := -1
				now := time.Now()
				for i := 0; i < len(f.txQueue); i++ {
					s := f.txQueue[i]
					if s.seq+uint32(len(s.data)) <= f.sndUna {
						continue
					}
					if isSACKed(f, s.seq, s.seq+uint32(len(s.data))) {
						continue
					}
					if s.sentAt.IsZero() || now.Sub(s.sentAt) > f.rto {
						idx = i
						break
					}
				}
				if idx >= 0 {
					seg := f.txQueue[idx]
					f.txQueue[idx].sentAt = now
					f.txQueue[idx].retries++
					f.txQueue[idx].rtx = true
					// Exponential backoff up to ~2s
					if f.rto < 2*time.Second {
						f.rto *= 2
						if f.rto > 2*time.Second {
							f.rto = 2 * time.Second
						}
					}
					// trimmed: per-flow RTO debug removed
					f.txMu.Unlock()

					// Track this flow as being in RTO state
					b.trackRTOFlow(f.key)

					pkt := buildIPv4TCPWithIP(f.dstIP, f.srcIP, f.dstPort, f.srcPort,
						seg.seq, f.clientNxt, 0x18, seg.data, f.tos, f.ttl)
					if pkt != nil {
						if !b.sendToGuest(f, pkt) {
							// fallthrough: nothing to do; metrics/cc updated below
						}
						if f.ccEnabled && f.cc != nil {
							f.cc.OnLoss(true)
						}
						atomic.AddUint64(&b.rtoCount, 1)
					}
				} else {
					f.txMu.Unlock()
				}
			}
		}
	}()
	for {
		// Window/cwnd-based backpressure: if there is no room to send
		// additional bytes to the client (advWnd/cwnd fully consumed by
		// in-flight), wait for ACK/window updates before reading more from the
		// server socket. This prevents unbounded read buffering and maps
		// downstream stalls back to the upstream server.
		inFlight := int(f.serverNxt - f.sndUna)
		allowed := int(f.advWnd) - inFlight
		if f.ccEnabled && f.cc != nil {
			cw := f.cc.Cwnd()
			if cw < 1 {
				cw = f.mss * 2
			}
			if (cw - inFlight) < allowed {
				allowed = cw - inFlight
			}
		}
		// If configured, and no ACK progress for a while with meaningful in-flight
		// data, avoid reading from server to prevent amplification during
		// downstream blackholes. Gate only when inFlight exceeds threshold
		// (defaults to ~1 MSS) to avoid penalizing tiny exchanges.
		if b.ackIdleGate > 0 && inFlight > 0 {
			minInflight := b.ackIdleMinInflight
			if minInflight <= 0 {
				minInflight = f.mss
			}
			if inFlight >= minInflight {
				idle := time.Since(f.lastAckTime)
				if idle >= b.ackIdleGate {
					// Always log ACK idle conditions (not just in debug mode)
					// but throttle to avoid log spam
					f.gateMu.Lock()
					now := time.Now()
					if f.lastGateLog.IsZero() || now.Sub(f.lastGateLog) >= 10*time.Second {
						logging.Infof("TCP ACK-idle detected: flow=%s idle=%v inFlight=%d rto=%v",
							f.key, idle.Round(time.Second), inFlight, f.rto)
						f.lastGateLog = now
					}
					f.gateMu.Unlock()

					select {
					case <-f.ackCh:
					case <-time.After(minDur(250*time.Millisecond, f.rto)):
					}
					// If a hard fail threshold is configured and exceeded, actively
					// reset the flow toward the client and tear it down to avoid
					// indefinite stalls consuming resources.
					if b.ackIdleFail > 0 && time.Since(f.lastAckTime) >= b.ackIdleFail {
						if b.errorSignal == "rst" || b.errorSignal == "icmp" {
							rst := buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x14, nil) // RST|ACK
							if rst != nil {
								_ = b.sendToGuest(f, rst)
							}
						}
						logging.Warnf("TCP ACK-idle failure: resetting stalled flow %s after %v idle (inFlight=%d, lastAck=%d, serverNxt=%d)",
							f.key, time.Since(f.lastAckTime).Round(time.Second), inFlight, f.lastAck, f.serverNxt)
						b.removeFlow(f.key)
						return
					}
					continue
				}
			}
		}
		if allowed <= 0 {
			select {
			case <-f.ackCh:
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		_ = f.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := f.conn.Read(buf)
		// Process any data we received, even if there was an error
		if n > 0 {
			f.touch()
			payload := make([]byte, n)
			copy(payload, buf[:n])

			// Log data being sent back to client with more detail
			logging.Debugf("TCP bridge received %d bytes from server for flow %s, data: %q",
				n, f.key, string(payload[:minInt(n, 50)]))

			// No protocol-specific heuristics; rely on flow control and ACKs.

			// Segment payload according to client MSS and advertised window
			// Compute allowed send window (advWnd - in-flight)
			inFlight := int(f.serverNxt - f.sndUna)
			wnd := int(f.advWnd)
			if wnd <= 0 {
				wnd = 65535
			}
			// Cap segment by MSS and MTU-40 as ultimate safety
			maxMSS := int(f.clientMSS)
			if b.mssClamp > 0 && maxMSS > b.mssClamp {
				maxMSS = b.mssClamp
			}
			mtuCap := 1460
			if b.parent != nil {
				effMTU := b.parent.EffectiveMTU()
				if effMTU <= 0 {
					effMTU = b.parent.config.MTU
				}
				mtuCap = effMTU - 40
				if mtuCap < 536 {
					mtuCap = 536
				}
			}
			baseSegMax := minInt(maxMSS, mtuCap)
			if baseSegMax <= 0 {
				baseSegMax = 1000
			}
			offset := 0
			for offset < n {
				allowed := wnd - inFlight
				// Apply congestion window if enabled
				if f.ccEnabled && f.cc != nil {
					cw := f.cc.Cwnd()
					if cw < 1 {
						cw = f.mss * 2
					}
					allowed = minInt(allowed, cw-inFlight)
				}
				if allowed <= 0 {
					// No window; wait for ACK/window update notification or short timeout
					if f.ackCh != nil {
						select {
						case <-f.ackCh:
						case <-time.After(10 * time.Millisecond):
						}
					} else {
						time.Sleep(2 * time.Millisecond)
					}
					// re-evaluate
					inFlight = int(f.serverNxt - f.sndUna)
					wnd = int(f.advWnd)
					if wnd <= 0 {
						wnd = 65535
					}
					allowed = wnd - inFlight
					if f.ccEnabled && f.cc != nil {
						cw := f.cc.Cwnd()
						if cw < 1 {
							cw = f.mss * 2
						}
						allowed = minInt(allowed, cw-inFlight)
					}
					if allowed <= 0 {
						// Always log flow control issues (not just in debug mode)
						// but with throttling to avoid log spam
						cause := "peer-wnd"
						cw := b.cwndBytes(f)
						if (wnd-inFlight) > 0 && (cw-inFlight) <= 0 {
							cause = "cwnd"
						}
						b.logSendGated(f, cause, wnd, inFlight, cw)
						continue
					}
				}
				segMax := minInt(baseSegMax, allowed)
				if segMax <= 0 {
					segMax = minInt(baseSegMax, n-offset)
				}
				segSize := minInt(segMax, n-offset)
				segPayload := payload[offset : offset+segSize]

				// Always use PSH|ACK for HTTP responses to ensure immediate delivery
				flags := byte(0x18) // PSH|ACK

				// Create the segment with the appropriate flags and TOS/TTL per policy
				tosOut, ttlOut := f.tos, f.ttl
				if b.parent != nil {
					tosOut, ttlOut = b.parent.effTosTTL(f.tos, f.ttl)
				}
				seg := buildIPv4TCPWithIP(f.dstIP, f.srcIP, f.dstPort, f.srcPort,
					f.serverNxt+uint32(offset), f.clientNxt, flags, segPayload, tosOut, ttlOut)

				if seg != nil {
					// trimmed: per-flow send debug removed
					logging.Debugf("TCP bridge sending segment %d-%d of %d bytes to client for flow %s",
						offset, offset+segSize, n, f.key)

					// Enqueue to per-flow scheduler if available; otherwise send inline.
					// When buffer pooling is enabled but pooled packet wrappers are disabled,
					// take a defensive copy to avoid subtle aliasing across async paths.
					out := seg
					if poolingEnabled() && !poolWrapEnabled() {
						out = append([]byte(nil), seg...)
					}
					sent := false
					if b.paceUS > 0 {
						time.Sleep(time.Duration(b.paceUS) * time.Microsecond)
					}
					if !sent {
						if b.sendToGuest(f, out) {
							f.toCliBytes += uint64(segSize)
							f.toCliPkts += 1
						} else {
							logging.Errorf("TCP bridge failed to send packet inline (no scheduler): flow=%s", f.key)
						}
					}
					// Track segment for retransmission
					f.txMu.Lock()
					f.txQueue = append(f.txQueue, struct {
						seq     uint32
						data    []byte
						sentAt  time.Time
						retries int
						rtx     bool
					}{
						seq:     f.serverNxt + uint32(offset),
						data:    append([]byte(nil), segPayload...),
						sentAt:  time.Now(),
						retries: 0,
						rtx:     false,
					})
					// No forced RTO reset; RTO follows RFC 6298 estimates
					f.txMu.Unlock()
					if f.ccEnabled && f.cc != nil {
						f.cc.OnSent(len(segPayload))
					}
				} else {
					logging.Errorf("TCP bridge failed to create segment or processor is nil")
				}

				// No artificial delay between segments; rely on TCP flow control.
				// Track in-flight growth
				inFlight += segSize
				offset += segSize
			}

			// Update sequence number by bytes actually sent
			// 'offset' reflects total bytes segmented and queued
			f.serverNxt += uint32(offset)
		}

		// Handle any error after processing data
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// No data yet, continue listening.
				continue
			}
			// Treat closed/reset connections as terminal and tear down the flow to
			// avoid a tight loop logging "use of closed network connection".
			if errors.Is(err, net.ErrClosed) ||
				strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "connection reset by peer") ||
				strings.Contains(err.Error(), "broken pipe") {
				b.removeFlow(f.key)
				return
			}
			if errors.Is(err, io.EOF) {
				// Graceful close from server: send FIN|ACK and allow client to ACK before teardown.
				fin := buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x01|0x10, nil)
				f.serverNxt += 1
				f.finSent = true
				if fin != nil && b.parent.processor != nil {
					logging.Debugf("TCP bridge sending FIN to client for flow %s", f.key)
					p := WrapPacket(fin)
					_ = b.parent.processor.ProcessPacket(p)
				}
				// Small delay to give client time to ACK
				time.Sleep(50 * time.Millisecond)
				b.removeFlow(f.key)
				return
			}
			logging.Debugf("TCP bridge reader transient error for flow %s: %v", f.key, err)
			continue
		}
		if n == 0 {
			continue
		}
	}
}

// flushPending drains any pre-connect pending client->server data and then
// flushes contiguous reassembly segments once a connection is available.
func (b *tcpBridge) flushPending(f *tcpFlow) {
	if f == nil || f.conn == nil {
		return
	}
	// Drain pending FIFO
	var batches [][]byte
	f.pendMu.Lock()
	if len(f.pending) > 0 {
		batches = append(batches, f.pending...)
		f.pending = nil
		f.pendingBytes = 0
	}
	f.pendMu.Unlock()
	for _, p := range batches {
		if f.conn == nil {
			break
		}
		if n, err := f.conn.Write(p); err == nil {
			atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.metrics.PacketsSent, 1)
			atomic.AddUint64(&b.parent.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.parent.metrics.PacketsSent, 1)
			f.toSrvBytes += uint64(n)
			f.toSrvPkts += 1
			atomic.AddUint64(&b.pendFlush, 1)
		} else {
			atomic.AddUint64(&b.parent.metrics.Errors, 1)
			break
		}
	}
	// Now attempt to flush any contiguous reassembly segments
	f.mu.Lock()
	for len(f.ooo) > 0 {
		s := f.ooo[0]
		if s.seq != f.clientNxt {
			break
		}
		if f.conn == nil {
			break
		}
		if n, err := f.conn.Write(s.data); err != nil {
			f.mu.Unlock()
			atomic.AddUint64(&b.parent.metrics.Errors, 1)
			return
		} else {
			atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.metrics.PacketsSent, 1)
			atomic.AddUint64(&b.parent.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.parent.metrics.PacketsSent, 1)
			f.toSrvBytes += uint64(n)
			f.toSrvPkts += 1
		}
		f.ooo = f.ooo[1:]
		f.futureBytes -= len(s.data)
		f.clientNxt += uint32(len(s.data))
	}
	f.mu.Unlock()
}

func (b *tcpBridge) removeFlow(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f, ok := b.flows[key]; ok {
		logging.Debugf("TCP flow closed %s; toServer bytes=%d pkts=%d, toClient bytes=%d pkts=%d",
			f.key, f.toSrvBytes, f.toSrvPkts, f.toCliBytes, f.toCliPkts)
		if f.conn != nil {
			_ = f.conn.Close()
		}
		if f.rtoStop != nil {
			close(f.rtoStop)
		}
		delete(b.flows, key)
		// (FlowManager removed)
		atomic.AddUint64(&b.metrics.ConnectionsClosed, 1)
		atomic.AddUint64(&b.parent.metrics.ConnectionsClosed, 1)
	}
}

func (b *tcpBridge) reaper() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-t.C:
			cutoff := time.Now().Add(-b.lifetime)
			// Collect expired flow keys under lock, then remove outside the lock.
			b.mu.Lock()
			expired := make([]string, 0)
			for k, f := range b.flows {
				if f.lastActive().Before(cutoff) {
					expired = append(expired, k)
				}
			}
			b.mu.Unlock()
			for _, k := range expired {
				logging.Debugf("TCP flow expired and removed: %s", k)
				b.removeFlow(k)
			}
		}
	}
}

// scheduleAck schedules a delayed ACK for the given flow if one isn't already scheduled.
func (b *tcpBridge) scheduleAck(f *tcpFlow) {
	f.ackMu.Lock()
	if f.ackScheduled {
		f.ackMu.Unlock()
		return
	}
	f.ackScheduled = true
	f.ackMu.Unlock()
	go func() {
		time.Sleep(b.ackDelay)
		f.ackMu.Lock()
		f.ackScheduled = false
		f.ackMu.Unlock()
		ack := buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x10, nil)
		_ = b.sendToGuest(f, ack)
	}()
}

func (f *tcpFlow) touch() {
	f.lastMu.Lock()
	f.lastActivity = time.Now()
	f.lastMu.Unlock()
}

func (f *tcpFlow) lastActive() time.Time {
	f.lastMu.Lock()
	defer f.lastMu.Unlock()
	return f.lastActivity
}

// buildIPv4TCP builds an IPv4+TCP packet with given sequence/ack and flags.
func buildIPv4TCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, nil, 0x00, 64)
}

// buildIPv4TCPOpts allows specifying TCP options (must be padded to 4-byte multiple).
func buildIPv4TCPOpts(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, options []byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, options, 0x00, 64)
}

// buildIPv4TCPWithIP allows specifying IP TOS/TTL without options.
func buildIPv4TCPWithIP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, tos byte, ttl byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, nil, tos, ttl)
}

// buildIPv4TCPOptsWith allows specifying both options and IP TOS/TTL.
func buildIPv4TCPOptsWith(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, options []byte, tos byte, ttl byte) []byte {
	ihl := 20
	thl := 20 + len(options)
	if thl%4 != 0 {
		// pad options to 4-byte multiple
		pad := 4 - (thl % 4)
		options = append(options, make([]byte, pad)...)
		thl += pad
	}
	total := ihl + thl + len(payload)
	pkt := bufMaybePool(total)

	// IPv4 header
	pkt[0] = 0x45
	pkt[1] = tos
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total & 0xff)
	// Identification: incrementing ID to avoid zero-ID issues on some paths
	id := nextIPID()
	pkt[4] = byte(id >> 8)
	pkt[5] = byte(id)
	pkt[6], pkt[7] = 0, 0
	pkt[8] = ttl
	pkt[9] = 6
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	ipcs := calculateChecksum(pkt[:20])
	pkt[10] = byte(ipcs >> 8)
	pkt[11] = byte(ipcs & 0xff)

	// TCP header
	off := 20
	binary.BigEndian.PutUint16(pkt[off:off+2], srcPort)
	binary.BigEndian.PutUint16(pkt[off+2:off+4], dstPort)
	binary.BigEndian.PutUint32(pkt[off+4:off+8], seq)
	binary.BigEndian.PutUint32(pkt[off+8:off+12], ack)
	pkt[off+12] = byte((thl / 4) << 4) // data offset
	pkt[off+13] = flags
	// Window size: choose a large default
	pkt[off+14] = 0xff
	pkt[off+15] = 0xff
	// Checksum later
	// Urgent pointer = 0
	// Options
	copy(pkt[off+20:off+20+len(options)], options)
	copy(pkt[off+thl:], payload)

	// TCP checksum with pseudo-header
	csum := tcpChecksum(pkt[off:off+thl+len(payload)], srcIP, dstIP)
	binary.BigEndian.PutUint16(pkt[off+16:off+18], csum)
	return pkt
}

func tcpChecksum(tcp []byte, srcIP, dstIP [4]byte) uint16 {
	sum := uint32(0)
	var pseudo [12]byte
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(uint16(tcp[len(tcp)-1]) << 8)
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ordered is a minimal constraint for types that support < and > comparisons
// used by the generic min/max helpers below. We keep it local to avoid an
// external dependency on x/exp/constraints.
// Local typed helpers (avoid generics to keep compatibility with older toolchains)
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// --- SACK helpers ---

func parseSACKBlocks(f *tcpFlow, opts []byte) {
	f.sackMu.Lock()
	defer f.sackMu.Unlock()
	// Collect blocks
	blocks := make([]struct{ left, right uint32 }, 0, 4)
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		if kind == 5 && (l-2)%8 == 0 { // SACK
			for j := i + 2; j+7 < i+l; j += 8 {
				left := binary.BigEndian.Uint32(opts[j : j+4])
				right := binary.BigEndian.Uint32(opts[j+4 : j+8])
				if right > left {
					blocks = append(blocks, struct{ left, right uint32 }{left, right})
				}
			}
		}
		i += l
	}
	if len(blocks) == 0 {
		return
	}
	// Merge with existing, normalize and cap size
	all := append([]struct{ left, right uint32 }{}, f.sackList...)
	all = append(all, blocks...)
	// sort by left (simple insertion sort for small N)
	for i := 1; i < len(all); i++ {
		j := i
		for j > 0 && all[j-1].left > all[j].left {
			all[j-1], all[j] = all[j], all[j-1]
			j--
		}
	}
	// merge overlaps
	merged := make([]struct{ left, right uint32 }, 0, len(all))
	for _, b := range all {
		if len(merged) == 0 || b.left > merged[len(merged)-1].right {
			merged = append(merged, b)
		} else if b.right > merged[len(merged)-1].right {
			merged[len(merged)-1].right = b.right
		}
	}
	// cap to last 4 blocks to match typical SACK cache sizes
	if len(merged) > 4 {
		merged = merged[len(merged)-4:]
	}
	f.sackList = merged
}

func isSACKed(f *tcpFlow, left, right uint32) bool {
	f.sackMu.Lock()
	list := append([]struct{ left, right uint32 }{}, f.sackList...)
	f.sackMu.Unlock()
	for _, b := range list {
		if left >= b.left && right <= b.right {
			return true
		}
	}
	return false
}

// --- RFC 6675 simplified helpers ---

func (b *tcpBridge) retransmitNextHole(f *tcpFlow) {
	// Compute pipe (bytes in flight not SACKed)
	f.txMu.Lock()
	inFlight := 0
	for _, s := range f.txQueue {
		if s.seq+uint32(len(s.data)) <= f.sndUna {
			continue
		}
		if isSACKed(f, s.seq, s.seq+uint32(len(s.data))) {
			continue
		}
		inFlight += len(s.data)
	}
	f.pipeBytes = inFlight
	cw := b.cwndBytes(f)
	budget := cw - inFlight
	if budget < 1 {
		f.txMu.Unlock()
		return
	}
	// Find first unsacked, unacked hole segment
	idx := -1
	for i := 0; i < len(f.txQueue); i++ {
		s := f.txQueue[i]
		if s.seq+uint32(len(s.data)) <= f.sndUna {
			continue
		}
		if isSACKed(f, s.seq, s.seq+uint32(len(s.data))) {
			continue
		}
		idx = i
		break
	}
	if idx < 0 {
		f.txMu.Unlock()
		return
	}
	seg := f.txQueue[idx]
	// Mark retransmit
	f.txQueue[idx].sentAt = time.Now()
	f.txQueue[idx].retries++
	f.txQueue[idx].rtx = true
	f.txMu.Unlock()

	tosOut, ttlOut := f.tos, f.ttl
	if b.parent != nil {
		tosOut, ttlOut = b.parent.effTosTTL(f.tos, f.ttl)
	}
	pkt := buildIPv4TCPWithIP(f.dstIP, f.srcIP, f.dstPort, f.srcPort,
		seg.seq, f.clientNxt, 0x18, seg.data, tosOut, ttlOut)
	if pkt != nil {
		_ = b.sendToGuest(f, pkt)
		if f.ccEnabled && f.cc != nil {
			f.cc.OnLoss(false)
		}
	}
}

func (b *tcpBridge) cwndBytes(f *tcpFlow) int {
	if f.ccEnabled && f.cc != nil {
		cw := f.cc.Cwnd()
		if cw < f.mss {
			cw = f.mss
		}
		return cw
	}
	// Fallback to peer's advertised window when CC is disabled
	if f.advWnd > 0 {
		return int(f.advWnd)
	}
	return 65535
}

// logSendGated emits a throttled message about send gating. To avoid
// log spam, it logs at most once per 5 seconds per flow and includes the number of
// suppressed messages since the previous emission.
func (b *tcpBridge) logSendGated(f *tcpFlow, cause string, advWnd, inFlight, cw int) {
	if b.gateLogDisabled {
		return
	}
	const gateEvery = 5 * time.Second // Increased from 200ms to reduce log volume
	now := time.Now()
	f.gateMu.Lock()
	defer f.gateMu.Unlock()
	if !f.lastGateLog.IsZero() && now.Sub(f.lastGateLog) < gateEvery {
		f.suppressedGates++
		return
	}

	if f.suppressedGates > 0 {
		if b.gateLogDebug {
			logging.Debugf("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d (suppressed=%d)",
				f.key, cause, advWnd, inFlight, cw, f.suppressedGates)
		} else {
			logging.Infof("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d (suppressed=%d)",
				f.key, cause, advWnd, inFlight, cw, f.suppressedGates)
		}
	} else {
		if b.gateLogDebug {
			logging.Debugf("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d",
				f.key, cause, advWnd, inFlight, cw)
		} else {
			logging.Infof("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d",
				f.key, cause, advWnd, inFlight, cw)
		}
	}
	f.lastGateLog = now
	f.suppressedGates = 0
}

// trackRTOFlow adds a flow to the RTO tracking map and checks if we need to dump metrics
func (b *tcpBridge) trackRTOFlow(flowKey string) {
	// Decide whether a dump is needed without holding the lock during the dump
	needDump := false
	b.rtoMu.Lock()
	// Add this flow to the active RTO flows map
	b.rtoActiveFlows[flowKey] = true
	if len(b.rtoActiveFlows) >= 3 {
		if !b.rtoMetricsDumped || time.Since(b.rtoMetricsDumpTime) > 30*time.Second {
			// Mark as dumped and record time under lock
			b.rtoMetricsDumped = true
			b.rtoMetricsDumpTime = time.Now()
			needDump = true
			// Schedule tracking reset to allow future dumps
			time.AfterFunc(10*time.Second, func() {
				b.rtoMu.Lock()
				b.rtoMetricsDumped = false
				b.rtoActiveFlows = make(map[string]bool)
				b.rtoMu.Unlock()
			})
		}
	}
	b.rtoMu.Unlock()
	if needDump {
		b.dumpDetailedMetrics()
	}
}

// dumpDetailedMetrics logs detailed system metrics when multiple flows are in RTO state
// This function is designed to be robust against errors and always complete the metrics dump
func (b *tcpBridge) dumpDetailedMetrics() {
	// Use a separate goroutine with a timeout to ensure the metrics dump completes
	done := make(chan struct{})

	go func() {
		// Always log the end marker, even if there's a panic
		defer func() {
			if r := recover(); r != nil {
				logging.Warnf("Recovered from panic in dumpDetailedMetrics: %v", r)
			}
			logging.Warnf("=== END DETAILED METRICS ===")
			close(done)
		}()

		// Get a snapshot of active flows
		b.mu.RLock()
		activeFlows := make(map[string]*tcpFlow)
		for k, f := range b.flows {
			activeFlows[k] = f
		}
		b.mu.RUnlock()

		// Log the RTO event
		b.rtoMu.Lock()
		rtoFlowKeys := make([]string, 0, len(b.rtoActiveFlows))
		for k := range b.rtoActiveFlows {
			rtoFlowKeys = append(rtoFlowKeys, k)
		}
		b.rtoMu.Unlock()

		logging.Warnf("MULTIPLE RTO EVENTS DETECTED: %d flows in RTO state: %v",
			len(rtoFlowKeys), rtoFlowKeys)

		// Log detailed metrics about each flow in RTO state
		logging.Warnf("=== DETAILED FLOW METRICS FOR RTO EVENT ===")

		// Count how many flows we'll log details for
		detailedFlowCount := 0
		b.rtoMu.Lock()
		for flowKey := range activeFlows {
			if b.rtoActiveFlows[flowKey] {
				detailedFlowCount++
			}
		}
		b.rtoMu.Unlock()

		// If no flows to log details for, log a message
		if detailedFlowCount == 0 {
			logging.Warnf("No active flows in RTO state found in flow map")
		}

		// Log individual flow metrics
		for flowKey, flow := range activeFlows {
			b.rtoMu.Lock()
			inRTO := b.rtoActiveFlows[flowKey]
			b.rtoMu.Unlock()

			if !inRTO {
				continue
			}

			// Use a separate try-catch block for each flow to ensure one bad flow doesn't stop the others
			func() {
				defer func() {
					if r := recover(); r != nil {
						logging.Warnf("Error logging metrics for flow %s: %v", flowKey, r)
					}
				}()

				// Calculate in-flight data
				inFlight := int(flow.serverNxt - flow.sndUna)

				// Get congestion window
				cwnd := 0
				if flow.ccEnabled && flow.cc != nil {
					cwnd = flow.cc.Cwnd()
				}

				// Calculate idle time
				idleTime := time.Since(flow.lastAckTime)

				// Log detailed flow metrics
				logging.Warnf("RTO Flow %s: inFlight=%d bytes, cwnd=%d, advWnd=%d, idle=%v, rto=%v, retries=%d",
					flowKey, inFlight, cwnd, flow.advWnd, idleTime.Round(time.Second), flow.rto,
					b.getMaxRetries(flow))
			}()
		}

		// Log global metrics in a separate try-catch block
		func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Warnf("Error logging global metrics: %v", r)
				}
			}()

			if b.parent != nil {
				dm := b.parent.DetailedMetrics()
				// Prefer reporting wg_queue_full from processor metrics when present
				var wgFull uint64
				if dm.Processor != nil {
					if v, ok := dm.Processor["wg_queue_full"]; ok {
						wgFull = v
					}
				}
				logging.Warnf("Global Metrics: activeFlows=%d, rtoCount=%d, wg_queue_full=%d",
					dm.TCP.ActiveFlows, b.rtoCount, wgFull)

				// Log WireGuard metrics if available
				if b.parent.processor != nil {
					if m, ok := b.parent.processor.(interface{ Metrics() map[string]uint64 }); ok {
						wgMetrics := m.Metrics()
						if drops, ok := wgMetrics["queue_drops"]; ok {
							logging.Warnf("WireGuard Metrics: queueDrops=%d", drops)
						}
					}
				}

				// Log current TCP bridge settings
				logging.Warnf("TCP Bridge Settings: mssClamp=%d, paceUS=%d, ackIdleGate=%v, ackIdleFail=%v",
					b.mssClamp, b.paceUS, b.ackIdleGate, b.ackIdleFail)
			}
		}()
	}()

	// Wait for the metrics dump to complete or timeout after 5 seconds
	select {
	case <-done:
		// Metrics dump completed normally
	case <-time.After(5 * time.Second):
		// Timeout - force log the end marker
		logging.Warnf("Metrics dump timed out after 5 seconds")
		logging.Warnf("=== END DETAILED METRICS ===")
	}
}

// getMaxRetries returns the maximum retry count for any segment in the flow's txQueue
func (b *tcpBridge) getMaxRetries(f *tcpFlow) int {
	f.txMu.Lock()
	defer f.txMu.Unlock()

	maxRetries := 0
	for _, seg := range f.txQueue {
		if seg.retries > maxRetries {
			maxRetries = seg.retries
		}
	}
	return maxRetries
}
