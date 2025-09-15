package socket

import (
    "os"
    "strconv"
    "strings"
    "sync/atomic"
)

// congestionControl is a minimal interface for pluggable TCP congestion algorithms
// governing server->guest sending in tcpBridge.
type congestionControl interface {
    // Cwnd returns the current congestion window in bytes.
    Cwnd() int
    // OnSent informs the CC that n bytes were sent.
    OnSent(n int)
    // OnAck informs the CC that n bytes were cumulatively ACKed.
    OnAck(n int)
    // OnLoss informs the CC of a loss event. If timeout is true, it was an RTO.
    OnLoss(timeout bool)
}

// newCongestionControl constructs a CC by name. Currently supports "newreno" (default).
func newCongestionControl(name string, mss int) congestionControl {
    switch name {
    case "", "newreno", "reno", "new-reno":
        return newNewReno(mss)
    default:
        return newNewReno(mss)
    }
}

// --- NewReno ---

type newReno struct {
    mss       int
    cwnd      int64 // bytes
    ssthresh  int64 // bytes
    caAcc     int64 // additive increase accumulator (bytes)
}

func newNewReno(mss int) *newReno {
    if mss <= 0 { mss = 1460 }
    // RFC 6928 initial cwnd: min(10*MSS, max(2*MSS, 14600))
    init := 10 * mss
    if init > 14600 { init = 14600 }
    if init < 2*mss { init = 2 * mss }
    // Optional override via TCP_INIT_CWND_MSS (number of MSS)
    if v := strings.TrimSpace(os.Getenv("TCP_INIT_CWND_MSS")); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            lim := n * mss
            if lim < init { init = lim }
        }
    }
    return &newReno{
        mss:      mss,
        cwnd:     int64(init),
        ssthresh: int64(64 * 1024), // conservative default
        caAcc:    0,
    }
}

func (n *newReno) Cwnd() int { return int(atomic.LoadInt64(&n.cwnd)) }

func (n *newReno) OnSent(int) { /* no-op */ }

func (n *newReno) OnAck(acked int) {
    if acked <= 0 { return }
    cw := atomic.LoadInt64(&n.cwnd)
    if cw < n.ssthresh {
        // Slow start: grow by MSS per MSS of data acked (byte counting)
        inc := int64(acked)
        if inc > int64(n.mss) { inc = int64(n.mss) }
        atomic.AddInt64(&n.cwnd, inc)
        return
    }
    // Congestion avoidance: roughly +1 MSS per RTT
    // Use byte-counting: accumulate (MSS*MSS)/cwnd per MSS of data acked.
    // Approximate by accumulating acked * MSS / cwnd and add when >= MSS.
    if cw <= 0 { cw = int64(n.mss) }
    add := (int64(acked) * int64(n.mss)) / cw
    if add <= 0 { add = 1 } // ensure progress on small ACKs
    n.caAcc += add
    if n.caAcc >= int64(n.mss) {
        grew := (n.caAcc / int64(n.mss)) * int64(n.mss)
        atomic.AddInt64(&n.cwnd, grew)
        n.caAcc -= grew
    }
}

func (n *newReno) OnLoss(timeout bool) {
    cw := atomic.LoadInt64(&n.cwnd)
    // Multiplicative decrease
    ssth := cw / 2
    if ssth < int64(2*n.mss) { ssth = int64(2 * n.mss) }
    n.ssthresh = ssth
    if timeout {
        // RTO: fall back to 1 MSS
        atomic.StoreInt64(&n.cwnd, int64(n.mss))
    } else {
        // Fast retransmit: enter fast recovery cwnd = ssthresh + 3*MSS
        atomic.StoreInt64(&n.cwnd, n.ssthresh+int64(3*n.mss))
    }
    n.caAcc = 0
}
