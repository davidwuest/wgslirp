package socket

import (
    "os"
    "strings"
    "sync/atomic"

    "github.com/irctrakz/wgslirp/pkg/core"
)

var poolFlag uint32
var poolWrapFlag uint32

func init() {
    v := strings.ToLower(strings.TrimSpace(os.Getenv("POOLING")))
    if v == "1" || v == "true" || v == "yes" || v == "on" {
        atomic.StoreUint32(&poolFlag, 1)
    }
    // By default, avoid pooled Packet wrappers to simplify ownership.
    // Opt-in via POOL_WRAP=1 once end-to-end ownership is proven safe.
    w := strings.ToLower(strings.TrimSpace(os.Getenv("POOL_WRAP")))
    if w == "1" || w == "true" || w == "yes" || w == "on" {
        atomic.StoreUint32(&poolWrapFlag, 1)
    }
}

func poolingEnabled() bool { return atomic.LoadUint32(&poolFlag) == 1 }
func poolWrapEnabled() bool { return atomic.LoadUint32(&poolWrapFlag) == 1 }

// bufMaybePool returns a byte slice of length n, using the pool when enabled.
func bufMaybePool(n int) []byte {
    if poolingEnabled() {
        return pktGet(n)
    }
    return make([]byte, n)
}

// WrapPacket wraps a buffer into a Packet according to the current
// pooling/ownership policy. It always returns a safe Packet for asynchronous
// processing, independently of DEBUG settings.
func WrapPacket(b []byte) core.Packet {
    if poolingEnabled() && poolWrapEnabled() {
        return core.NewPooledPacket(b, func(buf []byte) {
            if pktShouldPut(buf) { pktPut(buf) }
        })
    }
    // Non-pooled wrapper: ensure unique ownership by copying when DEBUG is off
    if !core.IsDebugMode() {
        bb := append([]byte(nil), b...)
        return core.NewPacket(bb)
    }
    return core.NewPacket(b)
}

// DEPRECATED: use WrapPacket. Kept for compatibility during refactors.
func pktWrapMaybe(b []byte) core.Packet { return WrapPacket(b) }

// pktReleaseMaybe releases a Packet if pooling is enabled. It is safe to call
// on non-pooled packets (no-op).
func pktReleaseMaybe(p core.Packet) {
    if poolingEnabled() {
        core.ReleasePacket(p)
    }
}
