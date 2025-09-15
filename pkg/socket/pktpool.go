package socket

import "sync"

// Packet buffer pools for small/medium/large common sizes to reduce
// allocations in builders. Callers should only return buffers that originated
// from pktGet (checked via capacity match).

const (
    pktSmall = 2048
    pktMed   = 4096
    pktLarge = 8192
    pktXL    = 16384
)

var (
    poolSmall = sync.Pool{New: func() any { b := make([]byte, pktSmall); return &b }}
    poolMed   = sync.Pool{New: func() any { b := make([]byte, pktMed); return &b }}
    poolLarge = sync.Pool{New: func() any { b := make([]byte, pktLarge); return &b }}
    poolXL    = sync.Pool{New: func() any { b := make([]byte, pktXL); return &b }}
)

func pktGet(n int) []byte {
    switch {
    case n <= pktSmall:
        p := poolSmall.Get().(*[]byte)
        return (*p)[:n]
    case n <= pktMed:
        p := poolMed.Get().(*[]byte)
        return (*p)[:n]
    case n <= pktLarge:
        p := poolLarge.Get().(*[]byte)
        return (*p)[:n]
    case n <= pktXL:
        p := poolXL.Get().(*[]byte)
        return (*p)[:n]
    default:
        return make([]byte, n)
    }
}

func pktPut(b []byte) {
    c := cap(b)
    switch c {
    case pktSmall:
        bb := b[:pktSmall]
        poolSmall.Put(&bb)
    case pktMed:
        bb := b[:pktMed]
        poolMed.Put(&bb)
    case pktLarge:
        bb := b[:pktLarge]
        poolLarge.Put(&bb)
    case pktXL:
        bb := b[:pktXL]
        poolXL.Put(&bb)
    }
}

func pktShouldPut(b []byte) bool {
    switch cap(b) {
    case pktSmall, pktMed, pktLarge, pktXL:
        return true
    default:
        return false
    }
}

// PktPut exposes returning a buffer to the pool for other packages.
func PktPut(b []byte) { pktPut(b) }

// PktShouldPut reports whether a buffer originated from one of the pools.
func PktShouldPut(b []byte) bool { return pktShouldPut(b) }
