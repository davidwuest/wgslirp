package wireguard

import (
    "encoding/binary"
    "os"
    "strings"
    "sync"
    "time"
)

// Simple PCAP writer (DLT_RAW) for plaintext IPv4 frames.
// Enabled when WG_PCAP is set to a writable filepath.

var (
    pcapMu      sync.Mutex
    pcapEnabled bool
    pcapFile    *os.File
)

func initPCAP() {
    path := strings.TrimSpace(os.Getenv("WG_PCAP"))
    if path == "" || pcapEnabled { return }
    f, err := os.Create(path)
    if err != nil { return }
    // PCAP Global Header
    // magic 0xa1b2c3d4, version 2.4, tz 0, sigfigs 0, snaplen 65535, network LINKTYPE_RAW (101)
    hdr := make([]byte, 24)
    binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
    binary.LittleEndian.PutUint16(hdr[4:6], 2)
    binary.LittleEndian.PutUint16(hdr[6:8], 4)
    // 8:12 thiszone (0), 12:16 sigfigs (0)
    binary.LittleEndian.PutUint32(hdr[16:20], 65535)
    binary.LittleEndian.PutUint32(hdr[20:24], 101)
    if _, err := f.Write(hdr); err != nil { f.Close(); return }
    pcapFile = f
    pcapEnabled = true
}

// pcapWriteIPv4 writes one raw IPv4 packet to the PCAP file if enabled.
func pcapWriteIPv4(b []byte) {
    if len(b) == 0 { return }
    pcapMu.Lock()
    defer pcapMu.Unlock()
    if !pcapEnabled {
        initPCAP()
    }
    if !pcapEnabled || pcapFile == nil { return }
    // per-packet header: ts_sec, ts_usec, incl_len, orig_len (all LE)
    ph := make([]byte, 16)
    now := time.Now()
    binary.LittleEndian.PutUint32(ph[0:4], uint32(now.Unix()))
    binary.LittleEndian.PutUint32(ph[4:8], uint32(now.Nanosecond()/1000))
    binary.LittleEndian.PutUint32(ph[8:12], uint32(len(b)))
    binary.LittleEndian.PutUint32(ph[12:16], uint32(len(b)))
    // write header then data
    _, _ = pcapFile.Write(ph)
    _, _ = pcapFile.Write(b)
}

