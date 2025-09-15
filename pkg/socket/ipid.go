package socket

import "sync/atomic"

// ipIDCounter provides a best-effort, process-wide IPv4 Identification field
// generator to avoid emitting a constant zero IP ID, which can confuse some
// middleboxes and OSes even for unfragmented traffic.
var ipIDCounter uint32

func nextIPID() uint16 { return uint16(atomic.AddUint32(&ipIDCounter, 1)) }

