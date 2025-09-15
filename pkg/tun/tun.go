package tun

import (
    "fmt"

    "github.com/irctrakz/wgslirp/pkg/core"
    "github.com/irctrakz/wgslirp/pkg/logging"
)

// CreateTUN is a stub function that returns an error indicating that kernel TUN devices are no longer supported.
// The router now uses a pure userspace implementation that doesn't require kernel TUN devices.
func CreateTUN(name string, mtu int) (core.TUNDevice, error) {
	logging.Infof("Kernel TUN devices are no longer supported")
	return nil, fmt.Errorf("kernel TUN devices are no longer supported; the router now uses a pure userspace implementation")
}

// OpenTUNWithPath is a stub function that returns an error indicating that kernel TUN devices are no longer supported.
// The router now uses a pure userspace implementation that doesn't require kernel TUN devices.
func OpenTUNWithPath(name string, mtu int, path string) (core.TUNDevice, error) {
	logging.Infof("Kernel TUN devices are no longer supported")
	return nil, fmt.Errorf("kernel TUN devices are no longer supported; the router now uses a pure userspace implementation")
}
