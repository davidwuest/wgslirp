package wireguard

// DeviceHandle is a minimal lifecycle for the WG device.
type DeviceHandle interface {
    Close() error
    // IpcGet returns the current device state in UAPI text form.
    IpcGet() (string, error)
    // RebindListenPort updates the device's UDP listen port (0 = random).
    RebindListenPort(port int) error
}
