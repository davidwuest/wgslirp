package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
	// wtun removed (no dynamic flow rate hooks)
)

func main() {
	// Debug logging toggle via DEBUG env (truthy parser)
	dval := strings.ToLower(strings.TrimSpace(os.Getenv("DEBUG")))
	debugOn := dval == "1" || dval == "true" || dval == "yes" || dval == "on"
	// Detect metrics enabled via env
	metricsEnabled := strings.TrimSpace(os.Getenv("METRICS_LOG")) != "" || strings.TrimSpace(os.Getenv("METRICS_INTERVAL")) != ""
	if debugOn {
		logging.SetLevel(logging.DebugLevel)
		core.SetDebugMode(true)
		logging.Infof("DEBUG enabled: verbose logging and packet copy mode")
	} else {
		// Default to warn to keep runtime quiet unless explicitly enabled
		logging.SetLevel(logging.WarnLevel)
		core.SetDebugMode(false)
		// If metrics are enabled, raise to info so metrics dumps are visible
		if metricsEnabled {
			logging.SetLevel(logging.InfoLevel)
		}
	}

	// Load WG config from env
	var dcfg wg.DeviceConfig
	if err := dcfg.LoadFromEnv(); err != nil {
		log.Fatalf("config: %v", err)
	}

	// Build socket interface (slirp bridges). Align slirp MTU with WG plaintext MTU
	// so that synthesized packets (e.g., TCP segments) never exceed the WG TUN MTU.
	// This prevents silent truncation/clamping at the tun boundary.
	mtu := dcfg.MTU
	if mtu <= 0 {
		mtu = 1380
	}
	scfg := socket.Config{IPAddress: "0.0.0.0", MTU: mtu, Protocol: "ip4:tcp"}
	si := socket.NewSocketInterface(scfg)

	// Create WG TUN bound to the socket writer
	wgtun := wg.NewWGTun("wgmux0", dcfg.MTU, si)

	// Packet processor: WG + optional health sink
	wgProc := wg.NewWGPacketProcessor(wgtun)
	proc := wgProc
	// Optional: tee a health-check sink to observe slirp replies
	if strings.TrimSpace(os.Getenv("HEALTHCHECK")) != "" {
		hc := newHealthSink()
		proc = newTeeProcessor(wgProc, hc)
		// Kick off a best-effort DNS slirp health probe
		go runSlirpDNSHealth(si, hc)
		// Also run an OS-level HTTP/DNS check to detect container egress issues
		go runDirectEgressHealth()
	}
	si.SetPacketProcessor(proc)
	if err := si.Start(); err != nil {
		log.Fatalf("socket start: %v", err)
	}
	defer si.Stop()

	// Start the WireGuard device (wg is the default implementation)
	dev, err := wg.StartDevice(dcfg, wgtun)
	if err != nil {
		log.Fatalf("wireguard start: %v", err)
	}
	defer dev.Close()

	// Optional periodic metrics reporter
	if metricsEnabled {
		go runMetricsReporter(si, wgtun, dev)
	}

	// Health check endpoint
	go func() {
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
		http.ListenAndServe(":8080", nil)
	}()

	// Wait for termination
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
}
