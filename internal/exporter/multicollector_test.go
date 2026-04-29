package exporter

import (
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/reloaded/prometheus_pihole_exporter/internal/pihole"
)

// TestAllCollectorsRegisterTogether is a regression test for the
// "descriptor pihole_collector_up already exists" panic that fired in
// systemd mode the first time DNS + DHCP leases + DHCP log collectors
// all ran on the same probe handler. The fix moved `collector` from a
// variable label to a const label per collector, giving each its own
// Desc identity in Prometheus's registry.
func TestAllCollectorsRegisterTogether(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := prometheus.NewRegistry()

	dns := newDNSCollector("primary", pihole.NewClient(pihole.Options{BaseURL: "http://127.0.0.1:1", Password: "x"}), logger)
	leases := newDHCPLeasesCollector("primary", "/dev/null", logger)
	logState := newDHCPLogState("primary", "/dev/null", logger)
	dlog := newDHCPLogCollector("primary", logState)

	for i, c := range []prometheus.Collector{dns, leases, dlog} {
		if err := registry.Register(c); err != nil {
			t.Fatalf("collector %d failed to register on shared registry: %v", i, err)
		}
	}
}
