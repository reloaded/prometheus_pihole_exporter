// Package exporter wires together per-instance Pi-hole collectors behind
// the exporter's HTTP probe handler.
//
// The probe handler implements the multi-target pattern: each request
// names an instance via ?target=<id>, the matching collectors are
// gathered into a fresh registry, and the resulting metrics are written
// out. This keeps instances isolated from each other and avoids global
// metric churn when one instance is briefly unreachable.
package exporter

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/reloaded/prometheus_pihole_exporter/internal/config"
	"github.com/reloaded/prometheus_pihole_exporter/internal/pihole"
)

// pingTimeout caps the auth check the probe handler runs before
// registering collectors. Independent of per-collector timeouts so a
// single slow Pi-hole can't block /probe past this deadline.
const pingTimeout = 10 * time.Second

// NewProbeHandler builds the HTTP handler served at /probe.
//
// Each Pi-hole instance gets a single shared *pihole.Client (reused
// across scrapes so the v6 session SID gets cached) and a freshly-built
// registry per request. Instances that opt into the dhcp_log collector
// also get a long-lived tailer goroutine started here; those goroutines
// stop when ctx is cancelled (typically on SIGINT/SIGTERM in main).
//
// `overrides` carries the global CLI/env collector toggles (issue #1).
// Each effective toggle is computed at handler-build time so the
// dhcp_log tailer goroutines can be skipped when the operator has
// killed the collector at the process level — no point starting a
// goroutine that's never going to register.
func NewProbeHandler(ctx context.Context, cfg *config.Config, overrides config.Overrides, logger *slog.Logger) http.Handler {
	h := &probeHandler{
		cfg:       cfg,
		overrides: overrides,
		logger:    logger,
		clients:   make(map[string]*pihole.Client, len(cfg.Instances)),
		dhcpLog:   make(map[string]*dhcpLogState, len(cfg.Instances)),
	}
	for id, inst := range cfg.Instances {
		h.clients[id] = pihole.NewClient(pihole.Options{
			BaseURL:            inst.URL,
			Password:           os.Getenv(inst.AppPasswordEnv),
			Timeout:            inst.Timeout,
			InsecureSkipVerify: inst.InsecureSkipVerify,
		})
		if overrides.EffectiveDHCPLog(inst) {
			state := newDHCPLogState(id, inst.Collectors.DHCPLog.Path, logger)
			h.dhcpLog[id] = state
			go state.run(ctx)
		}
	}
	return h
}

type probeHandler struct {
	cfg       *config.Config
	overrides config.Overrides
	logger    *slog.Logger
	mu        sync.Mutex // guards clients + dhcpLog
	clients   map[string]*pihole.Client
	dhcpLog   map[string]*dhcpLogState
}

func (h *probeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, `query parameter "target" is required`, http.StatusBadRequest)
		return
	}

	inst, ok := h.cfg.Instances[target]
	if !ok {
		http.Error(w, "unknown target", http.StatusNotFound)
		return
	}
	h.mu.Lock()
	client := h.clients[target]
	h.mu.Unlock()

	registry := prometheus.NewRegistry()
	logger := h.logger.With("instance", target)

	// pihole_up tracks whether a baseline auth+ping succeeded — operators
	// can alert on this single label without caring which collector group
	// failed underneath. Per-collector health is exposed separately as
	// `pihole_collector_up{collector=<group>}`.
	up := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pihole_up",
		Help: "1 if the Pi-hole instance was reachable and authenticated this scrape, 0 otherwise.",
		ConstLabels: prometheus.Labels{
			"instance": target,
		},
	})
	registry.MustRegister(up)

	// Scrape-duration metric — useful for alerting on slow Pi-holes.
	scrapeDuration := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pihole_scrape_duration_seconds",
		Help: "Wall-clock time spent gathering metrics for this Pi-hole instance.",
		ConstLabels: prometheus.Labels{
			"instance": target,
		},
	})
	registry.MustRegister(scrapeDuration)

	start := time.Now()
	defer func() {
		scrapeDuration.Set(time.Since(start).Seconds())
	}()

	// Verify the Pi-hole API is reachable + the app password still
	// works before running the collectors. This sets pihole_up cleanly
	// even when DNS / DHCP collectors aren't enabled.
	pingCtx, cancel := pingCtxWithTimeout(r.Context(), pingTimeout)
	defer cancel()
	if err := client.Ping(pingCtx); err != nil {
		logger.Warn("ping failed", "err", err)
		up.Set(0)
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
		return
	}
	up.Set(1)

	// Wire enabled collectors. The override layer (CLI / env) gets
	// the final say — see config.Overrides — so this entire chain
	// reads from the resolved-effective view, not from the raw YAML.
	if h.overrides.EffectiveDNS(inst) {
		registry.MustRegister(newDNSCollector(target, client, logger))
	}
	if h.overrides.EffectiveDHCPLeases(inst) {
		registry.MustRegister(newDHCPLeasesCollector(target, inst.Collectors.DHCPLeases.Path, logger))
	}
	if state := h.dhcpLog[target]; state != nil {
		registry.MustRegister(newDHCPLogCollector(target, state))
	}

	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// pingCtxWithTimeout is a thin wrapper so the probe handler can derive
// a bounded ping context off the request's context. Pulled out so the
// probe-handler tests can swap it out if needed.
var pingCtxWithTimeout = func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
