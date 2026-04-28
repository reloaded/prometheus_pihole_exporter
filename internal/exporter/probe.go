// Package exporter wires together per-instance Pi-hole collectors behind
// the exporter's HTTP probe handler.
//
// The probe handler implements the multi-target pattern: each request
// names an instance via ?target=<id>, the matching collectors are
// gathered into a fresh registry, and the resulting metrics are written
// out. This keeps instances isolated from each other and avoids global
// metric churn when one instance is briefly unreachable.
//
// Collector implementations themselves are stubbed out at scaffold time
// and will land in follow-up PRs (one per collector group).
package exporter

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/reloaded/prometheus_pihole_exporter/internal/config"
)

// NewProbeHandler builds the HTTP handler served at /probe.
func NewProbeHandler(cfg *config.Config, logger *slog.Logger) http.Handler {
	return &probeHandler{
		cfg:    cfg,
		logger: logger,
	}
}

type probeHandler struct {
	cfg    *config.Config
	logger *slog.Logger
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

	registry := prometheus.NewRegistry()

	// Per-probe metric describing whether collection succeeded end-to-end.
	// This stays in place even after real collectors land; alerts can key
	// off it without caring which collector group failed.
	up := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pihole_up",
		Help: "1 if the Pi-hole instance was successfully scraped, 0 otherwise.",
		ConstLabels: prometheus.Labels{
			"instance": target,
		},
	})
	registry.MustRegister(up)

	// TODO(scaffold): wire collectors based on inst.Collectors. Until the
	// real implementations land we just record up=0 with a debug log so
	// the multi-target plumbing can be exercised end-to-end.
	_ = inst
	up.Set(0)
	h.logger.Debug("probe (scaffold)", "target", target)

	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}
