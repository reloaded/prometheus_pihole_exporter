// Command prometheus_pihole_exporter is a Prometheus exporter for Pi-hole v6.
//
// It supports multiple Pi-hole instances using the multi-target pattern:
// `/probe?target=<instance-id>` runs the per-instance collectors and returns
// instance-scoped metrics; `/metrics` exposes only the exporter's own
// process / runtime metrics.
//
// Configuration is loaded from a YAML file (path via -config or
// $PIHOLE_EXPORTER_CONFIG) describing each Pi-hole instance and which
// collector groups to enable for it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/reloaded/prometheus_pihole_exporter/internal/config"
	"github.com/reloaded/prometheus_pihole_exporter/internal/exporter"
)

// Version metadata is injected at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var (
		configPath  = flag.String("config", envOr("PIHOLE_EXPORTER_CONFIG", "/etc/prometheus_pihole_exporter/config.yaml"), "Path to the YAML configuration file.")
		listenAddr  = flag.String("web.listen-address", envOr("PIHOLE_EXPORTER_LISTEN_ADDR", ":9617"), "Address to listen on for /metrics and /probe.")
		metricsPath = flag.String("web.telemetry-path", envOr("PIHOLE_EXPORTER_METRICS_PATH", "/metrics"), "Path under which exporter-self metrics are exposed.")
		probePath   = flag.String("web.probe-path", envOr("PIHOLE_EXPORTER_PROBE_PATH", "/probe"), "Path under which per-instance probe metrics are served.")
		showVersion = flag.Bool("version", false, "Print version information and exit.")
	)
	resolveOverrides := config.RegisterOverrides(flag.CommandLine, os.Getenv)
	flag.Parse()

	if *showVersion {
		fmt.Printf("prometheus_pihole_exporter version=%s commit=%s built=%s\n", version, commit, date)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	overrides, err := resolveOverrides()
	if err != nil {
		logger.Error("failed to resolve collector overrides", "err", err)
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "path", *configPath, "err", err)
		os.Exit(1)
	}
	logger.Info("loaded config", "instances", len(cfg.Instances),
		"override_dns", overrides.DNS != nil,
		"override_dhcp_leases", overrides.DHCPLeases != nil,
		"override_dhcp_log", overrides.DHCPLog != nil)

	// Self-metrics registry: exporter process + Go runtime.
	selfRegistry := prometheus.NewRegistry()
	selfRegistry.MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	probeHandler := exporter.NewProbeHandler(ctx, cfg, overrides, logger)

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(selfRegistry, promhttp.HandlerOpts{}))
	mux.Handle(*probePath, probeHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<!doctype html>
<html><head><title>prometheus_pihole_exporter</title></head><body>
<h1>prometheus_pihole_exporter</h1>
<p>version: %s</p>
<ul>
  <li><a href="%s">%s</a> — exporter-self metrics</li>
  <li><code>%s?target=&lt;instance-id&gt;</code> — per-Pi-hole metrics</li>
  <li><a href="/healthz">/healthz</a></li>
</ul>
</body></html>
`, version, *metricsPath, *metricsPath, *probePath)
	})

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("server listening", "addr", *listenAddr, "metrics", *metricsPath, "probe", *probePath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
