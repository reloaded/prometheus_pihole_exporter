package exporter

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	"github.com/reloaded/prometheus_pihole_exporter/internal/pihole"
)

// fakePihole is a minimal in-memory Pi-hole that can be steered per-test
// via responses keyed on path. It handles the v6 auth handshake out of
// the box.
type fakePihole struct {
	t         *testing.T
	responses map[string]string // path → JSON body
	status    map[string]int    // optional override (defaults to 200)
}

func (f *fakePihole) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth" {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"session":{"valid":true,"sid":"S","validity":1800}}`))
			return
		}
		body, ok := f.responses[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if code := f.status[r.URL.Path]; code != 0 {
			w.WriteHeader(code)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

// gatherText returns the rendered text-format metrics for the given
// collector — easier to assert against than the raw protobuf model.
func gatherText(t *testing.T, c prometheus.Collector) string {
	t.Helper()
	r := prometheus.NewRegistry()
	r.MustRegister(c)
	mfs, err := r.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	return buf.String()
}

func TestDNSCollector_Summary(t *testing.T) {
	t.Parallel()

	summary := pihole.StatsSummary{}
	summary.Queries.Total = 1000
	summary.Queries.Blocked = 100
	summary.Queries.Forwarded = 600
	summary.Queries.Cached = 300
	summary.Queries.PercentBlocked = 10.0
	summary.Queries.UniqueDomains = 250
	summary.Queries.Frequency = 3.5
	summary.Queries.Types = map[string]int64{"A": 700, "AAAA": 200, "MX": 100}
	summary.Queries.Status = map[string]int64{"GRAVITY": 100, "FORWARDED": 600, "CACHE": 300}
	summary.Queries.Replies = map[string]int64{"NXDOMAIN": 5, "NODATA": 10, "IP": 985}
	summary.Clients.Active = 12
	summary.Clients.Total = 50
	summary.Gravity.DomainsBeingBlocked = 250000
	summary.Gravity.LastUpdate = 1700000000
	summaryJSON, _ := json.Marshal(summary)

	upstreams := pihole.StatsUpstreams{
		ForwardedQueries: 600,
		TotalQueries:     1000,
	}
	upstreams.Upstreams = append(upstreams.Upstreams, struct {
		IP         string `json:"ip"`
		Name       string `json:"name"`
		Port       int    `json:"port"`
		Count      int64  `json:"count"`
		Statistics struct {
			Response float64 `json:"response"`
			Variance float64 `json:"variance"`
		} `json:"statistics"`
	}{IP: "9.9.9.9", Name: "9.9.9.9#53", Port: 53, Count: 600, Statistics: struct {
		Response float64 `json:"response"`
		Variance float64 `json:"variance"`
	}{Response: 0.05, Variance: 0.001}})
	upstreamsJSON, _ := json.Marshal(upstreams)

	srv := httptest.NewServer((&fakePihole{
		t: t,
		responses: map[string]string{
			"/api/stats/summary":   string(summaryJSON),
			"/api/stats/upstreams": string(upstreamsJSON),
			"/api/dns/blocking":    `{"blocking":"enabled","timer":null}`,
			"/api/info/ftl":        `{"ftl":{"privacy_level":0,"%mem":1.5,"%cpu":0.7,"clients":{"total":50,"active":12},"database":{"domains":{"allowed":{"total":3,"enabled":3},"denied":{"total":0,"enabled":0}},"regex":{"allowed":{"total":0,"enabled":0},"denied":{"total":0,"enabled":0}}},"dnsmasq":{"dns_cache_inserted":4242,"dns_cache_live_freed":11,"dns_queries_forwarded":600,"dns_auth_answered":12,"dns_local_answered":300,"dns_stale_answered":5,"dns_unanswered":2}}}`,
			"/api/info/version":    `{"version":{"core":{"local":{"version":"v6.0.0"}},"ftl":{"local":{"version":"v6.0.1"}},"web":{"local":{"version":"v6.0.0"}}}}`,
		},
	}).handler())
	defer srv.Close()

	c := newDNSCollector("primary",
		pihole.NewClient(pihole.Options{BaseURL: srv.URL, Password: "x"}),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	got := gatherText(t, c)

	for _, want := range []string{
		`pihole_dns_queries_total{instance="primary"} 1000`,
		`pihole_dns_queries_blocked_total{instance="primary"} 100`,
		`pihole_dns_queries_forwarded_total{instance="primary"} 600`,
		`pihole_dns_queries_cached_total{instance="primary"} 300`,
		`pihole_dns_queries_blocked_ratio{instance="primary"} 0.1`,
		`pihole_dns_queries_unique_domains{instance="primary"} 250`,
		`pihole_dns_queries_per_second{instance="primary"} 3.5`,
		`pihole_dns_clients_active{instance="primary"} 12`,
		`pihole_dns_clients_total{instance="primary"} 50`,
		`pihole_gravity_domains{instance="primary"} 250000`,
		`pihole_gravity_last_update_timestamp_seconds{instance="primary"} 1.7e+09`,
		`pihole_blocking_enabled{instance="primary"} 1`,
		`pihole_dns_queries_by_type_total{instance="primary",type="A"} 700`,
		`pihole_dns_queries_by_type_total{instance="primary",type="AAAA"} 200`,
		`pihole_dns_queries_by_status_total{instance="primary",status="GRAVITY"} 100`,
		`pihole_dns_queries_by_reply_total{instance="primary",reply="NXDOMAIN"} 5`,
		`pihole_dns_upstream_queries_total{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 600`,
		`pihole_dns_upstream_response_seconds{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 0.05`,
		`pihole_ftl_memory_percent{instance="primary"} 1.5`,
		`pihole_ftl_cpu_percent{instance="primary"} 0.7`,
		`pihole_dnsmasq_cache_inserted_total{instance="primary"} 4242`,
		`pihole_dnsmasq_queries_forwarded_total{instance="primary"} 600`,
		`pihole_info{core_version="v6.0.0",ftl_version="v6.0.1",instance="primary",web_version="v6.0.0"} 1`,
		`pihole_collector_up{collector="dns",instance="primary"} 1`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing or different:\n  want substring: %q\n  in metrics:\n%s", want, got)
		}
	}
}

func TestDNSCollector_BlockingDisabled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer((&fakePihole{
		t: t,
		responses: map[string]string{
			"/api/stats/summary":   `{"queries":{}}`,
			"/api/stats/upstreams": `{"upstreams":[]}`,
			"/api/dns/blocking":    `{"blocking":"disabled","timer":300}`,
			"/api/info/ftl":        `{"ftl":{}}`,
			"/api/info/version":    `{"version":{}}`,
		},
	}).handler())
	defer srv.Close()

	c := newDNSCollector("primary",
		pihole.NewClient(pihole.Options{BaseURL: srv.URL, Password: "x"}),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	got := gatherText(t, c)
	if !strings.Contains(got, `pihole_blocking_enabled{instance="primary"} 0`) {
		t.Fatalf("expected blocking_enabled=0 (disabled), got:\n%s", got)
	}
	if !strings.Contains(got, `pihole_info{core_version="unknown",ftl_version="unknown",instance="primary",web_version="unknown"} 1`) {
		t.Fatalf("expected info gauge with unknown versions, got:\n%s", got)
	}
}

func TestDNSCollector_PartialFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer((&fakePihole{
		t: t,
		responses: map[string]string{
			"/api/stats/summary":   `{"queries":{"total":1}}`,
			"/api/stats/upstreams": `not even valid json`,
			"/api/dns/blocking":    `{"blocking":"enabled"}`,
			"/api/info/ftl":        `{"ftl":{}}`,
			"/api/info/version":    `{"version":{}}`,
		},
	}).handler())
	defer srv.Close()

	c := newDNSCollector("primary",
		pihole.NewClient(pihole.Options{BaseURL: srv.URL, Password: "x"}),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	got := gatherText(t, c)
	// Summary succeeded, upstreams failed → collector_up should be 0,
	// but the summary metrics should still have been emitted.
	if !strings.Contains(got, `pihole_collector_up{collector="dns",instance="primary"} 0`) {
		t.Fatalf("expected collector_up=0 when an endpoint fails, got:\n%s", got)
	}
	if !strings.Contains(got, `pihole_dns_queries_total{instance="primary"} 1`) {
		t.Fatalf("expected partial summary metrics, got:\n%s", got)
	}
}
