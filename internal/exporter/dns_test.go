package exporter

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	"github.com/reloaded/prometheus_pihole_exporter/internal/pihole"
)

// fakePihole is a minimal in-memory Pi-hole that can be steered per-test
// via responses keyed on path. It handles the v6 auth handshake out of
// the box. The mutex makes mid-test response swaps safe — the
// windowed-counter tests need to drive the same collector through
// multiple Gather() rounds with different upstream values to verify
// delta accumulation.
type fakePihole struct {
	t *testing.T

	mu        sync.RWMutex
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
		f.mu.RLock()
		body, ok := f.responses[r.URL.Path]
		code := f.status[r.URL.Path]
		f.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if code != 0 {
			w.WriteHeader(code)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

// setResponse swaps the fake server's body for a given path. Used to
// replay multi-scrape traces in the windowed-counter test.
func (f *fakePihole) setResponse(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[path] = body
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
			"/api/info/ftl":        `{"ftl":{"privacy_level":0,"%mem":1.5,"%cpu":0.7,"clients":{"total":50,"active":12},"database":{"domains":{"allowed":{"total":3,"enabled":3},"denied":{"total":0,"enabled":0}},"regex":{"allowed":{"total":0,"enabled":0},"denied":{"total":0,"enabled":0}}},"dnsmasq":{"dns_cache_inserted":4242,"dns_cache_live_freed":11,"dns_queries_forwarded":600,"dns_auth_answered":12,"dns_local_answered":300,"dns_stale_answered":5,"dns_unanswered":2,"dhcp_ack":17,"dhcp_decline":0,"dhcp_discover":4,"dhcp_inform":0,"dhcp_nak":0,"dhcp_offer":4,"dhcp_release":2,"dhcp_request":17,"leases_allocated_4":22,"leases_pruned_4":3,"leases_allocated_6":1,"leases_pruned_6":0}}}`,
			"/api/info/version":    `{"version":{"core":{"local":{"version":"v6.0.0"}},"ftl":{"local":{"version":"v6.0.1"}},"web":{"local":{"version":"v6.0.0"}}}}`,
		},
	}).handler())
	defer srv.Close()

	c := newDNSCollector("primary",
		pihole.NewClient(pihole.Options{BaseURL: srv.URL, Password: "x"}),
		newDNSCounters(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// First Gather primes the windowed→monotonic accumulators — every
	// _total wrapped by the accumulator reads back as 0. The gauges
	// and the FTL-lifetime _total counters (dnsmasq_*, ftl_dhcp_*)
	// pass through unchanged on the first scrape.
	got := gatherText(t, c)

	for _, want := range []string{
		// Windowed → primed to 0 on first scrape.
		`pihole_dns_queries_total{instance="primary"} 0`,
		`pihole_dns_queries_blocked_total{instance="primary"} 0`,
		`pihole_dns_queries_forwarded_total{instance="primary"} 0`,
		`pihole_dns_queries_cached_total{instance="primary"} 0`,
		`pihole_dns_queries_by_type_total{instance="primary",type="A"} 0`,
		`pihole_dns_queries_by_type_total{instance="primary",type="AAAA"} 0`,
		`pihole_dns_queries_by_status_total{instance="primary",status="GRAVITY"} 0`,
		`pihole_dns_queries_by_reply_total{instance="primary",reply="NXDOMAIN"} 0`,
		`pihole_dns_upstream_queries_total{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 0`,
		// Gauges and FTL-lifetime counters pass through.
		`pihole_dns_queries_blocked_ratio{instance="primary"} 0.1`,
		`pihole_dns_queries_unique_domains{instance="primary"} 250`,
		`pihole_dns_queries_per_second{instance="primary"} 3.5`,
		`pihole_dns_clients_active{instance="primary"} 12`,
		`pihole_dns_clients_total{instance="primary"} 50`,
		`pihole_gravity_domains{instance="primary"} 250000`,
		`pihole_gravity_last_update_timestamp_seconds{instance="primary"} 1.7e+09`,
		`pihole_blocking_enabled{instance="primary"} 1`,
		`pihole_dns_upstream_response_seconds{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 0.05`,
		`pihole_ftl_memory_percent{instance="primary"} 1.5`,
		`pihole_ftl_cpu_percent{instance="primary"} 0.7`,
		`pihole_dnsmasq_cache_inserted_total{instance="primary"} 4242`,
		`pihole_dnsmasq_queries_forwarded_total{instance="primary"} 600`,
		// FTL-API-sourced DHCP counters (no log-tailer needed)
		`pihole_ftl_dhcp_messages_total{instance="primary",type="DHCPACK"} 17`,
		`pihole_ftl_dhcp_messages_total{instance="primary",type="DHCPNAK"} 0`,
		`pihole_ftl_dhcp_messages_total{instance="primary",type="DHCPOFFER"} 4`,
		`pihole_ftl_dhcp_messages_total{instance="primary",type="DHCPREQUEST"} 17`,
		`pihole_ftl_dhcp_messages_total{instance="primary",type="DHCPRELEASE"} 2`,
		`pihole_ftl_dhcp_leases_allocated_total{family="ipv4",instance="primary"} 22`,
		`pihole_ftl_dhcp_leases_pruned_total{family="ipv4",instance="primary"} 3`,
		`pihole_ftl_dhcp_leases_allocated_total{family="ipv6",instance="primary"} 1`,
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
		newDNSCounters(),
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
		newDNSCounters(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	got := gatherText(t, c)
	// Summary succeeded, upstreams failed → collector_up should be 0,
	// but the summary metrics should still have been emitted (here
	// reading 0 because this is the first scrape and the accumulator
	// is priming the baseline).
	if !strings.Contains(got, `pihole_collector_up{collector="dns",instance="primary"} 0`) {
		t.Fatalf("expected collector_up=0 when an endpoint fails, got:\n%s", got)
	}
	if !strings.Contains(got, `pihole_dns_queries_total{instance="primary"} 0`) {
		t.Fatalf("expected partial summary metrics (primed to 0 on first scrape), got:\n%s", got)
	}
}

// TestDNSCollector_WindowedCountersAcrossScrapes drives the same
// collector through four Gather() rounds against a fakePihole that
// replays a realistic Pi-hole trace: prime, growth, window flush,
// post-flush growth. Verifies that the windowed→monotonic wiring in
// emitSummary / emitUpstreams produces values rate() can consume
// without spike artefacts.
func TestDNSCollector_WindowedCountersAcrossScrapes(t *testing.T) {
	t.Parallel()

	mkSummary := func(total, blocked, forwarded, cached int64, byType map[string]int64) string {
		s := pihole.StatsSummary{}
		s.Queries.Total = total
		s.Queries.Blocked = blocked
		s.Queries.Forwarded = forwarded
		s.Queries.Cached = cached
		s.Queries.Types = byType
		b, _ := json.Marshal(s)
		return string(b)
	}
	mkUpstreams := func(count int64) string {
		u := pihole.StatsUpstreams{}
		u.Upstreams = append(u.Upstreams, struct {
			IP         string `json:"ip"`
			Name       string `json:"name"`
			Port       int    `json:"port"`
			Count      int64  `json:"count"`
			Statistics struct {
				Response float64 `json:"response"`
				Variance float64 `json:"variance"`
			} `json:"statistics"`
		}{IP: "9.9.9.9", Name: "9.9.9.9#53", Port: 53, Count: count})
		b, _ := json.Marshal(u)
		return string(b)
	}

	fp := &fakePihole{
		t: t,
		responses: map[string]string{
			"/api/stats/summary":   mkSummary(1000, 100, 600, 300, map[string]int64{"A": 700}),
			"/api/stats/upstreams": mkUpstreams(600),
			"/api/dns/blocking":    `{"blocking":"enabled","timer":null}`,
			"/api/info/ftl":        `{"ftl":{}}`,
			"/api/info/version":    `{"version":{}}`,
		},
	}
	srv := httptest.NewServer(fp.handler())
	defer srv.Close()

	c := newDNSCollector("primary",
		pihole.NewClient(pihole.Options{BaseURL: srv.URL, Password: "x"}),
		newDNSCounters(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	register := prometheus.NewRegistry()
	register.MustRegister(c)
	gather := func() string {
		t.Helper()
		mfs, err := register.Gather()
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

	// Round 1 — prime. Every windowed _total reads 0.
	got := gather()
	for _, want := range []string{
		`pihole_dns_queries_total{instance="primary"} 0`,
		`pihole_dns_queries_blocked_total{instance="primary"} 0`,
		`pihole_dns_queries_by_type_total{instance="primary",type="A"} 0`,
		`pihole_dns_upstream_queries_total{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 0`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("round 1 (prime): missing %q in:\n%s", want, got)
		}
	}

	// Round 2 — growth. q.Total: 1000 → 1500 → expected lifetime 500;
	// upstream.Count: 600 → 850 → expected lifetime 250.
	fp.setResponse("/api/stats/summary", mkSummary(1500, 150, 850, 500, map[string]int64{"A": 1050}))
	fp.setResponse("/api/stats/upstreams", mkUpstreams(850))
	got = gather()
	for _, want := range []string{
		`pihole_dns_queries_total{instance="primary"} 500`,
		`pihole_dns_queries_blocked_total{instance="primary"} 50`,
		`pihole_dns_queries_by_type_total{instance="primary",type="A"} 350`,
		`pihole_dns_upstream_queries_total{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 250`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("round 2 (growth): missing %q in:\n%s", want, got)
		}
	}

	// Round 3 — window flush. Upstream values drop; lifetime must
	// not roll backwards. This is the spike-producing scenario the
	// accumulator exists to defuse.
	fp.setResponse("/api/stats/summary", mkSummary(1380, 140, 780, 460, map[string]int64{"A": 950}))
	fp.setResponse("/api/stats/upstreams", mkUpstreams(780))
	got = gather()
	for _, want := range []string{
		`pihole_dns_queries_total{instance="primary"} 500`,
		`pihole_dns_queries_blocked_total{instance="primary"} 50`,
		`pihole_dns_queries_by_type_total{instance="primary",type="A"} 350`,
		`pihole_dns_upstream_queries_total{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 250`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("round 3 (flush): missing %q in:\n%s", want, got)
		}
	}

	// Round 4 — post-flush growth. New floor is 1380; rising to
	// 1480 adds 100 to lifetime → 600 total. Same shape per series.
	fp.setResponse("/api/stats/summary", mkSummary(1480, 145, 850, 485, map[string]int64{"A": 1010}))
	fp.setResponse("/api/stats/upstreams", mkUpstreams(850))
	got = gather()
	for _, want := range []string{
		`pihole_dns_queries_total{instance="primary"} 600`,
		`pihole_dns_queries_blocked_total{instance="primary"} 55`,
		`pihole_dns_queries_by_type_total{instance="primary",type="A"} 410`,
		`pihole_dns_upstream_queries_total{instance="primary",ip="9.9.9.9",port="53",upstream="9.9.9.9#53"} 320`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("round 4 (post-flush growth): missing %q in:\n%s", want, got)
		}
	}
}
