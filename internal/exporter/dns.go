package exporter

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/reloaded/prometheus_pihole_exporter/internal/pihole"
)

// dnsCollector pulls DNS / blocking / FTL metrics out of Pi-hole's
// REST API. One Collector instance per Pi-hole instance — the
// `instance` label is baked into every metric via ConstLabels.
type dnsCollector struct {
	instance string
	client   *pihole.Client
	logger   *slog.Logger

	// Top-line DNS counters / gauges
	queriesTotal      *prometheus.Desc
	queriesBlocked    *prometheus.Desc
	queriesForwarded  *prometheus.Desc
	queriesCached     *prometheus.Desc
	queriesByType     *prometheus.Desc
	queriesByStatus   *prometheus.Desc
	queriesByReply    *prometheus.Desc
	queriesUnique     *prometheus.Desc
	queriesFrequency  *prometheus.Desc
	queriesPctBlocked *prometheus.Desc

	// Clients
	clientsActive *prometheus.Desc
	clientsTotal  *prometheus.Desc

	// Gravity (blocklist)
	gravityDomains      *prometheus.Desc
	gravityLastUpdateTs *prometheus.Desc

	// Per-upstream (ip, name, port)
	upstreamQueries      *prometheus.Desc
	upstreamResponseSecs *prometheus.Desc
	upstreamVarianceSecs *prometheus.Desc

	// Blocking state
	blockingEnabled *prometheus.Desc

	// FTL daemon health (selected fields)
	ftlPrivacyLevel   *prometheus.Desc
	ftlMemPercent     *prometheus.Desc
	ftlCPUPercent     *prometheus.Desc
	ftlClientsActive  *prometheus.Desc
	ftlClientsTotal   *prometheus.Desc
	dnsmasqCacheIns   *prometheus.Desc
	dnsmasqCacheFreed *prometheus.Desc
	dnsmasqForwarded  *prometheus.Desc
	dnsmasqAuth       *prometheus.Desc
	dnsmasqLocal      *prometheus.Desc
	dnsmasqStale      *prometheus.Desc
	dnsmasqUnanswered *prometheus.Desc

	// FTL-API-sourced DHCP counters. Coexist with the dhcp_log
	// collector's `pihole_dhcp_messages_total` (different metric
	// names so both can run when an operator wants both signals).
	ftlDHCPMessages        *prometheus.Desc
	ftlDHCPLeasesAllocated *prometheus.Desc
	ftlDHCPLeasesPruned    *prometheus.Desc

	// Info gauge (constant 1, labels carry version strings)
	info *prometheus.Desc

	// Per-collector health: did the call succeed this scrape?
	collectorUp *prometheus.Desc
}

func newDNSCollector(instance string, client *pihole.Client, logger *slog.Logger) prometheus.Collector {
	labels := prometheus.Labels{"instance": instance}
	d := func(name, help string, varLabels ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, varLabels, labels)
	}
	return &dnsCollector{
		instance: instance,
		client:   client,
		logger:   logger,

		queriesTotal:      d("pihole_dns_queries_total", "Pi-hole DNS queries handled today (resets at midnight, treat as a Counter)."),
		queriesBlocked:    d("pihole_dns_queries_blocked_total", "Pi-hole DNS queries blocked today (resets at midnight)."),
		queriesForwarded:  d("pihole_dns_queries_forwarded_total", "Pi-hole DNS queries forwarded to upstream resolvers today (resets at midnight)."),
		queriesCached:     d("pihole_dns_queries_cached_total", "Pi-hole DNS queries answered from local cache today (resets at midnight)."),
		queriesByType:     d("pihole_dns_queries_by_type_total", "Pi-hole DNS queries today, partitioned by record type (resets at midnight).", "type"),
		queriesByStatus:   d("pihole_dns_queries_by_status_total", "Pi-hole DNS queries today, partitioned by FTL status (resets at midnight).", "status"),
		queriesByReply:    d("pihole_dns_queries_by_reply_total", "Pi-hole DNS queries today, partitioned by reply category (resets at midnight).", "reply"),
		queriesUnique:     d("pihole_dns_queries_unique_domains", "Distinct domains queried today (gauge)."),
		queriesFrequency:  d("pihole_dns_queries_per_second", "Pi-hole's reported short-window query rate (gauge)."),
		queriesPctBlocked: d("pihole_dns_queries_blocked_ratio", "Fraction of today's queries that were blocked (0–1)."),

		clientsActive: d("pihole_dns_clients_active", "Distinct clients seen in the rolling active window."),
		clientsTotal:  d("pihole_dns_clients_total", "Distinct clients ever seen by this Pi-hole."),

		gravityDomains:      d("pihole_gravity_domains", "Number of domains in the gravity (blocklist) table."),
		gravityLastUpdateTs: d("pihole_gravity_last_update_timestamp_seconds", "Unix timestamp of the last gravity database refresh."),

		upstreamQueries:      d("pihole_dns_upstream_queries_total", "Today's queries forwarded to a given upstream destination (resets at midnight).", "upstream", "ip", "port"),
		upstreamResponseSecs: d("pihole_dns_upstream_response_seconds", "Mean response time from a given upstream destination (Pi-hole's reported value).", "upstream", "ip", "port"),
		upstreamVarianceSecs: d("pihole_dns_upstream_response_variance_seconds", "Variance of response time from a given upstream destination (Pi-hole's reported value).", "upstream", "ip", "port"),

		blockingEnabled: d("pihole_blocking_enabled", "1 if Pi-hole's blocking is currently enabled, 0 otherwise (disabled / failed / unknown)."),

		ftlPrivacyLevel:   d("pihole_ftl_privacy_level", "FTL privacy level (0=show everything … 3=anonymous)."),
		ftlMemPercent:     d("pihole_ftl_memory_percent", "FTL daemon memory usage (percent of system memory)."),
		ftlCPUPercent:     d("pihole_ftl_cpu_percent", "FTL daemon CPU usage (percent)."),
		ftlClientsActive:  d("pihole_ftl_clients_active", "Active client count reported by FTL."),
		ftlClientsTotal:   d("pihole_ftl_clients_total", "Total client count reported by FTL."),
		dnsmasqCacheIns:   d("pihole_dnsmasq_cache_inserted_total", "dnsmasq cache insertions since FTL start."),
		dnsmasqCacheFreed: d("pihole_dnsmasq_cache_live_freed_total", "dnsmasq cache entries evicted live since FTL start."),
		dnsmasqForwarded:  d("pihole_dnsmasq_queries_forwarded_total", "dnsmasq queries forwarded since FTL start."),
		dnsmasqAuth:       d("pihole_dnsmasq_queries_auth_answered_total", "dnsmasq queries answered authoritatively since FTL start."),
		dnsmasqLocal:      d("pihole_dnsmasq_queries_local_answered_total", "dnsmasq queries answered locally since FTL start."),
		dnsmasqStale:      d("pihole_dnsmasq_queries_stale_answered_total", "dnsmasq queries answered from stale cache since FTL start."),
		dnsmasqUnanswered: d("pihole_dnsmasq_queries_unanswered_total", "dnsmasq queries left unanswered since FTL start."),

		ftlDHCPMessages:        d("pihole_ftl_dhcp_messages_total", "DHCP messages observed by Pi-hole's FTL since start, partitioned by message type. Source: /api/info/ftl. Coexists with the log-tailer's pihole_dhcp_messages_total — operators can enable either or both depending on data-source preference.", "type"),
		ftlDHCPLeasesAllocated: d("pihole_ftl_dhcp_leases_allocated_total", "DHCP leases ever allocated by Pi-hole's FTL since start, partitioned by IP family.", "family"),
		ftlDHCPLeasesPruned:    d("pihole_ftl_dhcp_leases_pruned_total", "DHCP leases pruned (expired, freed) since FTL start, partitioned by IP family. Currently-active leases approximate to allocated − pruned.", "family"),

		info: d("pihole_info", "Pi-hole component versions reported by the API. Always 1; labels carry the strings.", "core_version", "ftl_version", "web_version"),

		// Per-collector health gauge — `collector` is a CONST label
		// here (not a variable label) so each collector's instance of
		// this Desc has a different identity in Prometheus's registry.
		// Otherwise three collectors declaring `pihole_collector_up`
		// with identical const labels would all collide and crash
		// MustRegister (Pi-hole v6 #issue surfaced when DNS + leases +
		// log all run on the same systemd-mode host).
		collectorUp: prometheus.NewDesc(
			"pihole_collector_up",
			"1 if a given collector group's scrape succeeded, 0 otherwise.",
			nil,
			prometheus.Labels{"instance": instance, "collector": "dns"},
		),
	}
}

func (c *dnsCollector) Describe(ch chan<- *prometheus.Desc) {
	descs := []*prometheus.Desc{
		c.queriesTotal, c.queriesBlocked, c.queriesForwarded, c.queriesCached,
		c.queriesByType, c.queriesByStatus, c.queriesByReply,
		c.queriesUnique, c.queriesFrequency, c.queriesPctBlocked,
		c.clientsActive, c.clientsTotal,
		c.gravityDomains, c.gravityLastUpdateTs,
		c.upstreamQueries, c.upstreamResponseSecs, c.upstreamVarianceSecs,
		c.blockingEnabled,
		c.ftlPrivacyLevel, c.ftlMemPercent, c.ftlCPUPercent,
		c.ftlClientsActive, c.ftlClientsTotal,
		c.dnsmasqCacheIns, c.dnsmasqCacheFreed, c.dnsmasqForwarded,
		c.dnsmasqAuth, c.dnsmasqLocal, c.dnsmasqStale, c.dnsmasqUnanswered,
		c.ftlDHCPMessages, c.ftlDHCPLeasesAllocated, c.ftlDHCPLeasesPruned,
		c.info, c.collectorUp,
	}
	for _, d := range descs {
		ch <- d
	}
}

// Collect runs the configured Pi-hole REST calls and emits one batch of
// metrics. The collector splits work across four endpoints, each guarded
// independently — a single failed endpoint still lets the others publish
// what they got. `pihole_collector_up{collector="dns"}` ends as 1 only
// when every endpoint succeeded.
func (c *dnsCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allOK := true

	var summary pihole.StatsSummary
	if err := c.client.Get(ctx, "/api/stats/summary", &summary); err != nil {
		c.logger.Warn("dns: summary failed", "instance", c.instance, "err", err)
		allOK = false
	} else {
		c.emitSummary(ch, summary)
	}

	var upstreams pihole.StatsUpstreams
	if err := c.client.Get(ctx, "/api/stats/upstreams", &upstreams); err != nil {
		c.logger.Warn("dns: upstreams failed", "instance", c.instance, "err", err)
		allOK = false
	} else {
		c.emitUpstreams(ch, upstreams)
	}

	var blocking pihole.DNSBlocking
	if err := c.client.Get(ctx, "/api/dns/blocking", &blocking); err != nil {
		c.logger.Warn("dns: blocking failed", "instance", c.instance, "err", err)
		allOK = false
	} else {
		ch <- prometheus.MustNewConstMetric(c.blockingEnabled, prometheus.GaugeValue, blocking.Enabled())
	}

	var ftl pihole.InfoFTL
	if err := c.client.Get(ctx, "/api/info/ftl", &ftl); err != nil {
		c.logger.Warn("dns: ftl info failed", "instance", c.instance, "err", err)
		allOK = false
	} else {
		c.emitFTL(ch, ftl)
	}

	var ver pihole.InfoVersion
	if err := c.client.Get(ctx, "/api/info/version", &ver); err != nil {
		c.logger.Warn("dns: version info failed", "instance", c.instance, "err", err)
		allOK = false
	} else {
		ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1,
			ver.CoreVersion(), ver.FTLVersion(), ver.WebVersion())
	}

	upVal := 0.0
	if allOK {
		upVal = 1
	}
	ch <- prometheus.MustNewConstMetric(c.collectorUp, prometheus.GaugeValue, upVal)
}

func (c *dnsCollector) emitSummary(ch chan<- prometheus.Metric, s pihole.StatsSummary) {
	q := s.Queries
	ch <- prometheus.MustNewConstMetric(c.queriesTotal, prometheus.CounterValue, float64(q.Total))
	ch <- prometheus.MustNewConstMetric(c.queriesBlocked, prometheus.CounterValue, float64(q.Blocked))
	ch <- prometheus.MustNewConstMetric(c.queriesForwarded, prometheus.CounterValue, float64(q.Forwarded))
	ch <- prometheus.MustNewConstMetric(c.queriesCached, prometheus.CounterValue, float64(q.Cached))
	ch <- prometheus.MustNewConstMetric(c.queriesUnique, prometheus.GaugeValue, float64(q.UniqueDomains))
	ch <- prometheus.MustNewConstMetric(c.queriesFrequency, prometheus.GaugeValue, q.Frequency)
	ch <- prometheus.MustNewConstMetric(c.queriesPctBlocked, prometheus.GaugeValue, q.PercentBlocked/100)

	for k, v := range q.Types {
		ch <- prometheus.MustNewConstMetric(c.queriesByType, prometheus.CounterValue, float64(v), strings.ToUpper(k))
	}
	for k, v := range q.Status {
		ch <- prometheus.MustNewConstMetric(c.queriesByStatus, prometheus.CounterValue, float64(v), k)
	}
	for k, v := range q.Replies {
		ch <- prometheus.MustNewConstMetric(c.queriesByReply, prometheus.CounterValue, float64(v), k)
	}

	ch <- prometheus.MustNewConstMetric(c.clientsActive, prometheus.GaugeValue, float64(s.Clients.Active))
	ch <- prometheus.MustNewConstMetric(c.clientsTotal, prometheus.GaugeValue, float64(s.Clients.Total))

	ch <- prometheus.MustNewConstMetric(c.gravityDomains, prometheus.GaugeValue, float64(s.Gravity.DomainsBeingBlocked))
	ch <- prometheus.MustNewConstMetric(c.gravityLastUpdateTs, prometheus.GaugeValue, float64(s.Gravity.LastUpdate))
}

func (c *dnsCollector) emitUpstreams(ch chan<- prometheus.Metric, u pihole.StatsUpstreams) {
	for _, up := range u.Upstreams {
		port := upstreamPortLabel(up.Port)
		ch <- prometheus.MustNewConstMetric(c.upstreamQueries, prometheus.CounterValue, float64(up.Count), up.Name, up.IP, port)
		ch <- prometheus.MustNewConstMetric(c.upstreamResponseSecs, prometheus.GaugeValue, up.Statistics.Response, up.Name, up.IP, port)
		ch <- prometheus.MustNewConstMetric(c.upstreamVarianceSecs, prometheus.GaugeValue, up.Statistics.Variance, up.Name, up.IP, port)
	}
}

func (c *dnsCollector) emitFTL(ch chan<- prometheus.Metric, ftl pihole.InfoFTL) {
	f := ftl.FTL
	ch <- prometheus.MustNewConstMetric(c.ftlPrivacyLevel, prometheus.GaugeValue, float64(f.PrivacyLevel))
	ch <- prometheus.MustNewConstMetric(c.ftlMemPercent, prometheus.GaugeValue, f.MemPercent)
	ch <- prometheus.MustNewConstMetric(c.ftlCPUPercent, prometheus.GaugeValue, f.CPUPercent)
	ch <- prometheus.MustNewConstMetric(c.ftlClientsActive, prometheus.GaugeValue, float64(f.Clients.Active))
	ch <- prometheus.MustNewConstMetric(c.ftlClientsTotal, prometheus.GaugeValue, float64(f.Clients.Total))

	d := f.DNSMasq
	ch <- prometheus.MustNewConstMetric(c.dnsmasqCacheIns, prometheus.CounterValue, float64(d.DNSCacheInserted))
	ch <- prometheus.MustNewConstMetric(c.dnsmasqCacheFreed, prometheus.CounterValue, float64(d.DNSCacheLiveFreed))
	ch <- prometheus.MustNewConstMetric(c.dnsmasqForwarded, prometheus.CounterValue, float64(d.DNSQueriesForwarded))
	ch <- prometheus.MustNewConstMetric(c.dnsmasqAuth, prometheus.CounterValue, float64(d.DNSAuthAnswered))
	ch <- prometheus.MustNewConstMetric(c.dnsmasqLocal, prometheus.CounterValue, float64(d.DNSLocalAnswered))
	ch <- prometheus.MustNewConstMetric(c.dnsmasqStale, prometheus.CounterValue, float64(d.DNSStaleAnswered))
	ch <- prometheus.MustNewConstMetric(c.dnsmasqUnanswered, prometheus.CounterValue, float64(d.DNSUnanswered))

	// Always-emit zero rows for the v4 DHCP message types so rate()
	// queries don't need absent() guards. Mirrors the log-tailer's
	// pattern.
	dhcpByType := map[string]int64{
		"DHCPACK":      d.DHCPAck,
		"DHCPNAK":      d.DHCPNak,
		"DHCPOFFER":    d.DHCPOffer,
		"DHCPREQUEST":  d.DHCPRequest,
		"DHCPDECLINE":  d.DHCPDecline,
		"DHCPRELEASE":  d.DHCPRelease,
		"DHCPDISCOVER": d.DHCPDiscover,
		"DHCPINFORM":   d.DHCPInform,
	}
	for t, v := range dhcpByType {
		ch <- prometheus.MustNewConstMetric(c.ftlDHCPMessages, prometheus.CounterValue, float64(v), t)
	}
	ch <- prometheus.MustNewConstMetric(c.ftlDHCPLeasesAllocated, prometheus.CounterValue, float64(d.LeasesAllocated4), "ipv4")
	ch <- prometheus.MustNewConstMetric(c.ftlDHCPLeasesAllocated, prometheus.CounterValue, float64(d.LeasesAllocated6), "ipv6")
	ch <- prometheus.MustNewConstMetric(c.ftlDHCPLeasesPruned, prometheus.CounterValue, float64(d.LeasesPruned4), "ipv4")
	ch <- prometheus.MustNewConstMetric(c.ftlDHCPLeasesPruned, prometheus.CounterValue, float64(d.LeasesPruned6), "ipv6")
}

func upstreamPortLabel(p int) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(p)
}
