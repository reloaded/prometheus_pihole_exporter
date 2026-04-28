package exporter

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// dhcpLeasesCollector parses Pi-hole's dnsmasq leases file
// (default `/etc/pihole/dhcp.leases`) on each scrape and emits one
// metric per lease plus aggregate counts.
//
// The file format is dnsmasq's standard:
//
//	<expiry-unix> <mac> <ipv4> <hostname> <client-id>
//	<expiry-unix> <iaid-hex> <ipv6> <hostname> <duid>
//	duid <server-duid>      ← skipped (server DUID line)
//
// Hostname can be the literal "*" when the client didn't supply one;
// it's preserved as-is so operators see what dnsmasq saw.
type dhcpLeasesCollector struct {
	instance string
	path     string
	now      func() time.Time // injectable for tests
	logger   *slog.Logger

	leasesActive  *prometheus.Desc
	leasesExpired *prometheus.Desc
	leasesTotal   *prometheus.Desc
	leaseInfo     *prometheus.Desc
	leaseExpires  *prometheus.Desc
	collectorUp   *prometheus.Desc
}

func newDHCPLeasesCollector(instance, path string, logger *slog.Logger) prometheus.Collector {
	const familyLabel = "family"
	const macLabel = "mac"
	const ipLabel = "ip"
	const hostnameLabel = "hostname"
	labels := prometheus.Labels{"instance": instance}
	d := func(name, help string, varLabels ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, varLabels, labels)
	}
	return &dhcpLeasesCollector{
		instance: instance,
		path:     path,
		now:      time.Now,
		logger:   logger,

		leasesActive:  d("pihole_dhcp_leases_active", "Active DHCP leases (expiry in the future), partitioned by IP family.", familyLabel),
		leasesExpired: d("pihole_dhcp_leases_expired", "Expired DHCP leases still present in the leases file, partitioned by IP family.", familyLabel),
		leasesTotal:   d("pihole_dhcp_leases_total", "All DHCP leases in the leases file (active + expired), partitioned by IP family.", familyLabel),
		leaseInfo:     d("pihole_dhcp_lease_info", "Always 1; labels identify a specific DHCP lease.", macLabel, ipLabel, hostnameLabel, familyLabel),
		leaseExpires:  d("pihole_dhcp_lease_expires_timestamp_seconds", "Unix timestamp at which a given DHCP lease expires.", macLabel, ipLabel, hostnameLabel, familyLabel),
		collectorUp:   d("pihole_collector_up", "1 if a given collector group's scrape succeeded, 0 otherwise.", "collector"),
	}
}

func (c *dhcpLeasesCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.leasesActive, c.leasesExpired, c.leasesTotal, c.leaseInfo, c.leaseExpires, c.collectorUp} {
		ch <- d
	}
}

func (c *dhcpLeasesCollector) Collect(ch chan<- prometheus.Metric) {
	leases, err := readLeases(c.path)
	if err != nil {
		c.logger.Warn("dhcp_leases: read failed", "instance", c.instance, "path", c.path, "err", err)
		ch <- prometheus.MustNewConstMetric(c.collectorUp, prometheus.GaugeValue, 0, "dhcp_leases")
		return
	}

	now := c.now()
	counts := map[string][3]int{} // family → [active, expired, total]
	for _, l := range leases {
		key := l.family
		entry := counts[key]
		entry[2]++ // total
		if l.expires.After(now) {
			entry[0]++ // active
		} else {
			entry[1]++ // expired
		}
		counts[key] = entry

		ch <- prometheus.MustNewConstMetric(c.leaseInfo, prometheus.GaugeValue, 1, l.mac, l.ip, l.hostname, l.family)
		ch <- prometheus.MustNewConstMetric(c.leaseExpires, prometheus.GaugeValue, float64(l.expires.Unix()), l.mac, l.ip, l.hostname, l.family)
	}

	// Always emit zero rows for the families the operator may want to
	// alert on, even when no leases of that family exist — saves them
	// from having to use absent() in alerting expressions.
	for _, fam := range []string{"ipv4", "ipv6"} {
		entry := counts[fam]
		ch <- prometheus.MustNewConstMetric(c.leasesActive, prometheus.GaugeValue, float64(entry[0]), fam)
		ch <- prometheus.MustNewConstMetric(c.leasesExpired, prometheus.GaugeValue, float64(entry[1]), fam)
		ch <- prometheus.MustNewConstMetric(c.leasesTotal, prometheus.GaugeValue, float64(entry[2]), fam)
	}

	ch <- prometheus.MustNewConstMetric(c.collectorUp, prometheus.GaugeValue, 1, "dhcp_leases")
}

// lease is one parsed entry from the leases file.
type lease struct {
	expires  time.Time
	mac      string // empty for IPv6 entries (DUID is in client-id position)
	ip       string
	hostname string
	family   string // "ipv4" or "ipv6"
}

// readLeases opens the file and parses every well-formed line. Empty
// lines and the `duid <server-duid>` header line are skipped silently.
func readLeases(path string) ([]lease, error) {
	if path == "" {
		return nil, errors.New("dhcp_leases: empty path")
	}
	f, err := os.Open(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseLeases(f)
}

func parseLeases(r io.Reader) ([]lease, error) {
	var out []lease
	scanner := bufio.NewScanner(r)
	// dnsmasq lines are short, but allow up to 64KiB to cover absurdly
	// long client IDs without blowing up.
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Lines starting with "duid " carry the server DUID, not a lease.
		if strings.HasPrefix(line, "duid ") || line == "duid" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		expSec, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		ip := fields[2]
		family := "ipv4"
		if strings.Contains(ip, ":") {
			family = "ipv6"
		}

		hostname := "*"
		if len(fields) >= 4 {
			hostname = fields[3]
		}

		mac := ""
		if family == "ipv4" {
			mac = strings.ToLower(fields[1])
		}

		out = append(out, lease{
			expires:  time.Unix(expSec, 0),
			mac:      mac,
			ip:       ip,
			hostname: hostname,
			family:   family,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
