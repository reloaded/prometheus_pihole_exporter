package exporter

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestParseLeases_FixtureFile(t *testing.T) {
	t.Parallel()

	leases := mustReadFixture(t, "testdata/dhcp.leases")
	if got, want := len(leases), 5; got != want {
		t.Fatalf("len(leases) = %d, want %d", got, want)
	}

	// IPv4 row 1
	got := leases[0]
	if got.ip != "192.168.0.50" || got.mac != "aa:bb:cc:dd:ee:01" || got.hostname != "laptop-a" || got.family != "ipv4" {
		t.Errorf("first lease = %+v", got)
	}
	// MAC is normalised to lowercase even when the file shouts it.
	got = leases[4]
	if got.mac != "aa:bb:cc:dd:ee:04" {
		t.Errorf("mac case-fold: got %q, want lowercased", got.mac)
	}
	// IPv6 row — mac is empty (DUID is in the client-id field, but
	// we don't surface it as `mac=` to avoid mislabelling).
	got = leases[3]
	if got.family != "ipv6" {
		t.Errorf("ipv6 row: family = %q", got.family)
	}
	if got.mac != "" {
		t.Errorf("ipv6 row should have empty mac, got %q", got.mac)
	}
}

func TestDHCPLeasesCollector_Aggregate(t *testing.T) {
	t.Parallel()

	c := newDHCPLeasesCollector("primary", "testdata/dhcp.leases", slog.New(slog.NewTextHandler(io.Discard, nil)))
	cc, ok := c.(*dhcpLeasesCollector)
	if !ok {
		t.Fatalf("expected *dhcpLeasesCollector, got %T", c)
	}
	// Pin "now" earlier than the active rows' expiry, later than the
	// expired row's expiry, so we get 4 active + 1 expired.
	cc.now = func() time.Time { return time.Unix(1700000000, 0) }

	got := gatherText(t, c)

	for _, want := range []string{
		// Active counts
		`pihole_dhcp_leases_active{family="ipv4",instance="primary"} 3`,
		`pihole_dhcp_leases_active{family="ipv6",instance="primary"} 1`,
		// Expired counts (one expired ipv4 in the fixture)
		`pihole_dhcp_leases_expired{family="ipv4",instance="primary"} 1`,
		`pihole_dhcp_leases_expired{family="ipv6",instance="primary"} 0`,
		// Total
		`pihole_dhcp_leases_total{family="ipv4",instance="primary"} 4`,
		`pihole_dhcp_leases_total{family="ipv6",instance="primary"} 1`,
		// Per-lease info gauge (mac case-folded, hostname preserved)
		`pihole_dhcp_lease_info{family="ipv4",hostname="laptop-a",instance="primary",ip="192.168.0.50",mac="aa:bb:cc:dd:ee:01"} 1`,
		// IPv6 entry: mac is empty
		`pihole_dhcp_lease_info{family="ipv6",hostname="ipv6-host",instance="primary",ip="fe80::1",mac=""} 1`,
		// Expiry timestamp
		`pihole_dhcp_lease_expires_timestamp_seconds{family="ipv4",hostname="laptop-a",instance="primary",ip="192.168.0.50",mac="aa:bb:cc:dd:ee:01"} 1.73e+09`,
		// Health
		`pihole_collector_up{collector="dhcp_leases",instance="primary"} 1`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing or different:\n  want: %q\n  got:\n%s", want, got)
		}
	}
}

func TestDHCPLeasesCollector_MissingFile(t *testing.T) {
	t.Parallel()

	c := newDHCPLeasesCollector("primary", "testdata/does-not-exist.leases",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	got := gatherText(t, c)

	if !strings.Contains(got, `pihole_collector_up{collector="dhcp_leases",instance="primary"} 0`) {
		t.Fatalf("expected collector_up=0 on missing file, got:\n%s", got)
	}
	// No per-lease lines.
	if strings.Contains(got, "pihole_dhcp_lease_info") {
		t.Fatalf("did not expect lease info on missing file, got:\n%s", got)
	}
}

func TestDHCPLeasesCollector_EmptyFile(t *testing.T) {
	t.Parallel()

	leases, err := parseLeases(strings.NewReader(""))
	if err != nil {
		t.Fatalf("parseLeases: %v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("expected 0 leases, got %d", len(leases))
	}
}

func TestParseLeases_SkipsMalformed(t *testing.T) {
	t.Parallel()

	in := `
duid 00:01:00:01:server-duid

not-a-number aa:bb:cc:dd:ee:01 192.168.0.50 host 01:00
1730000000 aa:bb:cc:dd:ee:01 192.168.0.50 host 01:00
1730000000 too-few
`
	leases, err := parseLeases(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseLeases: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 lease, got %d (%+v)", len(leases), leases)
	}
}

func mustReadFixture(t *testing.T, path string) []lease {
	t.Helper()
	leases, err := readLeases(path)
	if err != nil {
		t.Fatalf("readLeases(%s): %v", path, err)
	}
	return leases
}
