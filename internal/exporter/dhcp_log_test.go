package exporter

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDHCPLog_ProcessLine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		line string
		want string
	}{
		{"DHCPDISCOVER", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:ff", "DHCPDISCOVER"},
		{"DHCPOFFER", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPOFFER(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff", "DHCPOFFER"},
		{"DHCPACK", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPACK(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff hostname-here", "DHCPACK"},
		{"DHCPNAK", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPNAK(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff", "DHCPNAK"},
		{"DHCPDECLINE", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPDECLINE(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff", "DHCPDECLINE"},
		{"DHCPRELEASE", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPRELEASE(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff", "DHCPRELEASE"},
		{"DHCPREQUEST", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPREQUEST(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff", "DHCPREQUEST"},
		{"DHCPINFORM", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPINFORM(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff", "DHCPINFORM"},
		{"DHCPv6", "Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCP6SOLICIT(eth0) aa:bb:cc:dd:ee:ff", "DHCPv6"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newDHCPLogState("primary", "/dev/null", slog.New(slog.NewTextHandler(io.Discard, nil)))
			s.processLine(tc.line)
			counts, _, _, _ := s.snapshot()
			if counts[tc.want] != 1 {
				t.Fatalf("counts[%q] = %d, want 1 (full snapshot: %v)", tc.want, counts[tc.want], counts)
			}
		})
	}
}

func TestDHCPLog_IgnoresUnrelatedLines(t *testing.T) {
	t.Parallel()

	s := newDHCPLogState("primary", "/dev/null", slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, l := range []string{
		"Apr 28 19:00:01 dnsmasq[1234]: query[A] example.com from 192.168.0.50",
		"Apr 28 19:00:02 dnsmasq[1234]: forwarded example.com to 9.9.9.9",
		"Apr 28 19:00:03 dnsmasq-dhcp[1234]: read /etc/hosts",
		"",
	} {
		s.processLine(l)
	}
	counts, _, _, _ := s.snapshot()
	if len(counts) != 0 {
		t.Fatalf("expected no DHCP counts from unrelated lines, got %v", counts)
	}
}

// TestDHCPLog_TailsAppendedLines exercises the run loop end-to-end:
// it points the tailer at a temp file, lets it consume the seed lines,
// then appends new lines and verifies the counters update.
func TestDHCPLog_TailsAppendedLines(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "pihole.log")
	if err := os.WriteFile(path, []byte("Apr 28 19:00:00 dnsmasq-dhcp[1234]: DHCPACK(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff\n"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	s := newDHCPLogState("primary", path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.run(ctx)

	// First iteration of run() seeks to end-of-file (so the seed line
	// from before the tailer started is intentionally NOT counted).
	// Wait for the loop to settle, then append one line and assert
	// it gets counted.
	if !waitFor(t, 3*time.Second, func() bool {
		_, _, _, healthy := s.snapshot()
		return healthy
	}) {
		t.Fatal("tailer never reported healthy")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := f.WriteString("Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:ff\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = f.Close()

	if !waitFor(t, 5*time.Second, func() bool {
		counts, _, _, _ := s.snapshot()
		return counts["DHCPDISCOVER"] == 1
	}) {
		counts, _, _, _ := s.snapshot()
		t.Fatalf("appended DHCPDISCOVER not counted; counts=%v", counts)
	}
}

func TestDHCPLogCollector_AlwaysEmitsZeroRows(t *testing.T) {
	t.Parallel()

	s := newDHCPLogState("primary", "/nonexistent", slog.New(slog.NewTextHandler(io.Discard, nil)))
	// processLine just one type, so the collector also has to fill in
	// the rest as zero.
	s.processLine("Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPACK(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff host")

	c := newDHCPLogCollector("primary", s)
	got := gatherText(t, c)

	for _, want := range []string{
		`pihole_dhcp_messages_total{instance="primary",type="DHCPACK"} 1`,
		`pihole_dhcp_messages_total{instance="primary",type="DHCPNAK"} 0`,
		`pihole_dhcp_messages_total{instance="primary",type="DHCPDECLINE"} 0`,
		`pihole_dhcp_messages_total{instance="primary",type="DHCPRELEASE"} 0`,
		`pihole_dhcp_log_parse_errors_total{instance="primary"} 0`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing:\n  want: %q\n  got:\n%s", want, got)
		}
	}
	if !strings.Contains(got, `pihole_collector_up{collector="dhcp_log",instance="primary"} 0`) {
		t.Fatalf("expected collector_up=0 (tailer never ran), got:\n%s", got)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}
