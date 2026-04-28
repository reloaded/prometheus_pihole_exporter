package exporter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// dhcpLogState is a long-lived counter holder for one Pi-hole's
// dnsmasq log. The tailer goroutine appends new events into the
// counters; the prometheus.Collector built around it just snapshots
// the current values when scraped.
type dhcpLogState struct {
	instance string
	path     string
	logger   *slog.Logger

	mu             sync.Mutex
	msgCounts      map[string]int64 // canonical message type → count
	parseErrors    int64
	lastEvent      int64 // unix seconds
	lastTailError  string
	lastTailErrAt  int64 // unix seconds
	healthyTailing bool
}

func newDHCPLogState(instance, path string, logger *slog.Logger) *dhcpLogState {
	return &dhcpLogState{
		instance:  instance,
		path:      path,
		logger:    logger.With("collector", "dhcp_log", "instance", instance),
		msgCounts: map[string]int64{},
	}
}

// dhcpMessageRE matches dnsmasq DHCP log lines. The interesting bit is
// the message-type word ("DHCPACK", "DHCPOFFER", …). Examples:
//
//	Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:ff
//	Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPOFFER(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff
//	Apr 28 19:00:01 dnsmasq-dhcp[1234]: DHCPACK(eth0) 192.168.0.50 aa:bb:cc:dd:ee:ff hostname-here
//
// The regex is anchored on a word boundary so DHCPv6 message-types
// (DHCP6SOLICIT etc.) match too — those decay into the canonical
// `DHCPv6` bucket so v4 and v6 don't collide.
var dhcpMessageRE = regexp.MustCompile(`\b(DHCP(?:ACK|NAK|OFFER|REQUEST|DECLINE|RELEASE|DISCOVER|INFORM|6[A-Z]+))\b`)

func (s *dhcpLogState) processLine(line string) {
	m := dhcpMessageRE.FindStringSubmatch(line)
	if m == nil {
		return
	}
	msg := m[1]
	bucket := canonicalMessageType(msg)
	s.mu.Lock()
	s.msgCounts[bucket]++
	s.lastEvent = time.Now().Unix()
	s.mu.Unlock()
}

func canonicalMessageType(raw string) string {
	if len(raw) >= 5 && raw[:5] == "DHCP6" {
		return "DHCPv6"
	}
	return raw
}

// run owns the tail loop until ctx is done. It re-opens the file on
// every iteration so log-rotation doesn't strand the descriptor; it
// detects truncation by inode change or by size shrink and resets the
// read offset accordingly.
func (s *dhcpLogState) run(ctx context.Context) {
	var (
		pos       int64
		lastInode uint64
	)
	const idle = 1 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := func() error {
			f, err := os.Open(s.path) //nolint:gosec // operator-controlled path
			if err != nil {
				return err
			}
			defer f.Close()

			st, err := f.Stat()
			if err != nil {
				return err
			}
			ino := inodeOf(st)
			if ino != lastInode || st.Size() < pos {
				// rotation, truncation, or first read: start at end so
				// we don't replay a giant historical log on startup.
				pos = st.Size()
				lastInode = ino
			}
			if _, err := f.Seek(pos, io.SeekStart); err != nil {
				return err
			}

			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for scanner.Scan() {
				s.processLine(scanner.Text())
			}
			if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
				s.mu.Lock()
				s.parseErrors++
				s.mu.Unlock()
			}
			cur, err := f.Seek(0, io.SeekCurrent)
			if err == nil {
				pos = cur
			}
			return nil
		}()

		s.mu.Lock()
		if err != nil {
			s.healthyTailing = false
			s.lastTailError = err.Error()
			s.lastTailErrAt = time.Now().Unix()
		} else {
			s.healthyTailing = true
		}
		s.mu.Unlock()

		if err != nil {
			s.logger.Warn("tail iteration failed", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(idle):
		}
	}
}

func (s *dhcpLogState) snapshot() (map[string]int64, int64, int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.msgCounts))
	for k, v := range s.msgCounts {
		out[k] = v
	}
	return out, s.parseErrors, s.lastEvent, s.healthyTailing
}

// dhcpLogCollector exposes the snapshot of a dhcpLogState as
// Prometheus metrics.
type dhcpLogCollector struct {
	instance string
	state    *dhcpLogState

	descMsgTotal    *prometheus.Desc
	descParseErrors *prometheus.Desc
	descLastEvent   *prometheus.Desc
	descCollectorUp *prometheus.Desc
}

func newDHCPLogCollector(instance string, state *dhcpLogState) prometheus.Collector {
	labels := prometheus.Labels{"instance": instance}
	d := func(name, help string, varLabels ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, varLabels, labels)
	}
	return &dhcpLogCollector{
		instance:        instance,
		state:           state,
		descMsgTotal:    d("pihole_dhcp_messages_total", "Number of DHCP messages observed in the dnsmasq log since the exporter started, partitioned by type.", "type"),
		descParseErrors: d("pihole_dhcp_log_parse_errors_total", "Errors encountered while parsing the dnsmasq log."),
		descLastEvent:   d("pihole_dhcp_log_last_event_timestamp_seconds", "Unix timestamp of the most recently observed DHCP event (0 if none yet)."),
		descCollectorUp: d("pihole_collector_up", "1 if a given collector group's scrape succeeded, 0 otherwise.", "collector"),
	}
}

func (c *dhcpLogCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.descMsgTotal, c.descParseErrors, c.descLastEvent, c.descCollectorUp} {
		ch <- d
	}
}

func (c *dhcpLogCollector) Collect(ch chan<- prometheus.Metric) {
	counts, parseErrors, lastEvent, healthy := c.state.snapshot()

	// Always emit zero rows for the message types operators most
	// commonly alert on, so PromQL `rate(pihole_dhcp_messages_total{
	// type="DHCPNAK"}[5m]) > 0` works without absent() guards.
	always := []string{"DHCPACK", "DHCPNAK", "DHCPOFFER", "DHCPREQUEST", "DHCPDECLINE", "DHCPRELEASE", "DHCPDISCOVER", "DHCPINFORM"}
	emitted := map[string]bool{}
	for _, t := range always {
		ch <- prometheus.MustNewConstMetric(c.descMsgTotal, prometheus.CounterValue, float64(counts[t]), t)
		emitted[t] = true
	}
	// Anything else we've actually observed (e.g. DHCPv6 bucket).
	for k, v := range counts {
		if !emitted[k] {
			ch <- prometheus.MustNewConstMetric(c.descMsgTotal, prometheus.CounterValue, float64(v), k)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.descParseErrors, prometheus.CounterValue, float64(parseErrors))
	ch <- prometheus.MustNewConstMetric(c.descLastEvent, prometheus.GaugeValue, float64(lastEvent))

	upVal := 0.0
	if healthy {
		upVal = 1
	}
	ch <- prometheus.MustNewConstMetric(c.descCollectorUp, prometheus.GaugeValue, upVal, "dhcp_log")
}
