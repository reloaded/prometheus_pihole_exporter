package exporter

// dnsCounters bundles the long-lived windowed→monotonic accumulators
// for one Pi-hole instance's DNS collector. Lives on probeHandler so
// it survives across /probe requests — the collector itself is
// rebuilt per request to keep registry state isolated, but the
// accumulator state has to persist or every scrape would re-prime
// the baseline at the upstream's current 24-hour total.
//
// Only metrics whose upstream value is windowed are wrapped here.
// FTL-lifetime counters (the dnsmasq_* family, the FTL DHCP family,
// FTL lease totals) come from FTL's *since-FTL-start* numbers and
// are already monotonic with respect to FTL's process; Prometheus's
// built-in counter-reset handling deals with FTL restarts.
type dnsCounters struct {
	queriesTotal     windowedCounter
	queriesBlocked   windowedCounter
	queriesForwarded windowedCounter
	queriesCached    windowedCounter

	queriesByType   *windowedCounters
	queriesByStatus *windowedCounters
	queriesByReply  *windowedCounters

	upstreamQueries *windowedCounters
}

func newDNSCounters() *dnsCounters {
	return &dnsCounters{
		queriesByType:   newWindowedCounters(),
		queriesByStatus: newWindowedCounters(),
		queriesByReply:  newWindowedCounters(),
		upstreamQueries: newWindowedCounters(),
	}
}
