package exporter

import (
	"strings"
	"sync"
)

// windowedCounter turns a *windowed* upstream value (something that
// reports "queries in the last N hours" rather than "queries since
// upstream start") into a *monotonic* Prometheus counter the rate()
// function can reason about correctly.
//
// Background — Pi-hole's /api/stats/summary returns 24-hour rolling
// totals. The value drifts upward as new queries arrive but
// periodically drops by a small amount (~once per 10 minutes, when
// FTL ages the oldest stats bucket out of the window). Forwarding
// those raw to Prometheus violates the counter contract — Prometheus
// counters never decrease except across a process restart — and
// rate() compensates for what it reads as "counter resets" by
// adding the previous value to the new one. The result is huge
// artificial spikes every flush cycle (a 207 195 → 206 424 drop is
// interpreted as a +206 424 increase, producing thousands of qps
// that didn't actually happen).
//
// Fix — observe upstream values at scrape time and accumulate only
// the *positive* deltas across calls. When the upstream drops
// (window flush), skip the delta: the queries between scrapes that
// fell out of the window before we observed them are unrecoverable
// from this signal. The undercount is bounded by the size of one
// flush bucket (a few hundred queries every ten minutes on a busy
// home network), and rate() now gives the correct qps with no
// spike artefacts.
//
// Concurrency — observe() takes its own mutex. The probe handler
// serializes scrapes for one instance, but the same accumulator can
// be touched concurrently by Describe-vs-Collect on a shared
// registry, so the lock is required.
type windowedCounter struct {
	mu       sync.Mutex
	last     int64
	lifetime int64
	primed   bool
}

// observe records an upstream sample and returns the resulting
// process-lifetime monotonic total. The first call seeds the
// baseline and returns 0 — counting Pi-hole's pre-existing 24-hour
// window as having happened "before we were watching" would emit a
// large spike at exporter start.
func (w *windowedCounter) observe(current int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.primed {
		w.last = current
		w.primed = true
		return 0
	}
	if current >= w.last {
		w.lifetime += current - w.last
	}
	// else: window flush; skip the negative delta.
	w.last = current
	return w.lifetime
}

// windowedCounters indexes accumulators by label tuple, used by
// metrics whose label values are dynamic — queries_by_type,
// queries_by_status, upstream_queries, … One accumulator is
// allocated per distinct label tuple on first observation.
type windowedCounters struct {
	mu sync.Mutex
	by map[string]*windowedCounter
}

func newWindowedCounters() *windowedCounters {
	return &windowedCounters{by: map[string]*windowedCounter{}}
}

// observe records a sample for the given label tuple and returns
// the resulting per-tuple lifetime total. The label tuple is keyed
// by joining values with NUL — same shape Prometheus uses
// internally for its sample maps, so distinct tuples never collide.
func (wc *windowedCounters) observe(current int64, labelValues ...string) int64 {
	key := strings.Join(labelValues, "\x00")
	wc.mu.Lock()
	w, ok := wc.by[key]
	if !ok {
		w = &windowedCounter{}
		wc.by[key] = w
	}
	wc.mu.Unlock()
	return w.observe(current)
}
