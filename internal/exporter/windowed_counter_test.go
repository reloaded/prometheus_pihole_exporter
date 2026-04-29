package exporter

import (
	"sync"
	"testing"
)

func TestWindowedCounter_PrimeReturnsZero(t *testing.T) {
	t.Parallel()
	var w windowedCounter
	if got := w.observe(12345); got != 0 {
		t.Errorf("first observe should seed baseline and return 0, got %d", got)
	}
}

func TestWindowedCounter_PositiveDeltasAccumulate(t *testing.T) {
	t.Parallel()
	var w windowedCounter
	w.observe(100) // prime
	cases := []struct {
		current int64
		want    int64 // expected lifetime
	}{
		{105, 5},
		{120, 20},
		{200, 100},
		{200, 100}, // no change
	}
	for i, tc := range cases {
		if got := w.observe(tc.current); got != tc.want {
			t.Errorf("step %d: observe(%d) = %d, want %d", i, tc.current, got, tc.want)
		}
	}
}

func TestWindowedCounter_FlushIsSkipped(t *testing.T) {
	t.Parallel()
	// Reproduces the failure mode behind PR #N: Pi-hole's 24h-rolling
	// total drops at every FTL flush cycle. With raw forwarding the
	// drop becomes a counter "reset" and rate() spikes. The
	// accumulator must absorb the drop without rolling lifetime
	// backwards or re-counting the dropped values on the next rise.
	var w windowedCounter
	w.observe(207_195) // prime at the value that observed the bug
	got := w.observe(208_000)
	if got != 805 {
		t.Fatalf("post-prime delta: got %d, want 805", got)
	}
	got = w.observe(206_424) // window flush — counter drops 1 576 below previous
	if got != 805 {
		t.Fatalf("flush should not roll lifetime backwards: got %d, want 805", got)
	}
	got = w.observe(207_000) // post-flush growth; only the 207 000 - 206 424 = 576 above the new floor counts
	if got != 805+576 {
		t.Fatalf("post-flush growth: got %d, want %d", got, 805+576)
	}
}

func TestWindowedCounter_ConcurrentObserveIsRaceFree(t *testing.T) {
	t.Parallel()
	// observe() must be safe under concurrent calls — promhttp can
	// invoke Describe and Collect on overlapping goroutines on the
	// same registered collector. Run -race against this and rely on
	// the race detector to catch any unsynchronized field access;
	// the value assertions only sanity-check that accumulation
	// actually happens (a deadlocked or no-op observe() would leave
	// lifetime at 0).
	var w windowedCounter
	w.observe(0) // prime

	var wg sync.WaitGroup
	const goroutines = 8
	const ticks = 250
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 1; i <= ticks; i++ {
				w.observe(int64(i))
			}
		}()
	}
	wg.Wait()
	if w.lifetime < 1 {
		t.Errorf("no accumulation observed under concurrent observe(): lifetime=%d", w.lifetime)
	}
}

func TestWindowedCounters_KeyedByLabelTuple(t *testing.T) {
	t.Parallel()
	wc := newWindowedCounters()
	// Two label tuples that share a prefix — must not collide via
	// naive string concatenation.
	if got := wc.observe(10, "a", "b"); got != 0 {
		t.Errorf("first observe of (a, b): got %d, want 0 (prime)", got)
	}
	if got := wc.observe(10, "ab"); got != 0 {
		t.Errorf("first observe of (ab): got %d, want 0 (prime, distinct tuple)", got)
	}
	if got := wc.observe(15, "a", "b"); got != 5 {
		t.Errorf("second observe of (a, b): got %d, want 5", got)
	}
	if got := wc.observe(100, "ab"); got != 90 {
		t.Errorf("second observe of (ab): got %d, want 90", got)
	}
	// (a, b) lifetime must not have been bumped by the "ab" call.
	if got := wc.observe(15, "a", "b"); got != 5 {
		t.Errorf("third observe of (a, b): got %d, want 5 (no change since previous)", got)
	}
}

func TestWindowedCounters_NoLabelsKey(t *testing.T) {
	t.Parallel()
	wc := newWindowedCounters()
	if got := wc.observe(50); got != 0 {
		t.Fatalf("zero-label first observe: got %d, want 0", got)
	}
	if got := wc.observe(75); got != 25 {
		t.Fatalf("zero-label second observe: got %d, want 25", got)
	}
}
