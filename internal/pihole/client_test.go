package pihole

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_Auth_Success(t *testing.T) {
	t.Parallel()

	var authCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			authCalls.Add(1)
			var body struct {
				Password string `json:"password"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Password != "secret" {
				http.Error(w, `{"session":{"valid":false,"message":"bad password"}}`, http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(authResponse{Session: struct {
				Valid    bool   `json:"valid"`
				TOTP     bool   `json:"totp"`
				SID      string `json:"sid"`
				CSRF     string `json:"csrf"`
				Validity int    `json:"validity"`
				Message  string `json:"message"`
			}{Valid: true, SID: "S1", Validity: 1800}})
		case "/api/stats/summary":
			if r.Header.Get(sidHeader) != "S1" {
				http.Error(w, "missing SID", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"queries":{"total":42}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(Options{BaseURL: srv.URL, Password: "secret", Timeout: 2 * time.Second})

	var summary StatsSummary
	if err := c.Get(context.Background(), "/api/stats/summary", &summary); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if summary.Queries.Total != 42 {
		t.Fatalf("queries.total = %d, want 42", summary.Queries.Total)
	}

	// Second call should reuse the session, not re-auth.
	if err := c.Get(context.Background(), "/api/stats/summary", &summary); err != nil {
		t.Fatalf("Get (cached): %v", err)
	}
	if got := authCalls.Load(); got != 1 {
		t.Fatalf("auth was called %d times, want 1 (session should be cached)", got)
	}
}

func TestClient_ReauthOn401(t *testing.T) {
	t.Parallel()

	var authCalls atomic.Int32
	var statsCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			n := authCalls.Add(1)
			sid := "S1"
			if n == 2 {
				sid = "S2"
			}
			_ = json.NewEncoder(w).Encode(authResponse{Session: struct {
				Valid    bool   `json:"valid"`
				TOTP     bool   `json:"totp"`
				SID      string `json:"sid"`
				CSRF     string `json:"csrf"`
				Validity int    `json:"validity"`
				Message  string `json:"message"`
			}{Valid: true, SID: sid, Validity: 1800}})
		case "/api/stats/summary":
			n := statsCalls.Add(1)
			// First request: session has aged out → 401.
			// Second request (after re-auth): accept S2.
			switch {
			case n == 1:
				http.Error(w, `{"session":{"valid":false}}`, http.StatusUnauthorized)
			case r.Header.Get(sidHeader) == "S2":
				_, _ = w.Write([]byte(`{"queries":{"total":7}}`))
			default:
				http.Error(w, "wrong sid", http.StatusUnauthorized)
			}
		}
	}))
	defer srv.Close()

	c := NewClient(Options{BaseURL: srv.URL, Password: "secret", Timeout: 2 * time.Second})

	var summary StatsSummary
	if err := c.Get(context.Background(), "/api/stats/summary", &summary); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if summary.Queries.Total != 7 {
		t.Fatalf("queries.total = %d, want 7", summary.Queries.Total)
	}
	if got := authCalls.Load(); got != 2 {
		t.Fatalf("auth was called %d times, want 2 (initial + reauth)", got)
	}
}

func TestClient_AuthRejected(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"session":{"valid":false,"message":"bad password"}}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewClient(Options{BaseURL: srv.URL, Password: "wrong"})
	err := c.Get(context.Background(), "/api/stats/summary", &StatsSummary{})
	if err == nil {
		t.Fatal("expected auth error, got nil")
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestClient_EmptyPassword(t *testing.T) {
	t.Parallel()

	c := NewClient(Options{BaseURL: "http://127.0.0.1:1", Password: ""})
	err := c.Get(context.Background(), "/api/stats/summary", &StatsSummary{})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-password error, got %v", err)
	}
}
