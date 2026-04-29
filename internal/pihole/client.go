// Package pihole speaks Pi-hole v6's session-based REST API. The client
// trades an "app password" (from Pi-hole's Settings → API admin page) for
// a session ID, caches it across calls, and reauths on a 401 from a
// stale session.
package pihole

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// sidHeader is the HTTP header Pi-hole v6 reads for the session ID.
// The API also accepts ?sid=… as a query parameter; the header is preferred
// because it doesn't show up in access logs.
const sidHeader = "X-FTL-SID"

// Client is safe for concurrent use by multiple goroutines.
type Client struct {
	baseURL  string
	password string
	hc       *http.Client
	now      func() time.Time // injectable for tests

	mu     sync.Mutex
	sid    string
	sidExp time.Time
}

// Options configures a Client.
type Options struct {
	// BaseURL is the Pi-hole admin root, e.g. http://pihole.lan. The
	// trailing /api is added by the client.
	BaseURL string

	// Password is the app-password generated under Settings → API in the
	// Pi-hole admin UI. Pi-hole v6 trades this for a session SID.
	Password string

	// Timeout caps each upstream HTTP call.
	Timeout time.Duration

	// InsecureSkipVerify disables TLS verification for self-signed
	// HTTPS Pi-holes. Off by default.
	InsecureSkipVerify bool
}

// NewClient builds a Client. Validation of the URL/password is deferred
// to the first authenticated call so config-time wiring stays simple.
func NewClient(opts Options) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // operator opt-in for self-signed Pi-holes
			MinVersion:         tls.VersionTLS12,
		},
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL:  strings.TrimRight(opts.BaseURL, "/"),
		password: opts.Password,
		hc: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		now: time.Now,
	}
}

// Get fetches an API path (e.g. "/api/stats/summary") and JSON-decodes
// the body into dst. The caller's context is honoured. A stale session
// triggers exactly one re-auth + retry.
func (c *Client) Get(ctx context.Context, path string, dst any) error {
	return c.do(ctx, http.MethodGet, path, nil, dst)
}

// Ping verifies the client can authenticate without issuing a downstream
// API call. Used by the probe handler to set pihole_up before running
// the per-collector scrape.
func (c *Client) Ping(ctx context.Context) error {
	return c.ensureSession(ctx)
}

// Logout best-effort invalidates the cached session. Failures are
// returned but don't affect the cache (Pi-hole sessions also age out
// server-side, so a client crash isn't catastrophic).
func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	sid := c.sid
	c.mu.Unlock()
	if sid == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/auth", nil)
	if err != nil {
		return err
	}
	req.Header.Set(sidHeader, sid)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	c.mu.Lock()
	c.sid = ""
	c.sidExp = time.Time{}
	c.mu.Unlock()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("logout: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, dst any) error {
	if err := c.ensureSession(ctx); err != nil {
		return err
	}

	if err := c.attempt(ctx, method, path, body, dst); err != nil {
		// One re-auth + retry on a stale session. Pi-hole returns 401
		// with `{"session":{"valid":false,…}}` when the SID has aged out;
		// attempt() reports that as errStaleSession.
		if errors.Is(err, errStaleSession) {
			if err := c.refreshSession(ctx); err != nil {
				return err
			}
			return c.attempt(ctx, method, path, body, dst)
		}
		return err
	}
	return nil
}

// attempt performs a single round-trip + decode. The caller handles
// auth-retry semantics. Splitting this out makes body-close tracking
// trivial: each call owns exactly one response and closes it.
func (c *Client) attempt(ctx context.Context, method, path string, body io.Reader, dst any) error {
	resp, err := c.execute(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return errStaleSession
	}
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pihole %s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(snippet))
	}
	if dst == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// errStaleSession is the internal signal that triggers reauth-and-retry
// inside Client.do.
var errStaleSession = errors.New("pihole: session stale")

func (c *Client) execute(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	sid := c.sid
	c.mu.Unlock()
	if sid != "" {
		req.Header.Set(sidHeader, sid)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return c.hc.Do(req)
}

// ensureSession returns nil if a non-expired session is already cached,
// otherwise authenticates with the configured app password.
func (c *Client) ensureSession(ctx context.Context) error {
	c.mu.Lock()
	fresh := c.sid != "" && c.now().Before(c.sidExp.Add(-30*time.Second))
	c.mu.Unlock()
	if fresh {
		return nil
	}
	return c.refreshSession(ctx)
}

func (c *Client) refreshSession(ctx context.Context) error {
	if c.password == "" {
		return errors.New("pihole: app password is empty")
	}
	body, err := json.Marshal(map[string]string{"password": c.password})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("auth: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(snippet))
	}

	var ar authResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return fmt.Errorf("auth: decode: %w", err)
	}
	if !ar.Session.Valid || ar.Session.SID == "" {
		return fmt.Errorf("auth: rejected: %s", ar.Session.Message)
	}

	validity := time.Duration(ar.Session.Validity) * time.Second
	if validity <= 0 {
		validity = 5 * time.Minute
	}
	c.mu.Lock()
	c.sid = ar.Session.SID
	c.sidExp = c.now().Add(validity)
	c.mu.Unlock()
	return nil
}

// authResponse mirrors POST /api/auth.
type authResponse struct {
	Session struct {
		Valid    bool   `json:"valid"`
		TOTP     bool   `json:"totp"`
		SID      string `json:"sid"`
		CSRF     string `json:"csrf"`
		Validity int    `json:"validity"`
		Message  string `json:"message"`
	} `json:"session"`
	Took float64 `json:"took"`
}
