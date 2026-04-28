// Package config loads the exporter's YAML configuration.
//
// The config file is the source of truth for which Pi-hole instances the
// exporter knows about, how to authenticate to each, and which collector
// groups are enabled per-instance. The file is read once at process start;
// reload requires a restart (a SIGHUP-driven reload may be added later if
// it turns out to matter).
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration document.
type Config struct {
	// Instances lists every Pi-hole the exporter can probe. The map key
	// (instance ID) is what the user passes as `?target=` to /probe.
	Instances map[string]Instance `yaml:"instances"`
}

// Instance is a single Pi-hole the exporter knows about.
type Instance struct {
	// URL is the base URL of the Pi-hole admin (e.g. http://pihole.example.com).
	// Pi-hole v6's REST API is rooted at <URL>/api.
	URL string `yaml:"url"`

	// AppPasswordEnv names an environment variable containing the Pi-hole
	// app-password (created in the admin UI under Settings → API). The
	// exporter exchanges this for a session SID at scrape time.
	//
	// Stored via env (not inline) so the YAML config is safe to commit.
	AppPasswordEnv string `yaml:"app_password_env"`

	// Timeout caps each upstream HTTP call to Pi-hole. Defaults to 10s.
	Timeout time.Duration `yaml:"timeout"`

	// InsecureSkipVerify disables TLS verification when scraping a Pi-hole
	// served over HTTPS with a self-signed cert. Off by default.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	// Collectors selects which collector groups to run for this instance.
	// Each group can be turned off independently — useful e.g. for a
	// secondary Pi-hole that isn't running DHCP.
	Collectors Collectors `yaml:"collectors"`
}

// Collectors toggles each logical collector group per-instance.
type Collectors struct {
	// DNS pulls statistics from Pi-hole's REST API. On by default.
	DNS *bool `yaml:"dns,omitempty"`

	// DHCPLeases parses the Pi-hole DHCP leases file. Off by default —
	// requires the exporter to have read access to the leases file.
	DHCPLeases *DHCPLeasesConfig `yaml:"dhcp_leases,omitempty"`

	// DHCPLog tails the dnsmasq log to count DHCP message types
	// (DISCOVER / OFFER / REQUEST / ACK / NAK / DECLINE). Off by default —
	// requires read access to the log path.
	DHCPLog *DHCPLogConfig `yaml:"dhcp_log,omitempty"`
}

// DHCPLeasesConfig configures the leases-file collector.
type DHCPLeasesConfig struct {
	// Path is the leases file. Pi-hole's default is
	// /etc/pihole/dhcp.leases. If empty, the collector is disabled.
	Path string `yaml:"path"`
}

// DHCPLogConfig configures the dnsmasq-log tailer.
type DHCPLogConfig struct {
	// Path is the dnsmasq log file. Pi-hole's default is
	// /var/log/pihole/pihole.log. If empty, the collector is disabled.
	Path string `yaml:"path"`
}

// Load reads, parses, and validates the YAML config at the given path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if len(cfg.Instances) == 0 {
		return nil, fmt.Errorf("config has no instances defined")
	}

	for id, inst := range cfg.Instances {
		if inst.URL == "" {
			return nil, fmt.Errorf("instance %q: url is required", id)
		}
		if inst.AppPasswordEnv == "" {
			return nil, fmt.Errorf("instance %q: app_password_env is required", id)
		}
		if inst.Timeout <= 0 {
			inst.Timeout = 10 * time.Second
			cfg.Instances[id] = inst
		}
	}

	return &cfg, nil
}
