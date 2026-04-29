package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

// Overrides is the global override layer over per-instance YAML
// collector toggles (issue #1). Each field is *bool: nil means "no
// override — use the YAML setting (or its default)". Set to a
// non-nil value, the override applies to every instance the exporter
// knows about.
//
// Truthy overrides for the DHCP collectors only enable the collector
// when the per-instance YAML has the corresponding section populated
// (e.g. `collectors.dhcp_leases.path` must be set). The override is a
// kill-switch / opt-in; it doesn't synthesise paths the YAML doesn't
// supply.
type Overrides struct {
	DNS        *bool
	DHCPLeases *bool
	DHCPLog    *bool
}

// Override-flag names. Exported so tests and main can reference them
// without restating the strings.
const (
	flagDNS        = "collector.dns"
	flagDHCPLeases = "collector.dhcp-leases"
	flagDHCPLog    = "collector.dhcp-log"

	envDNS        = "PIHOLE_EXPORTER_COLLECTOR_DNS"
	envDHCPLeases = "PIHOLE_EXPORTER_COLLECTOR_DHCP_LEASES"
	envDHCPLog    = "PIHOLE_EXPORTER_COLLECTOR_DHCP_LOG"
)

// RegisterOverrides binds the collector-override flags onto fs.
// Returns a resolver that the caller invokes after fs.Parse() to
// produce the final Overrides struct. Splitting registration from
// resolution lets main keep using the global flag set while remaining
// testable: tests can pass a fresh FlagSet + custom argv + custom
// getenv to drive the precedence ladder deterministically.
//
// Precedence (highest first): CLI flag → env var → unset (== nil).
func RegisterOverrides(fs *flag.FlagSet, getenv func(string) string) func() (Overrides, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	dns := fs.String(flagDNS, getenv(envDNS),
		"Global override for the DNS collector toggle. true|false; empty = use per-instance YAML. Env: "+envDNS+".")
	dhcpLeases := fs.String(flagDHCPLeases, getenv(envDHCPLeases),
		"Global override for the DHCP-leases collector toggle. true|false; empty = use per-instance YAML. Truthy values still require collectors.dhcp_leases.path to be set per instance. Env: "+envDHCPLeases+".")
	dhcpLog := fs.String(flagDHCPLog, getenv(envDHCPLog),
		"Global override for the DHCP-log collector toggle. true|false; empty = use per-instance YAML. Truthy values still require collectors.dhcp_log.path to be set per instance. Env: "+envDHCPLog+".")

	return func() (Overrides, error) {
		var o Overrides
		for _, e := range []struct {
			flagName string
			raw      *string
			dst      **bool
		}{
			{flagDNS, dns, &o.DNS},
			{flagDHCPLeases, dhcpLeases, &o.DHCPLeases},
			{flagDHCPLog, dhcpLog, &o.DHCPLog},
		} {
			if *e.raw == "" {
				continue
			}
			b, err := strconv.ParseBool(*e.raw)
			if err != nil {
				return Overrides{}, fmt.Errorf("-%s: %q is not a boolean (accepted: true,false,1,0,t,f)", e.flagName, *e.raw)
			}
			*e.dst = &b
		}
		return o, nil
	}
}

// EffectiveDNS returns the effective DNS-collector toggle for inst,
// taking the global override into account. DNS doesn't require any
// per-instance YAML config beyond the instance existing, so the
// override always wins when set.
func (o Overrides) EffectiveDNS(inst Instance) bool {
	if o.DNS != nil {
		return *o.DNS
	}
	if inst.Collectors.DNS == nil {
		return true
	}
	return *inst.Collectors.DNS
}

// EffectiveDHCPLeases returns the effective DHCP-leases toggle for
// inst. A truthy override only enables the collector when the YAML
// supplies a path; without the path there's nothing for the collector
// to read. A falsy override unconditionally disables.
func (o Overrides) EffectiveDHCPLeases(inst Instance) bool {
	yamlEnabled := inst.Collectors.DHCPLeases != nil && inst.Collectors.DHCPLeases.Path != ""
	if o.DHCPLeases == nil {
		return yamlEnabled
	}
	if !*o.DHCPLeases {
		return false
	}
	return yamlEnabled
}

// EffectiveDHCPLog mirrors EffectiveDHCPLeases. Truthy override + YAML
// path required; falsy override always wins.
func (o Overrides) EffectiveDHCPLog(inst Instance) bool {
	yamlEnabled := inst.Collectors.DHCPLog != nil && inst.Collectors.DHCPLog.Path != ""
	if o.DHCPLog == nil {
		return yamlEnabled
	}
	if !*o.DHCPLog {
		return false
	}
	return yamlEnabled
}
