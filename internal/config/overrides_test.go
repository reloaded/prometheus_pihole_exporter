package config

import (
	"flag"
	"strings"
	"testing"
)

// boolPtr is the test-side counterpart to the *bool fields on
// Overrides + Collectors. Inline-able but easier to read this way.
func boolPtr(b bool) *bool { return &b }

func TestRegisterOverrides_PrecedenceCLIBeatsEnv(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	getenv := func(k string) string {
		switch k {
		case envDNS:
			return "false" // env says off
		default:
			return ""
		}
	}
	resolve := RegisterOverrides(fs, getenv)
	if err := fs.Parse([]string{"-collector.dns=true"}); err != nil { // CLI says on
		t.Fatalf("parse: %v", err)
	}

	got, err := resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.DNS == nil || *got.DNS != true {
		t.Fatalf("CLI should have beaten env; got DNS=%v", got.DNS)
	}
}

func TestRegisterOverrides_EnvUsedWhenCLIAbsent(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	getenv := func(k string) string {
		switch k {
		case envDHCPLeases:
			return "1"
		default:
			return ""
		}
	}
	resolve := RegisterOverrides(fs, getenv)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, err := resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.DHCPLeases == nil || *got.DHCPLeases != true {
		t.Fatalf("env should have set DHCPLeases=true; got %v", got.DHCPLeases)
	}
	if got.DNS != nil || got.DHCPLog != nil {
		t.Fatalf("only DHCPLeases should be set; got %+v", got)
	}
}

func TestRegisterOverrides_BothUnsetMeansNil(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	resolve := RegisterOverrides(fs, func(string) string { return "" })
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.DNS != nil || got.DHCPLeases != nil || got.DHCPLog != nil {
		t.Fatalf("all overrides should be nil; got %+v", got)
	}
}

func TestRegisterOverrides_AcceptsParseBoolForms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want bool
	}{
		{"true", true},
		{"TRUE", true},
		{"1", true},
		{"t", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"f", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			resolve := RegisterOverrides(fs, func(string) string { return "" })
			if err := fs.Parse([]string{"-collector.dns=" + tc.raw}); err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := resolve()
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got.DNS == nil || *got.DNS != tc.want {
				t.Fatalf("raw %q → DNS=%v, want %v", tc.raw, got.DNS, tc.want)
			}
		})
	}
}

func TestRegisterOverrides_RejectsGarbage(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	resolve := RegisterOverrides(fs, func(string) string { return "" })
	if err := fs.Parse([]string{"-collector.dns=maybe"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err := resolve()
	if err == nil {
		t.Fatal("expected error for non-boolean value, got nil")
	}
	if !strings.Contains(err.Error(), "collector.dns") {
		t.Fatalf("error should name the offending flag; got %v", err)
	}
}

func TestEffectiveDNS_PrecedenceTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		override *bool
		yaml     *bool
		want     bool
	}{
		{"unset → defaults to true", nil, nil, true},
		{"yaml-only true", nil, boolPtr(true), true},
		{"yaml-only false", nil, boolPtr(false), false},
		{"override true wins over yaml false", boolPtr(true), boolPtr(false), true},
		{"override false wins over yaml true", boolPtr(false), boolPtr(true), false},
		{"override true with no yaml", boolPtr(true), nil, true},
		{"override false with no yaml", boolPtr(false), nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := Instance{Collectors: Collectors{DNS: tc.yaml}}
			o := Overrides{DNS: tc.override}
			if got := o.EffectiveDNS(inst); got != tc.want {
				t.Fatalf("EffectiveDNS = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEffectiveDHCPLeases_TruthyOverrideStillNeedsYAMLPath(t *testing.T) {
	t.Parallel()

	withPath := Instance{Collectors: Collectors{DHCPLeases: &DHCPLeasesConfig{Path: "/etc/pihole/dhcp.leases"}}}
	withoutPath := Instance{} // no DHCPLeases section at all

	cases := []struct {
		name     string
		inst     Instance
		override *bool
		want     bool
	}{
		// No override → YAML decides.
		{"unset + path = on", withPath, nil, true},
		{"unset + no-path = off", withoutPath, nil, false},

		// Truthy override only enables when YAML supplied a path.
		{"override-true + path = on", withPath, boolPtr(true), true},
		{"override-true + no-path = STILL off (override can't synthesise path)", withoutPath, boolPtr(true), false},

		// Falsy override always wins.
		{"override-false + path = off", withPath, boolPtr(false), false},
		{"override-false + no-path = off", withoutPath, boolPtr(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := Overrides{DHCPLeases: tc.override}
			if got := o.EffectiveDHCPLeases(tc.inst); got != tc.want {
				t.Fatalf("EffectiveDHCPLeases = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEffectiveDHCPLog_TruthyOverrideStillNeedsYAMLPath(t *testing.T) {
	t.Parallel()

	withPath := Instance{Collectors: Collectors{DHCPLog: &DHCPLogConfig{Path: "/var/log/pihole/pihole.log"}}}
	withoutPath := Instance{}

	cases := []struct {
		name     string
		inst     Instance
		override *bool
		want     bool
	}{
		{"unset + path = on", withPath, nil, true},
		{"unset + no-path = off", withoutPath, nil, false},
		{"override-true + path = on", withPath, boolPtr(true), true},
		{"override-true + no-path = off", withoutPath, boolPtr(true), false},
		{"override-false + path = off", withPath, boolPtr(false), false},
		{"override-false + no-path = off", withoutPath, boolPtr(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := Overrides{DHCPLog: tc.override}
			if got := o.EffectiveDHCPLog(tc.inst); got != tc.want {
				t.Fatalf("EffectiveDHCPLog = %v, want %v", got, tc.want)
			}
		})
	}
}
