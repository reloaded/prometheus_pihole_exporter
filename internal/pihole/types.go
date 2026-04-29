package pihole

// StatsSummary mirrors GET /api/stats/summary.
//
// All Pi-hole "today" counters reset at midnight server-time, which
// rate()/increase() handle as ordinary counter resets.
type StatsSummary struct {
	Queries struct {
		Total          int64            `json:"total"`
		Blocked        int64            `json:"blocked"`
		PercentBlocked float64          `json:"percent_blocked"`
		UniqueDomains  int64            `json:"unique_domains"`
		Forwarded      int64            `json:"forwarded"`
		Cached         int64            `json:"cached"`
		Frequency      float64          `json:"frequency"`
		Types          map[string]int64 `json:"types"`
		Status         map[string]int64 `json:"status"`
		Replies        map[string]int64 `json:"replies"`
	} `json:"queries"`
	Clients struct {
		Active int64 `json:"active"`
		Total  int64 `json:"total"`
	} `json:"clients"`
	Gravity struct {
		DomainsBeingBlocked int64 `json:"domains_being_blocked"`
		LastUpdate          int64 `json:"last_update"`
	} `json:"gravity"`
	Took float64 `json:"took"`
}

// StatsUpstreams mirrors GET /api/stats/upstreams.
type StatsUpstreams struct {
	Upstreams []struct {
		IP         string `json:"ip"`
		Name       string `json:"name"`
		Port       int    `json:"port"`
		Count      int64  `json:"count"`
		Statistics struct {
			Response float64 `json:"response"`
			Variance float64 `json:"variance"`
		} `json:"statistics"`
	} `json:"upstreams"`
	ForwardedQueries int64   `json:"forwarded_queries"`
	TotalQueries     int64   `json:"total_queries"`
	Took             float64 `json:"took"`
}

// InfoVersion mirrors GET /api/info/version. Pi-hole reports each
// component's version as a struct with local + remote sides; the
// exporter only consumes the local versions for an info-style metric.
type InfoVersion struct {
	Version struct {
		Core struct {
			Local versionLocal `json:"local"`
		} `json:"core"`
		FTL struct {
			Local versionLocal `json:"local"`
		} `json:"ftl"`
		Web struct {
			Local versionLocal `json:"local"`
		} `json:"web"`
	} `json:"version"`
	Took float64 `json:"took"`
}

type versionLocal struct {
	Version string `json:"version"`
	Branch  string `json:"branch"`
	Hash    string `json:"hash"`
}

// CoreVersion returns the local version string for Pi-hole core,
// defaulting to "unknown" when Pi-hole hasn't populated the field
// (e.g. during a partial upgrade).
func (v InfoVersion) CoreVersion() string { return orUnknown(v.Version.Core.Local.Version) }

// FTLVersion returns the local FTL version string, with the same
// "unknown" fallback as CoreVersion.
func (v InfoVersion) FTLVersion() string { return orUnknown(v.Version.FTL.Local.Version) }

// WebVersion returns the local web-admin version string, with the
// same "unknown" fallback as CoreVersion.
func (v InfoVersion) WebVersion() string { return orUnknown(v.Version.Web.Local.Version) }

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// InfoFTL mirrors GET /api/info/ftl. Only the fields the exporter maps
// to metrics today are decoded; unknown fields are dropped by
// json.Unmarshal so adding more is purely additive.
//
// Schema notes for Pi-hole v6 (verified against pihole-FTL):
//
//   - `database.domains.{allowed,denied}` and
//     `database.regex.{allowed,denied}` are `{total, enabled}` objects,
//     not scalars. Earlier exporter releases mis-typed these as int64
//     and the whole InfoFTL decode failed (taking the dnsmasq counters
//     down with it).
//   - The dnsmasq "unanswered" counter is `dns_unanswered`, not
//     `dns_unanswered_queries`.
type InfoFTL struct {
	FTL struct {
		Database struct {
			Gravity int64            `json:"gravity"`
			Groups  int64            `json:"groups"`
			Lists   int64            `json:"lists"`
			Clients int64            `json:"clients"`
			Domains FTLListBreakdown `json:"domains"`
			Regex   FTLListBreakdown `json:"regex"`
		} `json:"database"`
		PrivacyLevel int `json:"privacy_level"`
		Clients      struct {
			Total  int64 `json:"total"`
			Active int64 `json:"active"`
		} `json:"clients"`
		MemPercent float64 `json:"%mem"`
		CPUPercent float64 `json:"%cpu"`
		DNSMasq    struct {
			DNSCacheInserted    int64 `json:"dns_cache_inserted"`
			DNSCacheLiveFreed   int64 `json:"dns_cache_live_freed"`
			DNSQueriesForwarded int64 `json:"dns_queries_forwarded"`
			DNSAuthAnswered     int64 `json:"dns_auth_answered"`
			DNSLocalAnswered    int64 `json:"dns_local_answered"`
			DNSStaleAnswered    int64 `json:"dns_stale_answered"`
			DNSUnanswered       int64 `json:"dns_unanswered"`
		} `json:"dnsmasq"`
		Type string `json:"type"`
	} `json:"ftl"`
	Took float64 `json:"took"`
}

// FTLListBreakdown is the per-list `{total, enabled}` shape Pi-hole v6
// uses for `database.{domains,regex}.{allowed,denied}` entries — total
// rows defined and the subset that's currently active.
type FTLListBreakdown struct {
	Total   int64 `json:"total"`
	Enabled int64 `json:"enabled"`
}

// DNSBlocking mirrors GET /api/dns/blocking. The string field is one
// of "enabled", "disabled", "failed", "unknown".
type DNSBlocking struct {
	Blocking string  `json:"blocking"`
	Timer    *int    `json:"timer"`
	Took     float64 `json:"took"`
}

// Enabled returns 1 when blocking is in the "enabled" state, 0 otherwise.
func (b DNSBlocking) Enabled() float64 {
	if b.Blocking == "enabled" {
		return 1
	}
	return 0
}
