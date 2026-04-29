# prometheus_pihole_exporter

Prometheus exporter for [Pi-hole v6](https://pi-hole.net/). Exposes DNS,
blocking, and DHCP metrics from one or more Pi-hole instances. Single
static Go binary; published as a multi-arch container on
`ghcr.io/reloaded/prometheus_pihole_exporter`.

> **Status:** scaffold. The HTTP plumbing, config loader, and probe handler
> are in place; collector implementations land in subsequent PRs. See
> [`CLAUDE.md`](CLAUDE.md) for the development plan and conventions.

## Why another Pi-hole exporter?

Pi-hole v6 replaced the v5 PHP API with a session-based REST API. The
existing community exporters (notably `eko/pihole-exporter`) target v5
and don't speak the new auth flow. This exporter is purpose-built for v6,
adds first-class DHCP coverage (active leases + log-derived DHCP message
rates) which the v5-era exporters lack, and supports multiple Pi-hole
instances out of one process.

## Metrics groups

| Group | Source | Default | Notes |
| --- | --- | --- | --- |
| `dns` | Pi-hole v6 REST API (`/api/stats/*`, `/api/info/*`, `/api/ftl`, …) | on | total / blocked / cached / forwarded queries, top clients & domains, query types, upstream destinations, FTL state, blocking enabled/disabled |
| `dhcp_leases` | parses Pi-hole's `dhcp.leases` file | off | active-lease gauges, pool usage, per-MAC / per-IP labels |
| `dhcp_log` | tails the `dnsmasq` log | off | DISCOVER / OFFER / REQUEST / ACK / NAK / DECLINE counters |

Each group can be turned on or off per Pi-hole instance — useful for a
secondary Pi-hole that isn't running DHCP.

## Multi-target pattern

The exporter exposes two HTTP endpoints:

- `/metrics` — exporter-self process / Go runtime metrics only
- `/probe?target=<instance-id>` — runs the configured collectors against
  the named Pi-hole and returns the result

Prometheus is configured with one scrape job per Pi-hole instance,
relabelling `__address__` to the exporter and passing the instance ID via
`__param_target`. This is the same shape `blackbox_exporter` uses.

## Configuration

Configuration is YAML. See [`examples/config.yaml`](examples/config.yaml)
for the full shape. App-passwords are not stored inline — each instance
names an env var that the exporter reads at scrape time.

### Collector overrides (CLI / env)

Each Pi-hole instance enables collector groups via its `collectors:` block
in YAML, but a deploy-time global override is also available so a collector
can be flipped on or off across every instance without editing the config
file. Useful when rolling a collector out gradually, or silencing one for
an investigation.

| Flag                     | Env                                       | Effect when set                                                                                                                                                      |
| ------------------------ | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-collector.dns`         | `PIHOLE_EXPORTER_COLLECTOR_DNS`           | Force the DNS collector on (`true`) or off (`false`) for every instance.                                                                                             |
| `-collector.dhcp-leases` | `PIHOLE_EXPORTER_COLLECTOR_DHCP_LEASES`   | Force the DHCP-leases collector on/off. Truthy values still require `collectors.dhcp_leases.path` per instance — the override doesn't synthesise paths.              |
| `-collector.dhcp-log`    | `PIHOLE_EXPORTER_COLLECTOR_DHCP_LOG`      | Force the DHCP-log collector on/off, same "still needs the YAML path" rule.                                                                                          |

Precedence (highest first): **CLI flag → env var → per-instance YAML → built-in default**. Empty/unset means "don't override" and the YAML's view stands.

## Running

### Container

```sh
docker run --rm -p 9617:9617 \
  -e PIHOLE_PRIMARY_PASSWORD=... \
  -v $(pwd)/config.yaml:/etc/prometheus_pihole_exporter/config.yaml:ro \
  ghcr.io/reloaded/prometheus_pihole_exporter:latest
```

### From source

```sh
make build
./bin/prometheus_pihole_exporter -config ./examples/config.yaml
```

## Development

- [`CLAUDE.md`](CLAUDE.md) — repo conventions (commits, branches, releases)
- [`docs/worktrees.md`](docs/worktrees.md) — git worktree workflow

```sh
make test     # go test -race -cover ./...
make lint     # golangci-lint
make fmt      # gofmt -s -w .
make image    # build a local Docker image
```

## License

[MIT](LICENSE)
