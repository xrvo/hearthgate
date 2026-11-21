# Contributing

Issues and pull requests are welcome. For anything that affects the trust boundary between edge and home, please read [SECURITY.md](SECURITY.md) first, and report suspected vulnerabilities privately.

## Layout

| Path | What it is |
|---|---|
| `cmd/ctl` | The command-line tool and all its commands |
| `internal/config` | Parses and validates `hearthgate.yml` |
| `internal/render` | Turns config and keys into the generated files; templates are in `templates/` |
| `internal/remote` | Reaches the edge through the system `ssh` client |
| `internal/keys`, `internal/state` | WireGuard key generation and the saved key file |
| `Dockerfile` | The Hearthgate image, on Alpine: `ctl` and the OpenSSH client. The stacks run `linuxserver/wireguard` and the official Caddy and nginx images |
| `docker-compose.yml` | The home stack, and the `ctl` service; users download it from the release |
| `.github/workflows/release.yml` | On a `v*.*.*` tag, publishes the image to `ghcr.io/xrvo/hearthgate` and creates the GitHub release |
| `tests/e2e/run.sh` | Runs both stacks on one Docker host and probes them |
| `tests/e2e/docker-compose.override.yml` | Settings the home stack needs only inside that test |

## Running the tests

```sh
go vet ./... && go test ./...
bash tests/e2e/run.sh
```

The end-to-end test needs Docker with Compose 2.17 or newer and a kernel with WireGuard. It creates the real `hearthgate-*` networks, so don't run it on a machine hosting a live deployment. `KEEP=1 bash tests/e2e/run.sh` leaves everything running for inspection.

## Rules for changes

1. **Validate before you interpolate.** Every value from `hearthgate.yml` that reaches a template or a shell command must be checked against a strict pattern in `internal/config`. The renderers assume a `*config.Config` is safe to print as-is. A new config field needs a rejection case in `config_test.go`.
2. **Firewall and proxy changes need a test that fails without them.** Add an assertion to `render_test.go`, and for anything that changes what can connect to what, a `refuse` line in `tests/e2e/run.sh`. Showing that the allowed path works is not enough.
3. **No forwarding, no NAT.** Both tunnel namespaces only terminate connections at a proxy. If a feature seems to need packet forwarding, open an issue to discuss it first.
4. **Nothing about home goes to the edge unless the edge needs it to function.** The edge bundle holds no published hostnames or home container names; `TestEdgeBundleHoldsNoHomeSecrets` checks this.
5. **Pin upstream by version tag, never by digest.** `docker-compose.yml` names the WireGuard, Caddy and nginx images, and passes the WireGuard and nginx ones to `ctl` for the edge; the `Dockerfile` names Alpine and the Go toolchain. Nothing else names an image the stacks run. `TestUpstreamImagesPinnedByVersionTag` checks the tag levels; see [Upstream versions](#upstream-versions).
6. **Rendering stays deterministic.** The same config and keys must produce byte-identical files, because the config hash decides whether containers restart. The one input from the machine is the owner of the generated files, written to `.env` as `HEARTHGATE_PUID`/`HEARTHGATE_PGID` for the WireGuard container; it stays out of the mounted files and their hash.
7. **One directory per container, and the firewall first.** A container is mounted only the files it needs, read-only; key material belongs in a `tunnel/` directory and nowhere else. `wg0.conf` loads the firewall in `PreUp`, before the tunnel interface is configured and brought up, never in `PostUp`. `TestEachContainerGetsItsOwnDirectory` and the `refuse` lines in the end-to-end test check this.

## Upstream versions

Each upstream image is pinned by a version tag at the level where upstream ships only fixes, so patch releases arrive on their own and breaking changes do not. Move a tag by hand when its line ends:

| Image | Where | Tag | Bump by hand |
| --- | --- | --- | --- |
| WireGuard | `docker-compose.yml` (`x-wireguard`) | `linuxserver/wireguard:1.0.20260223` | When a new wireguard-tools release ships: linuxserver publishes it under a new `1.0.<date>` tag. Their weekly rebuilds of the current release, with Alpine fixes, arrive under the same tag. |
| nginx | `docker-compose.yml` (`x-nginx`) | `nginx:1.30-alpine` | **Once a year.** nginx replaces its stable branch, the even minor, about every April. Move to the new one (`1.32`), never to an odd mainline minor. |
| Caddy | `docker-compose.yml` (`x-caddy`) | `caddy:2.11-alpine` | When a new minor ships, read its [release notes](https://github.com/caddyserver/caddy/releases) for changes that affect the generated `Caddyfile` before moving to it. |
| Alpine (`ctl`) | `Dockerfile` | `alpine:3.24` | When a new Alpine branch ships (May and November). Package versions stay fixed within a branch and can change between branches. |
| Go | `Dockerfile` | `golang:1.27-alpine` | When a new Go release ships. Move the `go` line in `go.mod` with it. |

After moving any of them, run the end-to-end test; CI runs it on both `amd64` and `arm64`.

## Releasing

1. Set the `x-image` line in `docker-compose.yml` to the new version (`ghcr.io/xrvo/hearthgate:0.2.0`) and merge that to `main`.
2. Tag that commit `v0.2.0` and push the tag.

The release workflow fails before publishing anything if the two versions differ.

## Documentation

The website and documentation at [hearthgate.io](https://hearthgate.io) are built from a separate repository, [xrvo/hearthgate-site](https://github.com/xrvo/hearthgate-site). Its pages are written from this README and the source, so a change to behaviour needs a change there too. That repository's README lists which page follows which file here. The pages most likely to need it are the quick start, the configuration and `ctl` references, and troubleshooting, which quotes the messages `ctl` prints.

## Style

Go code is formatted with `gofmt` and has one external dependency (the YAML parser); please keep it that way unless there's a strong reason. Generated files start with a "do not edit" comment that says where the real source is.
