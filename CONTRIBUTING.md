# Contributing

Issues and pull requests are welcome. For anything that affects the trust boundary between edge and home, please read [SECURITY.md](SECURITY.md) first, and report suspected vulnerabilities privately.

## Layout

| Path | What it is |
|---|---|
| `cmd/ctl` | The command-line tool: `init`, `apply`, `push`, `check`, `rotate` |
| `internal/config` | Parses and validates `hearthgate.yml` |
| `internal/render` | Turns config and keys into the generated files; templates are in `templates/` |
| `internal/remote` | Reaches the edge through the system `ssh` client |
| `internal/keys`, `internal/state` | WireGuard key generation and the saved key file |
| `docker-compose.yml` | The home stack, and the `ctl` service; users download it from the release |
| `.github/workflows/release.yml` | On a `v*.*.*` tag, publishes the `ctl` image to `ghcr.io/xrvo/hearthgate` and creates the GitHub release |
| `tests/e2e/run.sh` | Runs both stacks on one Docker host and probes them |

## Running the tests

```sh
go vet ./... && go test ./...
bash tests/e2e/run.sh
```

The end-to-end test needs Docker with Compose v2 and a kernel with WireGuard. It creates the real `hearthgate-*` networks, so don't run it on a machine hosting a live deployment. `KEEP=1 bash tests/e2e/run.sh` leaves everything running for inspection.

## Rules for changes

1. **Validate before you interpolate.** Every value from `hearthgate.yml` that reaches a template or a shell command must be checked against a strict pattern in `internal/config`. The renderers assume a `*config.Config` is safe to print as-is. A new config field needs a rejection case in `config_test.go`.
2. **Firewall and proxy changes need a test that fails without them.** Add an assertion to `render_test.go`, and for anything that changes what can connect to what, a `refuse` line in `tests/e2e/run.sh`. Showing that the allowed path works is not enough.
3. **No forwarding, no NAT.** Both tunnel namespaces only terminate connections at a proxy. If a feature seems to need packet forwarding, open an issue to discuss it first.
4. **Nothing about home goes to the edge unless the edge needs it to function.** The edge bundle holds no published hostnames or home container names; `TestEdgeBundleHoldsNoHomeSecrets` checks this.
5. **Keep images pinned.** Image references carry a tag and a digest, and must match between `docker-compose.yml` and `internal/render/render.go`. When bumping one, say in the pull request where the digest came from.
6. **Rendering stays deterministic.** The same config and keys must produce byte-identical files, because the config hash decides whether containers restart.

## Releasing

1. Set the `ctl` service's image in `docker-compose.yml` to the new version (`ghcr.io/xrvo/hearthgate:0.2.0`) and merge that to `main`.
2. Tag that commit `v0.2.0` and push the tag.

The release workflow fails before publishing anything if the two versions differ.

## Style

Go code is formatted with `gofmt` and has one external dependency (the YAML parser); please keep it that way unless there's a strong reason. Generated files start with a "do not edit" comment that says where the real source is.
