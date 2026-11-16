# Hearthgate

**A self-hosted tunnel for people who don't trust their VPS.**

Tools like Pangolin, Cloudflare Tunnel and most reverse-proxy-on-a-VPS setups share one design choice: TLS ends on the cloud server, and the cloud server decides what it can reach inside your network. Whoever controls that server (a provider, an attacker, a bad image update) can read your logins and reconfigure its way further in.

Hearthgate turns that around. The VPS is a dumb pipe that forwards encrypted traffic. Your home server holds the TLS keys, the firewall policy and the only config file.

| If the VPS is compromised… | Typical VPS tunnel | Hearthgate |
|---|---|---|
| Can it read your traffic and passwords? | Yes | No, ciphertext only |
| Does it hold your TLS keys? | Yes | No |
| Can it change what's exposed? | Yes | No, config lives at home |
| What can it reach at home? | Whatever it's configured to | One port: the gateway's 443 |

```
                     cloud edge (low trust)              home (high trust)
Internet ──443──▶  ┌──────────────────────┐   WireGuard   ┌─────────────────────┐
                   │ TCP passthrough only │ ════════════▶ │ gateway: TLS + HTTP │──▶ your apps
                   │ no certs, no config  │ ◀──────────── │ firewall, config    │
                   │ agents ◀─────────────│  home dials   │ monitoring hubs     │
                   └──────────────────────┘     out       └─────────────────────┘
```

> **Status:** early release. Both stacks are covered by an end-to-end test, but the project is new: read the [security model](#security-model) and run `ctl check` before you rely on it.

## What you get

- **Public HTTPS for home services** with automatic certificates and no DNS API token.
- **No inbound ports at home.** Home dials out, so it works behind CGNAT.
- **One config file,** kept at home, generates both sides. The edge receives only its rendered bundle.
- **Safe-direction monitoring.** Home pulls from agents running on the edge; the edge never pushes into home.
- **Plain Docker Compose.** Your containers join a network and need no special modes or capabilities.

## What you give up

Hearthgate is deliberately small. It has no web UI, no built-in login or SSO layer and no user management. If you want those and are comfortable trusting your VPS, Pangolin is a good choice.

## Requirements

- Docker with Compose v2 on both machines
- Linux kernel 5.6+ (built-in WireGuard) on both machines
- A VPS with a public IP, and `443/tcp`, `80/tcp` and `51820/udp` open
- A DNS record for each hostname you publish, pointing at the VPS
- For `ctl push`: SSH access from home to the VPS, as a user who can run `docker`

## Quick start

On your **home server**:

```sh
mkdir hearthgate && cd hearthgate
docker run --rm -v "$PWD:/work" ghcr.io/xrvo/hearthgate init
```

This writes two files: a starting `hearthgate.yml` and the `docker-compose.yml` that every later command runs through. There is nothing to clone or build.

Edit `hearthgate.yml`:

```yaml
edge:
  address: 203.0.113.5
  ssh: ubuntu@203.0.113.5

publish:
  photos.example.com: immich-server:2283   # public hostname -> home container

agents:
  beszel: beszel-agent:45876               # edge container reachable from home
```

Then:

```sh
docker compose run --rm ctl init    # generate keys, render both stacks
docker compose run --rm ctl push    # copy the edge bundle to the VPS and start it
docker compose up -d                # start the home gateway
docker compose run --rm ctl check   # verify tunnel, certificates and firewall
```

Certificates are issued automatically the first time each hostname is requested.

`ctl push` signs in with your SSH agent, or with `id_ed25519`, `id_ecdsa` or `id_rsa` from `~/.ssh`. It does not read `~/.ssh/config`. If your keys live elsewhere, set `HEARTHGATE_SSH_DIR` to that directory.

### Installing the edge by hand

If you leave out `edge.ssh`, or `push` doesn't suit your setup, copy the bundle yourself:

```sh
scp -r generated/edge ubuntu@203.0.113.5:hearthgate
ssh ubuntu@203.0.113.5
cd hearthgate
printf 'HEARTHGATE_PUID=%s\nHEARTHGATE_PGID=%s\n' "$(id -u)" "$(id -g)" > .env
docker compose up -d
```

Repeat this whenever `ctl apply` says the edge bundle changed.

## Connecting your containers

Your containers join a network. They need no published ports, extra capabilities or special network modes.

| Where | Join network | Result |
|---|---|---|
| Home app you want public | `hearthgate-dmz` | The gateway proxies the hostname in `publish` to it |
| Home monitoring hub | `hearthgate-mgmt` | It reaches each agent at `gateway:<port>` |
| Edge agent | `hearthgate-agents` | It is reachable from home only |

The examples use [Immich](https://immich.app) and [Beszel](https://beszel.dev), but any HTTP app and any hub-and-agent tool work the same way.

### Home: publish Immich

Add the network to the server container in Immich's own compose file. Its database and other containers stay private.

```yaml
services:
  immich-server:
    networks: [default, hearthgate-dmz]

networks:
  hearthgate-dmz: { external: true }
```

Uploads go through as raw TCP, so there is no request size cap on large videos.

Apps see requests arriving from the gateway (`10.210.1.2` by default) with the visitor's address in `X-Forwarded-For`. If your app has a "trusted proxies" setting, add the gateway's address there.

### Edge: run a Beszel agent

```yaml
services:
  beszel-agent:
    image: henrygd/beszel-agent
    environment:
      LISTEN: 45876
      KEY: "<public key shown by your Beszel hub>"
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]
    networks: [hearthgate-agents]

networks:
  hearthgate-agents: { external: true }
```

On a Docker network the agent reports the container's network traffic, not the host's. CPU, memory, disk and container stats are unaffected.

### Home: run the Beszel hub

```yaml
services:
  beszel:
    image: henrygd/beszel
    volumes: ["./beszel_data:/beszel_data"]
    networks: [default, hearthgate-mgmt]
    ports: ["8090:8090"]

networks:
  hearthgate-mgmt: { external: true }
```

In the hub, add a system with host `gateway` and port `45876`. Leave the agent's `HUB_URL` and `TOKEN` unset: those make the agent dial the hub, which is the direction Hearthgate blocks.

## Configuration

`hearthgate.yml` is the only file you edit. It never leaves your home server.

| Key | Default | Description |
|---|---|---|
| `edge.address` | required | Public IP or hostname of the VPS |
| `edge.ssh` | none | `user@host` for `ctl push` and the remote half of `ctl check` |
| `edge.ssh_port` | `22` | SSH port |
| `edge.dir` | `hearthgate` | Directory for the bundle on the VPS, relative to the SSH user's home |
| `edge.wireguard_port` | `51820` | Public UDP port for the tunnel |
| `edge.https_port` | `443` | Public HTTPS port |
| `edge.http_port` | `80` | Public HTTP port; it only redirects to HTTPS |
| `publish` | required | Map of public hostname → `container:port` on `hearthgate-dmz` |
| `agents` | none | Map of name → `container:port` on `hearthgate-agents` |
| `tls.ca` | `letsencrypt` | `letsencrypt`, `letsencrypt-staging`, or `internal` (self-signed, for testing) |
| `tls.email` | none | Contact address given to the certificate authority |
| `tunnel.subnet` | `10.210.0.0/30` | Addresses used inside the tunnel |
| `networks.dmz` | `10.210.1.0/24` | Subnet of `hearthgate-dmz` |
| `networks.mgmt` | `10.210.2.0/24` | Subnet of `hearthgate-mgmt` |
| `networks.agents` | `10.210.3.0/24` | Subnet of `hearthgate-agents` |

An agent's port is used unchanged on the tunnel and at `gateway:<port>`. Ports 80, 443 and 2019 are taken, and two agents can't share one, so give a different port where needed:

```yaml
agents:
  beszel: beszel-agent:45876
  exporter:
    target: node-exporter:9100
    listen: 19100          # hubs connect to gateway:19100
```

After any change:

```sh
docker compose run --rm ctl apply   # shows a diff, asks, then updates the edge
docker compose up -d                # picks up the change at home
```

## Commands

Run each as `docker compose run --rm ctl <command>`.

| Command | What it does |
|---|---|
| `init` | Generates keys and renders the home and edge stacks |
| `push` | Copies the edge bundle over SSH and starts it |
| `apply` | Re-renders after a config change, previews the diff, and pushes the edge if it changed |
| `check` | Tests the certificates, the tunnel handshake, and that home ports other than 443 are closed to the edge |
| `rotate` | Replaces the WireGuard keys on both sides |

`apply` and `rotate` take `-yes` to skip the prompt and `-no-push` to leave the edge to you.

## Upgrading

Releases are published as `ghcr.io/xrvo/hearthgate:<version>` for `amd64` and `arm64`. `docker-compose.yml` names the release that wrote it, so to upgrade, run the new release's `apply` once:

```sh
docker run --rm -v "$PWD:/work" ghcr.io/xrvo/hearthgate:<version> apply -no-push
docker compose run --rm ctl push    # only if apply says the edge bundle changed
docker compose up -d
```

`apply` shows what the new release changes, such as updated image pins, before it writes anything.

## How it works

Each side runs a WireGuard container with proxies sharing its network namespace.

- **Edge:** an nginx `stream` proxy passes public 443 to the home gateway with PROXY protocol, so home sees real client IPs. It also exposes each agent on the tunnel address only.
- **Home:** Caddy terminates TLS and routes by hostname. A second nginx `stream` proxy carries hub-to-agent connections.
- **Certificates:** Caddy uses the TLS-ALPN-01 challenge, which works through the passthrough.
- **Firewall:** generated, default-deny, input rules only. IP forwarding is disabled in both tunnel namespaces, and neither side uses NAT.
- **Keys:** both WireGuard key pairs are generated at home. The edge's key reaches it inside the pushed bundle.
- **Images:** stock upstream images ([linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard), Caddy, nginx) pinned by digest. The only custom code is `ctl`, a small Go program that runs one-shot and never listens on the network.

Everything `ctl` writes is in `generated/`, `.env` and `docker-compose.yml`. Keep `generated/state.json` private and backed up: it holds the tunnel keys.

## Security model

**If the edge is compromised, the attacker can:**

- Take your services offline or drop connections
- See connection metadata: client IPs, timing and volume
- Forge the client IP that home logs
- Send traffic to the gateway's port 443, the same as anyone on the internet
- Feed false data to your monitoring hubs through the agents

**The attacker cannot:**

- Read or modify traffic contents (TLS ends at home)
- Obtain your TLS keys or your config
- Reach any other port, container or host on your home network
- Change what is published or reachable

**Out of scope:** vulnerabilities in the apps you publish. Hearthgate keeps them on an isolated network but does not add authentication in front of them.

Report security issues privately; see [SECURITY.md](SECURITY.md).

## Limitations

- **IPv4 inside the stacks.** Visitors arriving at the VPS over IPv6 are served, but home sees the VPS's Docker address in place of theirs.
- **The tunnel endpoint is resolved once.** If `edge.address` is a hostname that can't be resolved when the gateway starts, restart the gateway once DNS works.
- **No wildcard certificates.** Each published hostname gets its own certificate.
- **HTTP services only.** Raw TCP and UDP publishing are on the roadmap.

## Alternatives

| | TLS ends at | Policy lives at | Good fit when |
|---|---|---|---|
| **Hearthgate** | Home | Home | You want a public endpoint and don't trust the VPS |
| Pangolin | VPS | VPS | You want a UI and built-in auth, and trust the VPS |
| Cloudflare Tunnel | Cloudflare | Cloudflare | You're fine with a third party seeing traffic |
| Tailscale / Headscale / NetBird | n/a | Control plane | You need private access between many devices |
| frp / rathole | Your choice | Split | You want to hand-wire individual ports |

## FAQ

**Does it work behind CGNAT or with a dynamic home IP?**
Yes. Home initiates the tunnel, so its address doesn't matter. If you restrict `51820/udp` on the VPS firewall to your home IP, you'll need to update that rule when the IP changes.

**Why not discover services from Docker labels?**
That needs Docker socket access near the gateway, which is the one container the edge can talk to. A static file keeps the socket away from it.

**Can I use my existing reverse proxy?**
Not at the gateway. You can put it behind the gateway as a `publish` target.

**Can I add login or SSO in front of an app?**
Run your auth proxy at home on `hearthgate-dmz` and publish that instead of the app.

**Can I try it before pointing DNS at the VPS?**
Set `tls.ca: internal` to get self-signed certificates, or `letsencrypt-staging` to rehearse issuance without using up rate limits.

## Roadmap

- [ ] Raw TCP and UDP publishing
- [ ] Wildcard certificates through DNS-01
- [ ] Real visitor addresses for IPv6 clients
- [ ] Multiple edges
- [ ] Optional CrowdSec at the gateway

## Development

```sh
go test ./...           # unit tests
bash tests/e2e/run.sh   # both stacks on one Docker host; needs WireGuard in the kernel
```

The end-to-end test checks the paths that must work and, more importantly, the ones that must not. See [CONTRIBUTING.md](CONTRIBUTING.md).

To run a stack from a checkout, build the image under the name the compose file expects for a development build:

```sh
docker build -t ghcr.io/xrvo/hearthgate:dev .
docker run --rm -v "$PWD:/work" ghcr.io/xrvo/hearthgate:dev init   # in an empty directory
```

## License

[Apache-2.0](LICENSE)
