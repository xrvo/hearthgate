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

![Visitors connect to the low-trust cloud edge on port 443. The edge passes the TCP stream, still encrypted, through a WireGuard tunnel that the home gateway dialled. The high-trust home gateway terminates TLS and routes to your apps. Monitoring hubs at home pull from agents on the edge.](docs/architecture.svg)

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

- Docker with Compose 2.17 or newer on both machines (`docker compose version`)
- Linux kernel 5.6+ (built-in WireGuard) on both machines
- A VPS with a public IP, and `443/tcp`, `80/tcp` and `51820/udp` open
- A DNS record for each hostname you publish, pointing at the VPS
- For `ctl deploy`: SSH access from home to the VPS, as a user who can run `docker`

## Quick start

On your **home server**:

```sh
mkdir hearthgate && cd hearthgate
wget https://github.com/xrvo/hearthgate/releases/latest/download/docker-compose.yml
docker compose run --rm ctl init     # asks four questions, then generates keys and both stacks
docker compose up -d                 # start the home gateway
docker compose run --rm ctl deploy   # install the edge on the VPS, wait for the tunnel, verify
```

You can also copy [`docker-compose.yml`](docker-compose.yml) from the repository by hand. There is nothing to clone or build: the compose file pulls the published `ghcr.io/xrvo/hearthgate` image.

`init` asks for the VPS's address, the SSH user to reach it as, a first hostname to publish and the home container it should reach. It writes them to `hearthgate.yml`:

```yaml
edge:
  address: 203.0.113.5
  ssh: ubuntu@203.0.113.5

publish:
  photos.example.com: immich-server:2283   # public hostname -> home container
```

`deploy` first checks that the VPS is ready: SSH works, Docker and Compose answer, nothing else holds the public ports, and DNS for each hostname points at the VPS. It then installs and starts the edge, waits for home to connect, and runs `check`. Certificates are issued automatically the first time each hostname is requested.

To publish more hostnames or add [agents](#configuration), edit `hearthgate.yml` and deploy again:

```sh
docker compose run --rm ctl deploy   # shows a diff, asks, then updates the edge
docker compose up -d                 # picks up the change at home
```

If `docker compose up -d` reports that the gateway did not start, `docker compose logs gateway` says why in plain words: most often the configuration has not been generated yet (run `init`), or the kernel has no WireGuard support. Where there is no terminal to ask on, `init` writes an example `hearthgate.yml` for you to edit, and a second `init` generates from it.

`ctl` reaches the VPS as `edge.ssh`. It signs in with your SSH agent, or with `id_ed25519`, `id_ecdsa` or `id_rsa` from `~/.ssh`. It does not read `~/.ssh/config`. If your keys live elsewhere, set `HEARTHGATE_SSH_DIR` to that directory.

If it cannot connect, `ctl` says why (no key found, key not authorised on the VPS, wrong port, changed host key, Docker missing on the VPS) and lists what to try. The first time it connects it shows the VPS's host key fingerprint and remembers the key in `generated/known_hosts`.

If you have no `~/.ssh` folder yet, Docker creates an empty one owned by root when `ctl` first runs. Take it back with `sudo chown "$(id -u):$(id -g)" ~/.ssh` before you make a key in it.

### Installing the edge with your own ssh

If you leave out `edge.ssh`, or your connection needs `~/.ssh/config`, a jump host or a password, pipe the bundle through your own `ssh`:

```sh
docker compose run --rm -T ctl bundle | ssh ubuntu@203.0.113.5 \
  'mkdir -p hearthgate && cd hearthgate && tar -xzf - && docker compose up -d --remove-orphans'
```

`ctl` prints this command, filled in for your configuration, whenever the edge needs installing by hand. Repeat it whenever `ctl apply` says the edge bundle changed. The `-T` matters: without it the archive would pass through a terminal and arrive corrupted, so `ctl bundle` stops and tells you.

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
| `edge.ssh` | none | `user@host` that `ctl` uses to install, control and check the edge |
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

Docker cannot change the subnet of a network that containers are attached to. If you change one under `networks`, `ctl apply` tells you what to stop first.

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
docker compose run --rm ctl deploy   # shows a diff, asks, then updates the edge
docker compose up -d                 # picks up the change at home
```

## Commands

Run each as `docker compose run --rm ctl <command>`.

| Command | What it does |
|---|---|
| `init` | Sets up a new project: asks for the VPS and a first hostname, writes `hearthgate.yml`, generates keys and renders both stacks |
| `deploy` | Checks the VPS, applies pending changes, pushes the edge, waits for the tunnel and runs `check` |
| `push` | Copies the edge bundle over SSH and starts it |
| `bundle` | Writes the edge bundle to standard output as a `tar.gz`, for installing with your own `ssh` |
| `apply` | Re-renders after a config change, previews the diff, and pushes the edge if it changed |
| `status` | Shows whether the generated files, the edge and the tunnel are in step |
| `edge up` / `down` / `restart` | Starts, stops or restarts the edge stack on the VPS |
| `edge status` | Shows whether the edge is installed, running, up to date and connected |
| `edge logs` | Shows the edge's logs; `-f` follows, `-tail N` sets the length, and `tunnel` or `proxy` picks one service |
| `check` | Tests DNS, the certificates, the tunnel handshake, and that home ports other than 443 are closed to the edge |
| `rotate` | Replaces the WireGuard keys on both sides |

`deploy` is `apply`, `push` and `check` in one, with a check of the VPS in front; the separate commands remain for doing one step at a time. `deploy`, `apply` and `rotate` take `-yes` to skip the prompt. `apply` and `rotate` take `-no-push` to leave the edge to you, and `deploy -wait N` sets how many seconds to wait for the tunnel (60 by default).

Each command ends by listing the commands to run next. Output is coloured on a terminal; set `NO_COLOR=1` to turn that off.

## Starting and stopping

Each side is started and stopped from your home server:

| | Home gateway | Edge (on the VPS) |
|---|---|---|
| Start | `docker compose up -d` | `docker compose run --rm ctl edge up` |
| Stop | `docker compose down` | `docker compose run --rm ctl edge down` |
| Is it working? | `docker compose ps` | `docker compose run --rm ctl status` |

`edge down` asks first, because every published hostname goes offline. It stops the containers and deletes nothing, and the edge stays stopped across VPS reboots until `edge up`. These commands need `edge.ssh`; without it, run `docker compose` in the bundle directory on the VPS.

`status` is the quick look: it compares the files on the edge with the ones generated at home, and reads the tunnel's last handshake. `check` does the same and also tests each certificate and probes the home firewall from the edge.

## Upgrading

Releases are published as `ghcr.io/xrvo/hearthgate:<version>` for `amd64` and `arm64`, and each release's `docker-compose.yml` names that version. To upgrade, replace the compose file and re-apply:

```sh
wget -O docker-compose.yml https://github.com/xrvo/hearthgate/releases/latest/download/docker-compose.yml
docker compose run --rm ctl apply   # shows what the new release changes, then updates the edge
docker compose up -d
```

## How it works

Each side runs a tunnel container, holding the WireGuard interface and the firewall, with proxies sharing its network namespace.

- **Edge:** an nginx `stream` proxy passes public 443 to the home gateway with PROXY protocol, so home sees real client IPs. It also exposes each agent on the tunnel address only.
- **Home:** Caddy terminates TLS and routes by hostname. A second nginx `stream` proxy carries hub-to-agent connections.
- **Certificates:** Caddy uses the TLS-ALPN-01 challenge, which works through the passthrough.
- **Firewall:** generated, default-deny, input rules only. IP forwarding is disabled in both tunnel namespaces, and neither side uses NAT.
- **Keys:** both WireGuard key pairs are generated at home. The edge's key reaches it inside the pushed bundle.
- **Separation:** every container gets a directory holding only its own files, mounted read-only. Only the tunnel container has the WireGuard keys and the `NET_ADMIN` capability. Caddy and nginx share its network, but can neither read the keys nor change the firewall, and the firewall is loaded before the tunnel interface comes up.
- **Image:** one image, `ghcr.io/xrvo/hearthgate`, runs every container on both sides. This repository builds it and publishes it with a build provenance attestation. It packages Caddy and nginx from their official images, pinned by digest in the [`Dockerfile`](Dockerfile), with WireGuard's `wg`, `iptables` and OpenSSH from Alpine's package repository. Alpine packages are installed when the image is built and are not pinned individually.
- **Own code:** `ctl`, a Go program that runs one-shot and never listens on the network, and a short [shell entrypoint](image/hearthgate) that brings up the tunnel and firewall and starts each proxy.

Everything `ctl` writes is in `generated/` and `.env`, plus the starting `hearthgate.yml`. Keep `generated/state.json` private and backed up: it holds the tunnel keys.

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

**What you are trusting:** the Hearthgate image, and through it Caddy, nginx, WireGuard and Alpine. You can check that an image was built by this repository's release workflow from its source:

```sh
gh attestation verify oci://ghcr.io/xrvo/hearthgate:0.1.0 --owner xrvo
```

**Out of scope:** vulnerabilities in the apps you publish. Hearthgate keeps them on an isolated network but does not add authentication in front of them.

Report security issues privately; see [SECURITY.md](SECURITY.md).

## Limitations

- **IPv4 inside the stacks.** Visitors arriving at the VPS over IPv6 are served, but home sees the VPS's Docker address in place of theirs.
- **The tunnel endpoint is resolved once,** when the gateway starts. If `edge.address` is a hostname that can't be resolved then, the gateway restarts itself until it can. If the address behind the name changes later, restart the gateway.
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

To run a stack with your own build, give the image the name `docker-compose.yml` uses, so Compose finds it locally and does not pull the release:

```sh
docker build -t "$(sed -n 's/^x-image: &image //p' docker-compose.yml)" .
```

## License

[Apache-2.0](LICENSE)
