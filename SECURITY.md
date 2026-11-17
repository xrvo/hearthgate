# Security policy

Hearthgate exists to keep a low-trust server from reaching into a home network, so a flaw in that boundary is the most serious kind of bug this project can have.

## Reporting a vulnerability

Please report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a suspected vulnerability.

Include what you can of:

- the Hearthgate version or commit, and your `hearthgate.yml` with addresses and hostnames changed
- what an attacker can do, and from where (the internet, the edge server, a published app, a container on one of the Hearthgate networks)
- steps or a script that demonstrates it

You should get a first reply within a week. Please allow time for a fix to be released before publishing details.

## What counts

In scope, assuming the attacker fully controls the edge server:

- reaching anything at home other than the gateway's TLS listener on port 443
- reading or altering the contents of published traffic
- obtaining TLS private keys, the home WireGuard key, or `hearthgate.yml`
- changing which services are published or which agent ports home will connect to
- getting `ctl` to run attacker-chosen commands at home, for example through output returned from the edge

Also in scope:

- a published app on `hearthgate-dmz` reaching edge agents or the tunnel
- anything in `hearthgate.yml` or `ctl`'s inputs that lets a value escape into generated configs or shell commands

Out of scope, because the design accepts them (see the README's security model):

- the edge dropping, delaying or observing the metadata of traffic
- the edge forging the client address that home logs
- the edge returning false data from agents
- vulnerabilities in the apps you publish, or in the upstream software the image packages, unless Hearthgate's configuration makes them reachable where they otherwise would not be

## Supported versions

Fixes are made on the latest release only.
