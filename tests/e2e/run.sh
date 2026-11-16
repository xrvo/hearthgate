#!/usr/bin/env bash
# End-to-end test: runs the home and edge stacks on one Docker host and checks
# that traffic flows where it should and nowhere else.
#
# Needs Docker with Compose v2 and a kernel with WireGuard. It creates the
# networks hearthgate-dmz, hearthgate-mgmt and hearthgate-agents, so do not run
# it on a machine that hosts a real Hearthgate deployment.
#
#   tests/e2e/run.sh          run and clean up
#   KEEP=1 tests/e2e/run.sh   leave everything running for inspection
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tests/e2e/.work"
HTTPS_PORT=18443
HTTP_PORT=18080
WG_PORT=51821
AGENT_PORT=19090
SSH_PORT=12222
HOME_IP=10.210.0.2
DMZ_IP=10.210.1.2
MGMT_IP=10.210.2.2

ALPINE=alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
WHOAMI=traefik/whoami:v1.11.0@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab

# Git Bash on Windows rewrites arguments that look like paths; turn that off
# and hand Docker a path it understands.
export MSYS_NO_PATHCONV=1
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }
WORK_MOUNT=$(hostpath "$WORK")

home() { (cd "$WORK" && docker compose -p hearthgate-e2e "$@"); }
edge() { (cd "$WORK/generated/edge" && docker compose -p hearthgate-e2e-edge "$@"); }
ctl()  { docker run --rm --add-host host.docker.internal:host-gateway -v "$WORK_MOUNT:/work" hearthgate-ctl:e2e "$@"; }

# teardown removes everything a run creates. It works by project name, so it
# also clears what an earlier, interrupted or KEEP=1 run left behind.
teardown() {
	docker rm -f e2e-app e2e-agent e2e-sshd >/dev/null 2>&1 || true
	docker compose -p hearthgate-e2e down -v --remove-orphans >/dev/null 2>&1 || true
	docker compose -p hearthgate-e2e-edge down -v --remove-orphans >/dev/null 2>&1 || true
	docker compose -p hearthgate-e2e-nossh down -v --remove-orphans >/dev/null 2>&1 || true
	# Generated files may belong to the container user, so remove them from a container.
	docker run --rm -v "$WORK_MOUNT:/w" "$ALPINE" sh -c 'rm -rf /w/generated /w/.env /w/push /w/nossh' >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
cleanup() {
	if [ "${KEEP:-}" = 1 ]; then
		echo "KEEP=1: leaving the stacks running; work dir is $WORK"
		return
	fi
	teardown
}
trap cleanup EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }
# expect <description> <command...>: the command must succeed.
expect() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
# refuse <description> <command...>: the command must fail.
refuse() { local d=$1; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }

echo "== Building ctl and rendering the configuration"
teardown
mkdir -p "$WORK"
cp "$ROOT/docker-compose.yml" "$ROOT/tests/e2e/docker-compose.override.yml" "$WORK/"
cat > "$WORK/hearthgate.yml" <<EOF
edge:
  address: host.docker.internal
  wireguard_port: $WG_PORT
  https_port: $HTTPS_PORT
  http_port: $HTTP_PORT
publish:
  app.e2e.test: e2e-app:80
agents:
  probe: {target: "e2e-agent:80", listen: $AGENT_PORT}
tls:
  ca: internal
EOF
docker build -q -t hearthgate-ctl:e2e "$(hostpath "$ROOT")" >/dev/null
ctl init

echo "== Starting the edge, then home"
edge up -d
home up -d gateway caddy stream
docker run -d --name e2e-app --network hearthgate-dmz "$WHOAMI" >/dev/null
docker run -d --name e2e-agent --network hearthgate-agents "$WHOAMI" >/dev/null

echo "== Waiting for the tunnel"
handshake=0
for _ in $(seq 1 30); do
	handshake=$(edge exec -T tunnel wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' || true)
	[ "${handshake:-0}" -gt 0 ] 2>/dev/null && break
	sleep 2
done
if [ "${handshake:-0}" -gt 0 ] 2>/dev/null; then
	pass "WireGuard handshake completed"
else
	fail "WireGuard handshake completed"
	echo "--- gateway logs"; home logs --tail 40 gateway || true
	echo "--- tunnel logs"; edge logs --tail 40 tunnel || true
fi

echo "== Public path: internet -> edge -> tunnel -> gateway -> app"
fetch() { curl -sk --max-time 10 --resolve "app.e2e.test:$HTTPS_PORT:127.0.0.1" "https://app.e2e.test:$HTTPS_PORT/"; }
body=""
for _ in $(seq 1 20); do
	body=$(fetch || true)
	echo "$body" | grep -q '^Hostname:' && break
	sleep 2
done
if echo "$body" | grep -q '^Hostname:'; then
	pass "published app answers over HTTPS through the edge"
else
	fail "published app answers over HTTPS through the edge"
	echo "--- caddy logs"; home logs --tail 40 caddy || true
	echo "--- edge proxy logs"; edge logs --tail 40 proxy || true
fi
xff=$(echo "$body" | grep -i '^X-Forwarded-For:' | tr -d '\r' | awk '{print $2}' || true)
if [ -n "$xff" ] && [ "$xff" != "10.210.0.1" ]; then
	pass "app sees the client address ($xff), not the edge's tunnel address"
else
	fail "app sees the client address, not the edge's tunnel address (got '${xff}')"
fi
redirect=$(curl -sI --max-time 10 -H 'Host: app.e2e.test' "http://127.0.0.1:$HTTP_PORT/x" | tr -d '\r' | awk 'NR==1 {code=$2} tolower($1)=="location:" {loc=$2} END {print code, loc}' || true)
if [ "$redirect" = "301 https://app.e2e.test:$HTTPS_PORT/x" ]; then
	pass "plain HTTP redirects to HTTPS"
else
	fail "plain HTTP redirects to HTTPS (got '$redirect')"
fi

echo "== Monitoring path: hub on hearthgate-mgmt -> gateway -> tunnel -> agent"
on() { local net=$1; shift; docker run --rm --network "$net" "$ALPINE" "$@"; }
if on hearthgate-mgmt wget -qO- -T 8 "http://gateway:$AGENT_PORT/" 2>/dev/null | grep -q '^Hostname:'; then
	pass "hub reaches the edge agent at gateway:$AGENT_PORT"
else
	fail "hub reaches the edge agent at gateway:$AGENT_PORT"
	echo "--- stream logs"; home logs --tail 20 stream || true
	echo "--- edge proxy logs"; edge logs --tail 20 proxy || true
fi

echo "== What must not work"
for port in 22 53 80 2019 "$AGENT_PORT"; do
	refuse "edge cannot open home port $port" edge exec -T tunnel nc -z -w 3 "$HOME_IP" "$port"
done
expect "edge can open home port 443 (the one allowed port)" edge exec -T tunnel nc -z -w 3 "$HOME_IP" 443

refuse "published apps cannot reach edge agents through the gateway" on hearthgate-dmz nc -z -w 3 "$DMZ_IP" "$AGENT_PORT"
refuse "published apps cannot reach the TLS listener directly" on hearthgate-dmz nc -z -w 3 "$DMZ_IP" 443
refuse "hubs cannot reach the TLS listener directly" on hearthgate-mgmt nc -z -w 3 "$MGMT_IP" 443

tunnel_id=$(edge ps -q tunnel)
tunnel_agents_ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "hearthgate-agents").IPAddress}}' "$tunnel_id")
refuse "edge agents cannot reach the agent listener (it is tunnel-only)" on hearthgate-agents nc -z -w 3 "$tunnel_agents_ip" "$AGENT_PORT"

for side in home edge; do
	if [ "$side" = home ]; then fwd=$(home exec -T gateway cat /proc/sys/net/ipv4/ip_forward); else fwd=$(edge exec -T tunnel cat /proc/sys/net/ipv4/ip_forward); fi
	if [ "$(echo "$fwd" | tr -d '\r')" = 0 ]; then pass "$side namespace does not forward packets"; else fail "$side namespace does not forward packets"; fi
done

echo "== ctl check and ctl apply"
check_out=$(ctl check 2>&1) && check_rc=0 || check_rc=$?
if [ "$check_rc" = 0 ] && echo "$check_out" | grep -q 'app.e2e.test: certificate from'; then
	pass "ctl check passes and sees the certificate served from home"
else
	fail "ctl check passes and sees the certificate served from home"
	echo "$check_out"
fi
expect "ctl apply reports nothing to change" sh -c "docker run --rm -v '$WORK_MOUNT:/work' hearthgate-ctl:e2e apply | grep -q 'Nothing to change'"

echo "== ctl push over SSH (to a throwaway SSH server with a stand-in docker command)"
PUSH="$WORK/push"
mkdir -p "$PUSH/keys"
cat > "$PUSH/hearthgate.yml" <<EOF
edge:
  address: 203.0.113.5
  ssh: tester@host.docker.internal
  ssh_port: $SSH_PORT
publish:
  app.e2e.test: e2e-app:80
EOF
docker run -d --name e2e-sshd -p "$SSH_PORT:22" -v "$(hostpath "$PUSH/keys"):/keys" "$ALPINE" sh -c '
	set -e
	apk add --no-cache openssh-server >/dev/null
	ssh-keygen -A >/dev/null
	ssh-keygen -q -t ed25519 -N "" -f /keys/id_ed25519
	adduser -D tester && echo "tester:$(head -c 18 /dev/urandom | base64)" | chpasswd 2>/dev/null
	mkdir -p /home/tester/.ssh
	cp /keys/id_ed25519.pub /home/tester/.ssh/authorized_keys
	chown -R tester /home/tester/.ssh && chmod 700 /home/tester/.ssh
	printf "#!/bin/sh\necho \"\$@\" >> /tmp/docker-calls\n" > /usr/local/bin/docker
	chmod +x /usr/local/bin/docker
	exec /usr/sbin/sshd -D -e' >/dev/null
for _ in $(seq 1 30); do
	docker exec e2e-sshd sh -c 'nc -z 127.0.0.1 22' >/dev/null 2>&1 && break
	sleep 1
done
pushctl() {
	docker run --rm --add-host host.docker.internal:host-gateway \
		-v "$(hostpath "$PUSH"):/work" -v "$(hostpath "$PUSH/keys"):/ssh:ro" hearthgate-ctl:e2e "$@"
}
pushctl init >/dev/null
push_out=$(pushctl push 2>&1) && push_rc=0 || push_rc=$?
if [ "$push_rc" = 0 ]; then
	pass "ctl push connects with the mounted key and succeeds"
else
	fail "ctl push connects with the mounted key and succeeds"
	echo "$push_out"
fi
remote() { docker exec -u tester e2e-sshd sh -c "$1"; }
expect "push installed the whole bundle" remote 'cd ~/hearthgate && test -f docker-compose.yml -a -f nginx.conf -a -f wireguard/firewall.sh -a -f wireguard/wg_confs/wg0.conf'
expect "pushed WireGuard config is private (mode 600)" remote 'test "$(stat -c %a ~/hearthgate/wireguard/wg_confs/wg0.conf)" = 600'
expect "push recorded the SSH user for the tunnel container" remote 'grep -q "^HEARTHGATE_PUID=$(id -u)$" ~/hearthgate/.env'
expect "push started the edge stack" remote 'grep -qx "compose up -d --remove-orphans" /tmp/docker-calls'
expect "pushed bundle is identical to the rendered one" sh -c "docker exec -u tester e2e-sshd cat /home/tester/hearthgate/nginx.conf | cmp -s - '$PUSH/generated/edge/nginx.conf'"


echo "== SSH failures are explained"
# says <description> <text> <output>: the output must contain the text.
says() { if echo "$3" | grep -qF -- "$2"; then pass "$1"; else fail "$1"; echo "$3"; fi; }
first=$(echo "$push_out" | grep -c 'Fingerprint: SHA256:' || true)
[ "$first" = 1 ] && pass "the first connection shows the host key fingerprint" || { fail "the first connection shows the host key fingerprint"; echo "$push_out"; }
again=$(pushctl push 2>&1 || true)
if echo "$again" | grep -q 'Fingerprint\|Permanently added'; then fail "a known host key is not announced again"; echo "$again"; else pass "a known host key is not announced again"; fi

nokeys() { docker run --rm --add-host host.docker.internal:host-gateway -e HEARTHGATE_SSH_DIR_HOST=/home/me/.ssh \
	-v "$(hostpath "$PUSH"):/work" -v "$(hostpath "$PUSH/empty"):/ssh:ro" hearthgate-ctl:e2e "$@"; }
mkdir -p "$PUSH/empty"
out=$(nokeys push 2>&1) && rc=0 || rc=$?
nokeys_out=$out
[ "$rc" != 0 ] && pass "push without a key fails" || fail "push without a key fails"
says "it says the sign-in was refused" 'refused the sign-in as "tester"' "$out"
says "it names the key folder on the host" "the key folder /home/me/.ssh is empty" "$out"
says "it says how to make and authorise a key" "ssh-keygen -t ed25519 && ssh-copy-id -i ~/.ssh/id_ed25519.pub -p $SSH_PORT tester@host.docker.internal" "$out"
says "it offers the manual install" "docker compose run --rm -T ctl bundle | ssh -p $SSH_PORT tester@host.docker.internal" "$out"
out=$(nokeys check 2>&1 || true)
says "check explains the same failure" "ctl had no key to offer" "$out"

remote 'rm -f ~/.ssh/authorized_keys'
out=$(pushctl push 2>&1 || true)
says "an unauthorised key is named, with the command to authorise it" "ssh-copy-id -i /ssh/id_ed25519.pub -p $SSH_PORT tester@host.docker.internal" "$out"
remote 'cp /keys/id_ed25519.pub ~/.ssh/authorized_keys'

docker exec e2e-sshd sh -c 'rm /etc/ssh/ssh_host_*_key* && ssh-keygen -A >/dev/null && kill -HUP 1'
sleep 2
out=$(pushctl push 2>&1 || true)
says "a changed host key stops the push with an explanation" "presented a different host key" "$out"
docker run --rm -v "$(hostpath "$PUSH"):/w" "$ALPINE" rm /w/generated/known_hosts
expect "push works again once the old host key is deleted" pushctl push

echo "== ctl bundle, installed through a plain ssh pipe"
remote 'rm -rf ~/hearthgate /tmp/docker-calls'
install=$(echo "$nokeys_out" | sed -n "s/.*| ssh [^']*'\\(.*\\)'\$/\\1/p" || true)
refuse "ctl bundle refuses to write the archive to a terminal" docker run --rm -t -v "$(hostpath "$PUSH"):/work" hearthgate-ctl:e2e bundle
if [ -n "$install" ] && pushctl bundle | docker exec -i -u tester e2e-sshd sh -c "cd ~ && $install" >/dev/null 2>&1; then
	pass "the manual install command that ctl prints runs on the edge"
else
	fail "the manual install command that ctl prints runs on the edge (command: '$install')"
fi
expect "bundle installed the whole bundle and started the stack" remote 'cd ~/hearthgate && test -f docker-compose.yml -a -f wireguard/wg_confs/wg0.conf && grep -q "^HEARTHGATE_PUID=$(id -u)$" .env && grep -qx "compose up -d --remove-orphans" /tmp/docker-calls'

echo "== Failures on the edge and on the way to it are explained"
docker exec e2e-sshd rm /usr/local/bin/docker
out=$(pushctl push 2>&1 || true)
says "a VPS without Docker is explained" 'no `docker` command for user "tester"' "$out"

sed -i "s/ssh_port: $SSH_PORT/ssh_port: 12223/" "$PUSH/hearthgate.yml"
out=$(pushctl apply -yes -no-push 2>&1; pushctl push 2>&1 || true)
says "a wrong SSH port is explained" "nothing accepts SSH connections on port 12223" "$out"

echo "== The home stack does not need an SSH folder to start ctl"
NOSSH="$WORK/nossh"
mkdir -p "$NOSSH/home"
cp "$ROOT/docker-compose.yml" "$NOSSH/"
sed -i "s|image: ghcr.io/.*|image: hearthgate-ctl:e2e|" "$NOSSH/docker-compose.yml"
if (cd "$NOSSH" && HOME="$NOSSH/home" SSH_AUTH_SOCK= docker compose -p hearthgate-e2e-nossh run --rm -T ctl init 2>&1 | grep -q 'Wrote a starting hearthgate.yml'); then
	pass "ctl init runs for a user with no ~/.ssh and no agent"
else
	fail "ctl init runs for a user with no ~/.ssh and no agent"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
