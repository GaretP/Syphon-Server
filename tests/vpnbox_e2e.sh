#!/usr/bin/env bash
# Syphon manages a real VPN box (syphon-vpn) over the link, run as root. Two network namespaces: the box and the
# Syphon server on a home network. SYPHON_VPN points at the syphon-vpn source (default: ../syphon-vpn).
set -u
cd "$(dirname "$0")/.."
VPNSRC="$(cd "${SYPHON_VPN:-../syphon-vpn}" && pwd)"
T="$(mktemp -d)"; chmod 700 "$T"
cleanup() { for n in box node; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $n 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
(cd "$VPNSRC" && cargo build -q --offline) || exit 1
cargo test -q --offline --no-run --test mesh_sync 2>/dev/null || exit 1
VPN="$VPNSRC/target/debug/syphon-vpn --root $T/box"
for n in box node; do ip netns add $n; ip -n $n link set lo up; done
ip link add b1 netns box type veth peer name n0 netns node
ip -n box addr add 192.168.50.1/24 dev b1; ip -n box link set b1 up
ip -n node addr add 192.168.50.20/24 dev n0; ip -n node link set n0 up
$VPN init --endpoint 203.0.113.1 --node 192.168.50.20 >/dev/null || exit 1
CODE="$($VPN link)"
# the link code names the box's own address; in the test it is 192.168.50.1
CODE="$(python3 -c "
import sys,json,base64
c=sys.argv[1]; b=c.split(':',1)[1]; j=json.loads(base64.urlsafe_b64decode(b+'='*(-len(b)%4)))
j['box']='192.168.50.1:51822'
print('SYPHON-VPNBOX-1:'+base64.urlsafe_b64encode(json.dumps(j).encode()).decode().rstrip('='))" "$CODE")"
ip netns exec box $VPN serve --listen 127.0.0.1:0 --files-only >"$T/box.log" 2>&1 &
sleep 1
# someone else on the network gets no answer at all
ip netns exec box curl -s -m 3 -X POST http://192.168.50.1:51822/manage -d x >/dev/null && echo "  FAIL another address got an answer" && exit 1
echo "  ok   another address gets no answer from the management link"
SYPHON_TEST_VPNBOX_CODE="$CODE" ip netns exec node cargo test -q --offline --test mesh_sync the_owner_manages_a_real_vpn_box -- --ignored 2>&1 | tail -4
