#!/usr/bin/env bash
# End-to-end test of the updater (systemd/syphon-update) with a real signature, a real archive and a local
# "release server" (a folder). The node, systemctl and the running program are stand-ins, so it runs anywhere
# with root. Run: sudo tests/update_e2e.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"
id syphon >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin syphon
T="$(mktemp -d /var/tmp/syphon-e2e.XXXXXX)"; chmod 755 "$T"
trap 'pkill -f "$T/srv.py" 2>/dev/null; rm -rf "$T"' EXIT
export SYPHON_ETC="$T/etc" SYPHON_BINDIR="$T/bin" SYPHON_RUN="$T/run" HEALTH_TRIES=3 HEALTH_WAIT=1
DATA="$T/data"; mkdir -p "$SYPHON_ETC" "$SYPHON_BINDIR" "$SYPHON_RUN" "$DATA" "$T/stub" "$T/rel"
chmod 755 "$SYPHON_BINDIR"; chown syphon:syphon "$DATA"
echo 'access_bind = "127.0.0.1:18096"' >"$DATA/config.toml"
echo "db-old" >"$DATA/syphon.db"; chown syphon:syphon "$DATA/syphon.db"
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL $*"; }
expect() { # description, actual, expected
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
state() { sed -n 's/.*"state":"\([a-z]*\)".*/\1/p' "$DATA/update/status.json"; }
msg() { sed -n 's/.*"message":"\([^"]*\)".*/\1/p' "$DATA/update/status.json"; }
ver() { "$SYPHON_BINDIR/syphon" --version | awk '{print $2}'; }

# keys: the real one for releases, a stranger's for the forgery test
ssh-keygen -q -t ed25519 -N '' -f "$T/key" -C test; ssh-keygen -q -t ed25519 -N '' -f "$T/evil" -C evil
printf 'release namespaces="syphon-release" %s\n' "$(cat "$T/key.pub")" >"$SYPHON_ETC/allowed_signers"
printf 'BASE="file://%s"\nROUTE=direct\nDATA="%s"\n' "$T/rel" "$DATA" >"$SYPHON_ETC/update.conf"

# a stand-in for the syphon program: knows --version and snapshot; "BAD" in it means it will not serve; "MIGRATES" changes the database
mkprog() { # version [extra]
  local extra="${2:-}"
  cat >"$T/$1.prog" <<EOF
#!/bin/sh
# $extra
case "\$*" in
  *--version*) echo "syphon $1" ;;
  *snapshot*) while [ \$# -gt 0 ]; do [ "\$1" = "--dir" ] && d="\$2"; [ "\$1" = "--to" ] && to="\$2"; shift; done; mkdir -p "\$to"; cp "\$d/syphon.db" "\$to/syphon.db"; echo kr > "\$to/keyring.json" ;;
esac
EOF
  chmod 755 "$T/$1.prog"
}
# stub systemctl: "restart" starts a tiny web server unless the installed program is BAD or the database is incompatible
cat >"$T/srv.py" <<'EOF'
import http.server,sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        if s.path.startswith('/api/status'): s.send_response(200); s.end_headers(); s.wfile.write(b'{"name":null,"locked":false,"zone":"lan"}')
        else: s.send_response(401); s.end_headers()
    def log_message(*a): pass
http.server.HTTPServer(('127.0.0.1',18096),H).serve_forever()
EOF
cat >"$T/stub/systemctl" <<EOF
#!/bin/bash
T="$T"; DATA="$DATA"
case "\$1" in
  restart|start|stop)
    pkill -f "\$T/srv.py" 2>/dev/null; sleep 0.3
    [[ "\$1" == stop ]] && exit 0
    echo "\$1 armed=\$([[ -e "\$SYPHON_RUN/syphon-handoff/arm" ]] && echo yes || echo no)" >>"\$T/systemctl.log"
    prog="\$SYPHON_BINDIR/syphon"
    if grep -q MIGRATES "\$prog"; then echo db-new >"\$DATA/syphon.db"; fi
    grep -q BAD "\$prog" && exit 0
    [[ "\$(cat "\$DATA/syphon.db")" == db-new ]] && ! grep -q MIGRATES "\$prog" && exit 0
    nohup python3 "\$T/srv.py" >/dev/null 2>&1 &
    sleep 0.5 ;;
esac
exit 0
EOF
chmod +x "$T/stub/systemctl"; export PATH="$T/stub:$PATH"
UPDATE="bash systemd/syphon-update"

release() { # version [extra-args for release.sh]   (program stand-in must exist: $T/<version>.prog)
  local v="$1"; shift
  bash release/release.sh "$v" --key "${KEYFILE:-$T/key}" --signers "$T/signers-for-release" --binary "$T/$v.prog" --no-git --out "$T/out/$v" "$@" >/dev/null 2>&1 || { bad "release.sh $v failed"; return 1; }
  mkdir -p "$T/rel/latest/download" "$T/rel/download/$v"
  cp "$T/out/$v"/manifest.txt "$T/out/$v"/manifest.txt.sig "$T/rel/latest/download/"
  cp "$T/out/$v"/*.tar.gz "$T/rel/download/$v/"
}
printf 'release namespaces="syphon-release" %s\n' "$(cat "$T/key.pub")" >"$T/signers-for-release"
cp "$T/stub/systemctl" "$T/stub/systemctl.keep"

echo "== install v0.1.0 as the running version"
mkprog v0.1.0; cp "$T/v0.1.0.prog" "$SYPHON_BINDIR/syphon"
bash systemd/syphon-ctl status >/dev/null 2>&1 || true
expect "starting version" "$(ver)" "v0.1.0"
systemctl restart syphon   # the node is running and its library is open

echo "== nothing published yet"
$UPDATE check; expect "no release list: refused with a message" "$(state)" "failed"

echo "== a good signed release installs, saves the database and keeps the library unlocked"
mkprog v0.2.0; release v0.2.0
$UPDATE check; expect "update is offered" "$(state)" "available"
$UPDATE apply
expect "update done" "$(state)" "done"
expect "new version runs" "$(ver)" "v0.2.0"
[[ -x "$SYPHON_BINDIR/syphon.prev" ]] && expect "previous program kept" "$("$SYPHON_BINDIR/syphon.prev" --version | awk '{print $2}')" "v0.1.0" || bad "previous program kept"
ls "$DATA/update/snapshots"/before-v0.1.0-*/syphon.db >/dev/null 2>&1 && ok "database snapshot saved before the update" || bad "database snapshot saved before the update"
grep -q "armed=yes" "$T/systemctl.log" && ok "key hand-over was armed for the restart" || bad "key hand-over was armed for the restart"
case "$(msg)" in *"stayed unlocked"*) ok "reports the library stayed unlocked" ;; *) bad "reports the library stayed unlocked ($(msg))" ;; esac
[[ ! -e "$SYPHON_RUN/syphon-handoff/arm" && ! -e "$SYPHON_RUN/syphon-handoff/key" ]] && ok "hand-over files cleaned up" || bad "hand-over files cleaned up"

echo "== already current"
$UPDATE apply; expect "up to date" "$(state)" "uptodate"

echo "== an older release is never installed (downgrade)"
mkprog v0.1.5; release v0.1.5
$UPDATE apply; expect "older release ignored" "$(state)" "uptodate"; expect "still v0.2.0" "$(ver)" "v0.2.0"

echo "== a release signed by someone else is refused"
mkprog v0.3.0
# release.sh itself refuses to produce a release that does not verify against the signers file
if bash release/release.sh v0.3.0 --key "$T/evil" --signers "$T/signers-for-release" --binary "$T/v0.3.0.prog" --no-git --out "$T/out/forged" >/dev/null 2>&1; then bad "release.sh signed with the wrong key"; else ok "release.sh refuses a signature that is not in the signers file"; fi
# sign by hand with the stranger's key instead
bash release/release.sh v0.3.0 --key "$T/key" --signers "$T/signers-for-release" --binary "$T/v0.3.0.prog" --no-git --out "$T/out/v0.3.0" >/dev/null 2>&1
rm -f "$T/out/v0.3.0/manifest.txt.sig"; ssh-keygen -Y sign -f "$T/evil" -n syphon-release "$T/out/v0.3.0/manifest.txt" >/dev/null 2>&1
mkdir -p "$T/rel/latest/download" "$T/rel/download/v0.3.0"; cp "$T/out/v0.3.0/manifest.txt" "$T/out/v0.3.0/manifest.txt.sig" "$T/rel/latest/download/"; cp "$T/out/v0.3.0"/*.tar.gz "$T/rel/download/v0.3.0/"
$UPDATE apply; expect "forged signature refused" "$(state)" "failed"; expect "still v0.2.0" "$(ver)" "v0.2.0"
case "$(msg)" in *"not signed"*) ok "says why" ;; *) bad "says why ($(msg))" ;; esac

echo "== a tampered download is refused"
release v0.3.0 >/dev/null
echo "extra" >>"$T/rel/download/v0.3.0/syphon-v0.3.0-x86_64-linux.tar.gz"
$UPDATE apply; expect "tampered archive refused" "$(state)" "failed"; expect "still v0.2.0" "$(ver)" "v0.2.0"

# put a different archive under a release and sign a matching manifest, to test the checks that come after the hash
resign() { # version archive-file
  local v="$1" f="$2" sha size
  sha="$(sha256sum "$f" | cut -d' ' -f1)"; size="$(stat -c %s "$f")"
  cp "$f" "$T/rel/download/$v/syphon-$v-x86_64-linux.tar.gz"
  sed -i "s/^file .*/file syphon-$v-x86_64-linux.tar.gz sha256 $sha size $size arch x86_64/" "$T/rel/latest/download/manifest.txt"
  rm -f "$T/rel/latest/download/manifest.txt.sig"; ssh-keygen -Y sign -f "$T/key" -n syphon-release "$T/rel/latest/download/manifest.txt" >/dev/null 2>&1
}
repack() { # version prog-file [extra file name]
  local d; d="$(mktemp -d)"; cp "$2" "$d/syphon"; cp systemd/syphon-update systemd/syphon-ctl "$d/"
  local extra=(); if [[ -n "${3:-}" ]]; then echo x >"$d/$3"; extra=("$3"); fi
  tar -czf "$T/repacked.tgz" -C "$d" syphon syphon-update syphon-ctl "${extra[@]}"; rm -rf "$d"
}

echo "== a program that reports the wrong version is refused"
rm -rf "$T/rel"; mkdir -p "$T/rel"
mkprog v0.4.0; mkprog v0.3.9; release v0.4.0
repack v0.4.0 "$T/v0.3.9.prog"; resign v0.4.0 "$T/repacked.tgz"
$UPDATE apply; expect "wrong self-reported version refused" "$(state)" "failed"; expect "still v0.2.0" "$(ver)" "v0.2.0"
case "$(msg)" in *"reports version"*) ok "says why" ;; *) bad "says why ($(msg))" ;; esac

echo "== an archive with an unexpected file is refused"
rm -rf "$T/rel"; mkdir -p "$T/rel"
mkprog v0.5.0; release v0.5.0
repack v0.5.0 "$T/v0.5.0.prog" extra; resign v0.5.0 "$T/repacked.tgz"
$UPDATE apply; expect "unexpected archive content refused" "$(state)" "failed"; expect "still v0.2.0" "$(ver)" "v0.2.0"

echo "== a release that will not start is rolled back"
rm -rf "$T/rel"; mkdir -p "$T/rel"
mkprog v0.6.0 BAD; release v0.6.0
$UPDATE apply; expect "rolled back" "$(state)" "rolledback"; expect "old program is back" "$(ver)" "v0.2.0"
expect "database untouched when the old program works" "$(cat "$DATA/syphon.db")" "db-old"

echo "== a release that changes the database and will not start: the database comes back too"
rm -rf "$T/rel"; mkdir -p "$T/rel"
mkprog v0.7.0 "BAD MIGRATES"; release v0.7.0
$UPDATE apply; expect "rolled back with the saved database" "$(state)" "rolledback"; expect "old program is back" "$(ver)" "v0.2.0"
expect "database restored" "$(cat "$DATA/syphon.db")" "db-old"
case "$(msg)" in *"database saved"*) ok "reports the database restore" ;; *) bad "reports the database restore ($(msg))" ;; esac

echo "== going back by hand"
$UPDATE rollback; expect "manual rollback" "$(state)" "done"; expect "back at v0.1.0" "$(ver)" "v0.1.0"

echo "== no program for this computer"
rm -rf "$T/rel"; mkdir -p "$T/rel"; mkprog v0.8.0; release v0.8.0
sed -i 's/ arch x86_64/ arch riscv64/' "$T/rel/latest/download/manifest.txt"; rm -f "$T/rel/latest/download/manifest.txt.sig"; ssh-keygen -Y sign -f "$T/key" -n syphon-release "$T/rel/latest/download/manifest.txt" >/dev/null 2>&1
$UPDATE check; expect "missing architecture reported" "$(state)" "failed"

echo "== a fresh install lets the service user write its requests"
# install -d -o only gives the LAST folder to the service user; the parent must be created on its own line (this broke every
# button that talks to the helper on a fresh install)
D="$(grep -n 'install -d -o "\$SVC_USER" -g "\$SVC_USER" -m 0755 "\$DATA/update"$' install.sh | head -1 | cut -d: -f1)"
R="$(grep -n 'install -d -o "\$SVC_USER" -g "\$SVC_USER" -m 0755 "\$DATA/update/requests"' install.sh | head -1 | cut -d: -f1)"
if [[ -n "$D" && -n "$R" && "$D" -lt "$R" ]]; then ok "installer creates the update folder for the service user first"; else bad "installer creates the update folder for the service user first"; fi
grep -q 'ExecStartPre=+.*update/requests' "systemd/syphon.service" && ok "service repairs the folder's owner on every start" || bad "service repairs the folder's owner on every start"
echo
echo "passed: $PASS  failed: $FAIL"
[[ $FAIL -eq 0 ]]
