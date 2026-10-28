#!/usr/bin/env bash
# Syphon installer for Debian, Ubuntu and Raspberry Pi OS.
#
#   sudo ./install.sh
#
# It asks a few questions (what to call this node, what to call you, a password, and whether this computer can lose power), installs what
# Syphon needs, and starts it. You do not need to know anything about the terminal.
# Advanced: --name NAME  --owner NAME  --data DIR  --persistence on|off  --dedicated yes|no  --storage all|none|"/mnt/a,/mnt/b"  --system-tor  --bridge "LINE" (repeatable)  --yes (use SYPHON_PASSWORD from the environment)
set -euo pipefail

NAME=""; OWNER="${SYPHON_OWNER:-}"; PERSIST=""; DEDICATED=""; STORAGE=""; TORIFY=""; BRIDGES=(); ASK_BRIDGE=1; DATA="/var/lib/syphon"; ASSUME_YES=0; SVC_USER="syphon"
LOG="/tmp/syphon-install.log"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --owner) OWNER="$2"; shift 2 ;;
    --data) DATA="$2"; shift 2 ;;
    --persistence) PERSIST="$2"; shift 2 ;;   # on | off
    --dedicated) DEDICATED="$2"; shift 2 ;;   # yes | no
    --storage) STORAGE="$2"; shift 2 ;;     # all | none | comma separated mount points
    --bridge) BRIDGES+=("$2"); shift 2 ;;
    --system-tor) TORIFY="yes"; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    *) echo "I did not understand \"$1\"." >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; P=$'\033[35m'; R=$'\033[31m'; N=$'\033[0m'; else B=""; D=""; G=""; P=""; R=""; N=""; fi
say()  { printf '%s\n' "$*"; }
step() { QLABEL="$2"; printf '\n%s[%s/%s]%s %s%s%s\n' "$P" "$1" "$TOTAL" "$N" "$B" "$2" "$N"; }
ok()   { printf '    %s✓%s %s\n' "$G" "$N" "$*"; }
die()  { printf '\n%sSomething went wrong:%s %s\n' "$R" "$N" "$*" >&2; [[ -s "$LOG" ]] && printf '%sThe details are in %s%s\n' "$D" "$LOG" "$N" >&2; exit 1; }
QLABEL="working"
# Run a command with its output kept in the log, and show that something is happening: a spinner, how long it has
# been going, and the last line it printed. (Without a terminal, a short "still working" line every 20 seconds.)
progress() {
  "$@" >>"$LOG" 2>&1 &
  local pid=$! start=$SECONDS i=0 frames='|/-\' rc=0 el last
  while kill -0 "$pid" 2>/dev/null; do
    el=$((SECONDS - start))
    if [[ -t 1 ]]; then
      last="$(tail -n 1 "$LOG" 2>/dev/null | tr -cd '[:print:]' | cut -c1-46)"
      printf '\r\033[K    %s %dm%02ds  %s%s%s' "${frames:i%4:1}" $((el / 60)) $((el % 60)) "$D" "$last" "$N"
      i=$((i + 1)); sleep 0.25
    else
      sleep 1
      if (( el > 0 && el % 20 == 0 )); then printf '    ... still working (%dm%02ds)\n' $((el / 60)) $((el % 60)); fi
    fi
  done
  wait "$pid" || rc=$?
  [[ -t 1 ]] && printf '\r\033[K'
  return $rc
}
quiet() { progress "$@" || { tail -n 12 "$LOG" >&2; die "a step failed ($1 ...)"; }; }
# like quiet, but a failure is not the end of the world
soft() { progress "$@" || true; }
TOTAL=5

# Need administrator rights to install software and a background service.
say ""; say "Syphon installer starting..."
if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then say "Syphon needs administrator rights to install. Asking for your computer password…"; exec sudo -E bash "$0" "$@"; fi
  die "please run this as an administrator: sudo ./install.sh"
fi
cd "$(dirname "$0")"
: >"$LOG"
command -v apt-get >/dev/null 2>&1 || die "this installer is for Debian, Ubuntu and Raspberry Pi OS (it needs apt)."

cat <<BANNER

${P}${B}  Syphon${N}  ${D}your videos, your houses, your rules${N}

  This will set up a Syphon node on this computer. It takes about 10 minutes,
  mostly waiting. You will answer a few questions first.
  (Everything the installer does is written to $LOG, if you want to watch it.)

BANNER

# ---- questions
DEFAULT_NAME="$(hostname)"
if [[ -z "$NAME" ]]; then
  if [[ $ASSUME_YES -eq 1 ]]; then NAME="$DEFAULT_NAME"; else
    read -r -p "  1. What should this node be called? (for example \"Home\")  [$DEFAULT_NAME] " NAME
    NAME="${NAME:-$DEFAULT_NAME}"
  fi
fi
if [[ -z "$OWNER" ]]; then
  [[ $ASSUME_YES -eq 1 ]] && die "with --yes, tell me your name with --owner NAME"
  while [[ -z "$OWNER" ]]; do read -r -p "  2. What should we call you? " OWNER; done
fi
PW="${SYPHON_PASSWORD:-}"
if [[ -z "$PW" ]]; then
  [[ $ASSUME_YES -eq 1 ]] && die "with --yes, set SYPHON_PASSWORD in the environment"
  while true; do
    read -r -s -p "  3. Choose a password (8 or more characters): " PW; echo
    if [[ ${#PW} -lt 8 ]]; then say "     That is a bit short. Please use at least 8 characters."; continue; fi
    read -r -s -p "     Type it once more: " PW2; echo
    [[ "$PW" == "$PW2" ]] && break
    say "     Those did not match. Let's try again."
  done
  unset PW2
fi
if [[ -z "$PERSIST" ]]; then
  if [[ $ASSUME_YES -eq 1 ]]; then PERSIST="on"; else
    say ""
    say "  4. Can this computer lose power or crash without warning? (a Raspberry Pi on a wall"
    say "     plug, a spare PC, a house with storms)"
    say "     ${B}Yes${N}: Syphon saves everything safely and picks up unfinished downloads by itself."
    say "     ${B}No${N}:  it is switched off properly each time, and forgets unfinished work."
    while true; do
      read -r -p "     Answer yes or no [yes]: " a
      case "${a:-yes}" in y|Y|yes|YES|Yes) PERSIST="on"; break ;; n|N|no|NO|No) PERSIST="off"; break ;; *) say "     Please type yes or no." ;; esac
    done
  fi
fi
if [[ -z "$DEDICATED" ]]; then
  if [[ $ASSUME_YES -eq 1 ]]; then DEDICATED="no"; else
    say ""
    say "  5. Is this computer used only for Syphon? (a spare PC or a small server that does nothing else)"
    say "     ${B}Yes${N}: Syphon looks at the processor, memory, disk and network speed this computer has and uses"
    say "          what it can, and adjusts by itself if you upgrade the computer or your internet."
    say "     ${B}No${N}:  Syphon stays gentle with fixed, small limits so it never gets in the way of other things."
    say "     (You can change this later in Settings, under Performance.)"
    while true; do
      read -r -p "     Answer yes or no [no]: " a
      case "${a:-no}" in y|Y|yes|YES|Yes) DEDICATED="yes"; break ;; n|N|no|NO|No) DEDICATED="no"; break ;; *) say "     Please type yes or no." ;; esac
    done
  fi
fi
# other drives in this computer (not the one the system is on, not boot partitions, not USB sticks)
EXTRA=()
if command -v findmnt >/dev/null; then
  while IFS= read -r line; do
    t="$(printf '%b' "${line%% *}")"
    [[ -z "$t" || "$t" == "/" || "$t" == /boot* || "$t" == /efi* || "$t" == /snap* || "$t" == /var/lib/docker* || "$t" == /run* ]] && continue
    src="$(awk -v t="$t" '$2==t{print $1; exit}' /proc/mounts)"; base="$(basename "$src" | sed -E 's/p?[0-9]+$//')"
    [[ "$(cat "/sys/block/$base/removable" 2>/dev/null || echo 0)" == "1" ]] && continue
    EXTRA+=("$t")
  done < <(findmnt -rno TARGET -t ext4,xfs,btrfs,f2fs,zfs,ntfs,ntfs3,fuseblk,exfat 2>/dev/null | sort -u)
fi
if [[ -z "$STORAGE" ]]; then
  STORAGE="none"
  if [[ ${#EXTRA[@]} -gt 0 && $ASSUME_YES -eq 0 ]]; then
    say ""
    say "  6. This computer has more than one drive. Where should Syphon keep its videos?"
    say "     (Videos are always encrypted. Syphon always leaves some free space on every drive."
    say "      You can add or change drives later in Settings, under Storage, and link a NAS there too.)"
    i=1; for t in "${EXTRA[@]}"; do sz="$(df -h --output=size,avail "$t" 2>/dev/null | tail -n1 | awk '{print $1" ("$2" free)"}')"; say "       $i) $t   $sz"; i=$((i+1)); done
    if [[ "$DEDICATED" == "yes" ]]; then
      say "     Because this computer is only for Syphon, it can use ${B}all${N} of them."
      read -r -p "     Use all the drives? [yes] " a
      case "${a:-yes}" in y|Y|yes|YES|Yes) STORAGE="all" ;; esac
    fi
    if [[ "$STORAGE" == "none" ]]; then
      read -r -p "     Type the numbers of the drives to use, like 1 3 (or press Enter to use only the main drive): " a
      sel=(); for n in $a; do [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 && "$n" -le ${#EXTRA[@]} ]] && sel+=("${EXTRA[$((n-1))]}"); done
      if [[ ${#sel[@]} -gt 0 ]]; then STORAGE="$(IFS=,; echo "${sel[*]}")"; fi
    fi
  fi
fi
if [[ ${#BRIDGES[@]} -eq 0 && $ASSUME_YES -eq 0 ]]; then
  say ""
  say "  7. Does your country or network block Tor, or would you rather your internet provider"
  say "     could not tell that you use Tor? Then Syphon can connect through a ${B}bridge${N}."
  read -r -p "     Use a bridge? [no] " a
  case "${a:-no}" in y|Y|yes|YES|Yes)
    say ""
    say "     Get bridge lines from https://bridges.torproject.org (choose obfs4 or Snowflake;"
    say "     you can do that on your phone) and paste them here, one per line."
    say "     Press Enter on an empty line when you are done."
    while true; do read -r -p "     bridge> " b; [[ -z "$b" ]] && break; BRIDGES+=("$b"); done ;;
  esac
fi
if [[ "$PERSIST" == "on" ]]; then PMODE="always_on"; else PMODE="on_demand"; fi
if [[ -f "$DATA/keyring.json" || -f "$DATA/vault.json" ]]; then
  say ""; say "  A Syphon node already exists here, so it will be updated and kept as it is."
fi

# ---- installation
step 1 "Installing what Syphon needs (Tor, video tools)"
export DEBIAN_FRONTEND=noninteractive
quiet apt-get update
quiet apt-get install -y tor ffmpeg bubblewrap nftables obfs4proxy build-essential pkg-config curl ca-certificates git openssh-client
# optional: a known-malware scanner for every file (uses about 1 GB of memory while it scans)
QLABEL="Antivirus (ClamAV) and its signatures"
soft apt-get install -y clamav
QLABEL="Network drive support (NFS and SMB)"
soft apt-get install -y nfs-common cifs-utils
soft apt-get install -y ethtool
soft freshclam
QLABEL="Installing what Syphon needs"
# Syphon runs its own Tor with two private addresses; the system-wide Tor is not needed.
systemctl disable --now tor.service >>"$LOG" 2>&1 || true
systemctl disable --now tor@default.service >>"$LOG" 2>&1 || true
ok "done"
if [[ -n "$TORIFY" ]]; then :; fi

step 2 "Getting the build tools ready"
need_rust=1
if command -v cargo >/dev/null 2>&1; then
  ver="$(cargo --version | awk '{print $2}')"
  if [[ "$(printf '%s\n1.80.0\n' "$ver" | sort -V | head -n1)" == "1.80.0" ]]; then need_rust=0; fi
fi
if [[ $need_rust -eq 1 ]]; then
  progress curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh || die "could not download the Rust installer. Check the internet connection."
  quiet sh /tmp/rustup.sh -y --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
fi
ok "done"

step 3 "Building Syphon (the slow part: 5 to 10 minutes, please leave it running)"
say "    You will see a timer and the latest line of the build. It is not stuck."
quiet cargo build --release
install -m 0755 target/release/syphon /usr/local/bin/syphon
ok "done"

step 4 "Creating your node"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$SVC_USER"
# The safety scanner runs ffmpeg and ClamAV inside a bubblewrap sandbox when this computer allows it. Some systems
# (virtual machines, hardened kernels, Ubuntu 24.04) switch off the feature bubblewrap needs for ordinary users.
SBX=(bwrap --unshare-all --die-with-parent --ro-bind / / --dev /dev --tmpfs /tmp -- true)
if ! runuser -u "$SVC_USER" -- "${SBX[@]}" >/dev/null 2>&1; then
  say "    This computer does not let ordinary programs use a sandbox yet. Switching that on."
  : > /etc/sysctl.d/60-syphon-sandbox.conf
  [[ -e /proc/sys/kernel/unprivileged_userns_clone ]] && echo "kernel.unprivileged_userns_clone=1" >> /etc/sysctl.d/60-syphon-sandbox.conf
  [[ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]] && echo "kernel.apparmor_restrict_unprivileged_userns=0" >> /etc/sysctl.d/60-syphon-sandbox.conf
  [[ "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 1)" == "0" ]] && echo "user.max_user_namespaces=15000" >> /etc/sysctl.d/60-syphon-sandbox.conf
  sysctl --system >>"$LOG" 2>&1 || true
  if runuser -u "$SVC_USER" -- "${SBX[@]}" >/dev/null 2>&1; then ok "the scanner's sandbox works"; else
    say "    The sandbox still cannot start here (a virtual machine or container can block it). Files are still scanned in full;"
    say "    the scanning programs just run without the extra wall. Settings > Safety scan shows the reason."
  fi
fi
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$DATA"
if [[ ! -f "$DATA/keyring.json" && ! -f "$DATA/vault.json" ]]; then
  SYPHON_PASSWORD="$PW" runuser -u "$SVC_USER" -- env SYPHON_PASSWORD="$PW" /usr/local/bin/syphon --dir "$DATA" init --name "$NAME" --owner "$OWNER" --transport tor --persistence "$PMODE" >>"$LOG" 2>&1 || die "could not create the node"
fi
unset PW
if [[ "$DEDICATED" == "yes" ]]; then runuser -u "$SVC_USER" -- /usr/local/bin/syphon --dir "$DATA" set perf dedicated >>"$LOG" 2>&1 || say "    Could not save the performance choice; set it later in Settings."; fi
STORAGE_PATHS=()
if [[ "$STORAGE" == "all" ]]; then
  STORAGE_PATHS=("${EXTRA[@]}")
elif [[ "$STORAGE" != "none" && -n "$STORAGE" ]]; then
  IFS=, read -r -a STORAGE_PATHS <<<"$STORAGE"
fi
for m in "${STORAGE_PATHS[@]}"; do
  [[ -d "$m" ]] || { say "    $m is not a folder, so it was skipped."; continue; }
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$m/syphon"
  [[ "$STORAGE" == "all" ]] || runuser -u "$SVC_USER" -- /usr/local/bin/syphon --dir "$DATA" set storage-add "$m" >>"$LOG" 2>&1 || say "    Could not add $m; add it later in Settings > Storage."
done
[[ "$STORAGE" == "all" ]] && { runuser -u "$SVC_USER" -- /usr/local/bin/syphon --dir "$DATA" set storage all >>"$LOG" 2>&1 || say "    Could not turn on 'use all drives'; do it later in Settings > Storage."; }
# the service may only write where it is told to; list each extra drive
if [[ ${#STORAGE_PATHS[@]} -gt 0 ]]; then
  install -d /etc/syphon /etc/systemd/system/syphon.service.d
  printf '%s\n' "${STORAGE_PATHS[@]/%//syphon}" > /etc/syphon/storage-paths
  { echo "[Service]"; printf 'ReadWritePaths=-%s\n' "${STORAGE_PATHS[@]/%//syphon}"; } > /etc/systemd/system/syphon.service.d/storage.conf
fi
for b in "${BRIDGES[@]}"; do
  runuser -u "$SVC_USER" -- /usr/local/bin/syphon --dir "$DATA" set bridge "$b" >>"$LOG" 2>&1 || say "    That bridge line was not accepted, so it was skipped: $b"
done
if [[ ${#BRIDGES[@]} -gt 0 ]]; then quiet apt-get install -y snowflake-client || say "    (snowflake-client could not be installed; obfs4 bridges still work)"; fi
install -m 0644 systemd/syphon.service /etc/systemd/system/syphon.service
install -m 0644 systemd/syphon-torify.service /etc/systemd/system/syphon-torify.service
install -m 0755 systemd/syphon-ctl /usr/local/bin/syphon-ctl
install -m 0755 systemd/syphon-update /usr/local/bin/syphon-update
install -m 0644 systemd/syphon-update.service /etc/systemd/system/syphon-update.service
install -m 0644 systemd/syphon-update.path /etc/systemd/system/syphon-update.path
sed -i "s|/var/lib/syphon|$DATA|g" /etc/systemd/system/syphon-update.path
sed -i "s|/var/lib/syphon|$DATA|g" /etc/systemd/system/syphon.service /etc/systemd/system/syphon-torify.service
# where updates come from and whose signature they must carry (shipped with the source you installed from)
if [[ -s release/allowed_signers && -s release/update.default ]]; then
  install -d -m 0755 /etc/syphon
  install -m 0644 release/allowed_signers /etc/syphon/allowed_signers
  { cat release/update.default; printf 'DATA="%s"\n' "$DATA"; } > /etc/syphon/update.conf
  # install -d only gives the LAST folder to the service user, so create the parent first (the program writes its requests there)
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0755 "$DATA/update"
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0755 "$DATA/update/requests"
fi
sed -i "s|^DATA=.*|DATA=\"\${SYPHON_DATA:-$DATA}\"|" /usr/local/bin/syphon-ctl
sed -i "s|; DATA=/var/lib/syphon\$|; DATA=$DATA|" /usr/local/bin/syphon-update
[[ "$PERSIST" == "off" ]] && sed -i 's/^Restart=.*/Restart=on-failure/' /etc/systemd/system/syphon.service 2>/dev/null || true
systemctl daemon-reload
quiet systemctl enable --now syphon.service
# the helper that lets the web page update or remove this node (it waits for a request, otherwise does nothing)
quiet systemctl enable --now syphon-update.path
ok "Syphon is running and will start again by itself after a restart"

say ""
say "  What this computer has, and what Syphon will use of it:"
/usr/local/bin/syphon perf 2>/dev/null | sed 's/^/    /' || true
step 5 "Connecting to Tor (this can take a minute or two)"
ONION=""
for _ in $(seq 1 90); do
  if INFO="$(runuser -u "$SVC_USER" -- /usr/local/bin/syphon --dir "$DATA" info 2>/dev/null)" && grep -q 'access onion: *[a-z0-9]*\.onion' <<<"$INFO"; then
    ONION="$(grep 'access onion:' <<<"$INFO" | awk '{print $3}')"; break
  fi
  sleep 2
done
if [[ -n "$ONION" ]]; then ok "your private outside address is ready"; else
  say "    Tor is still starting. That is usually fine and finishes by itself."
  [[ ${#BRIDGES[@]} -eq 0 ]] && say "    If it is still not ready after 10 minutes, your network may block Tor. Then get a bridge from bridges.torproject.org and run:  sudo syphon-ctl bridge add \"LINE\""
fi

if [[ -n "$TORIFY" ]]; then /usr/local/bin/syphon-ctl torify on >>"$LOG" 2>&1 && ok "everything on this computer now goes through Tor" || say "    Could not turn on system-wide Tor; see $LOG"; fi

IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' || true)"
cat <<DONE

${G}${B}  All set.${N}

  Open Syphon in a web browser on any phone, tablet or laptop on your home network:

DONE
if [[ -n "$IPS" ]]; then while read -r ip; do [[ -n "$ip" ]] && say "      ${B}http://$ip:8096${N}"; done <<<"$IPS"; else say "      ${B}http://$(hostname).local:8096${N}  (or this computer's address on your network)"; fi
cat <<DONE

  Sign in as ${B}$OWNER${N} with the password you just chose.

  Next, in Syphon:
    • Add: search a source or upload videos. New files wait in Review until you approve them.
    • Mesh: connect your other houses with an invite code. Settings has a QR code for your phone.
    • Settings: turn on two-step sign-in so you can safely use Syphon away from home.

  ${B}Optional:${N} to send everything this computer does through Tor (not just Syphon):
      sudo syphon-ctl torify on        (undo with: sudo syphon-ctl torify off)

  Away from home you use Tor Browser. Your private outside address is shown in Settings.
  If something looks wrong:  sudo journalctl -u syphon -n 50
DONE
