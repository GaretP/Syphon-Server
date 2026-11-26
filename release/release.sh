#!/usr/bin/env bash
# Build, package and SIGN a Syphon release on your own computer.
#
#   release/release.sh v0.2.0 --key ~/syphon-signing [--target aarch64-unknown-linux-gnu]... [--requires v0.1.5] [--publish]
#
# It builds with the exact dependencies in Cargo.lock (--locked) and the Rust version in rust-toolchain.toml,
# packs the program with its two helper scripts, writes a manifest (version, SHA-256 hashes, sizes, the hash of
# Cargo.lock) and signs the manifest with your private key. Nodes only install what that signature covers.
# The private key never leaves this computer. See RELEASING.md.
set -euo pipefail
cd "$(dirname "$0")/.."
die() { echo "release: $*" >&2; exit 1; }

VERSION="${1:-}"; shift || true
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "give a version like v0.2.0"
KEY=""; SIGNERS=release/allowed_signers; PUBLISH=0; REQUIRES=""; TARGETS=(); BINARY=""; OUT="dist/$VERSION"; NOGIT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) KEY="$2"; shift 2 ;;
    --signers) SIGNERS="$2"; shift 2 ;;  # who may sign (default: release/allowed_signers)
    --target) TARGETS+=("$2"); shift 2 ;;
    --requires) REQUIRES="$2"; shift 2 ;;
    --publish) PUBLISH=1; shift ;;
    --binary) BINARY="$2"; shift 2 ;;     # package a program that is already built (tests)
    --out) OUT="$2"; shift 2 ;;
    --no-git) NOGIT=1; shift ;;           # skip the repository checks (tests)
    *) die "unknown option $1" ;;
  esac
done
[[ -n "$KEY" && -f "$KEY" ]] || die "give your private signing key with --key FILE"
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  if [[ -n "$BINARY" ]]; then TARGETS=("$(uname -m)-unknown-linux-gnu"); else TARGETS=("$(rustc -vV | sed -n 's/^host: //p')"); fi
fi

if [[ $NOGIT -eq 0 ]]; then
  git rev-parse --git-dir >/dev/null 2>&1 || die "run this inside the repository"
  [[ -z "$(git status --porcelain)" ]] || die "the working tree has uncommitted changes; commit them first so the release matches the code"
  git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1 || die "Cargo.lock is not committed. It pins every dependency and must be part of the release"
  if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
    [[ "$(git rev-parse "$VERSION^{commit}")" == "$(git rev-parse HEAD)" ]] || die "tag $VERSION already exists and points at a different commit"
  else
    git tag "$VERSION"; echo "created tag $VERSION"
  fi
fi
if [[ -f rust-toolchain.toml && -z "$BINARY" ]]; then
  want="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
  have="$(rustc --version | awk '{print $2}')"
  [[ "$want" == "$have" ]] || die "rust-toolchain.toml pins Rust $want but the active compiler is $have"
fi

mkdir -p "$OUT"; rm -f "$OUT"/*
LOCKSUM="$(sha256sum Cargo.lock | cut -d' ' -f1)"
{
  echo "syphon-release 1"
  echo "version $VERSION"
  echo "issued $(date +%s)"
  [[ -n "$REQUIRES" ]] && echo "requires $REQUIRES"
  echo "lock sha256 $LOCKSUM"
} >"$OUT/manifest.txt"

for T in "${TARGETS[@]}"; do
  case "$T" in x86_64-*) ARCH=x86_64 ;; aarch64-*) ARCH=aarch64 ;; *) die "unsupported target $T" ;; esac
  STAGE="$(mktemp -d)"
  if [[ -n "$BINARY" ]]; then
    cp "$BINARY" "$STAGE/syphon"
  else
    echo "building $VERSION for $T (locked dependencies)…"
    SYPHON_VERSION="$VERSION" cargo build --release --locked --target "$T"
    cp "target/$T/release/syphon" "$STAGE/syphon"
  fi
  cp systemd/syphon-update systemd/syphon-ctl "$STAGE/"
  chmod 0755 "$STAGE"/*
  if [[ "$ARCH" == "$(uname -m | sed 's/amd64/x86_64/;s/arm64/aarch64/')" ]]; then
    said="$("$STAGE/syphon" --version | awk '{print $2}')"
    [[ "$said" == "$VERSION" ]] || die "the built program says $said, expected $VERSION"
  fi
  NAME="syphon-$VERSION-$ARCH-linux.tar.gz"
  # reproducible archive: fixed order, owner and time
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - -C "$STAGE" syphon syphon-update syphon-ctl | gzip -n -9 >"$OUT/$NAME"
  rm -rf "$STAGE"
  echo "file $NAME sha256 $(sha256sum "$OUT/$NAME" | cut -d' ' -f1) size $(stat -c %s "$OUT/$NAME") arch $ARCH" >>"$OUT/manifest.txt"
done

rm -f "$OUT/manifest.txt.sig"
ssh-keygen -Y sign -f "$KEY" -n syphon-release "$OUT/manifest.txt" >/dev/null
ssh-keygen -Y verify -f "$SIGNERS" -I release -n syphon-release -s "$OUT/manifest.txt.sig" <"$OUT/manifest.txt" >/dev/null \
  || die "the signature does not verify against $SIGNERS: is that the key you signed with?"
echo "signed and verified. Files in $OUT:"; ls -1 "$OUT"

if [[ $PUBLISH -eq 1 ]]; then
  command -v gh >/dev/null || die "--publish needs the GitHub CLI (gh). Upload the files in $OUT to a release named $VERSION by hand instead"
  git push origin "$VERSION"
  gh release create "$VERSION" "$OUT"/* --title "Syphon $VERSION" --notes "Signed release $VERSION."
  echo "published $VERSION"
else
  echo "Not published. Upload every file in $OUT to a GitHub release named $VERSION (or run again with --publish)."
fi
