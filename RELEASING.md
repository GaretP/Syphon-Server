# Releasing Syphon

A release is a signed manifest plus a program archive. You make it on your own computer; the nodes only verify and install.

## One-time setup

1. **Signing key** (keep the private half offline, with a passphrase):

       ssh-keygen -t ed25519 -f ~/syphon-signing -C "syphon release"

   Its public half is already in `release/allowed_signers` (principal `release`, namespace `syphon-release`). To change keys, replace that line, commit, and give every node the new file: `sudo syphon-ctl update-source set https://github.com/GaretP/Syphon-Server --signers release/allowed_signers`.
2. **Repository.** Commit everything, including `Cargo.lock`, `rust-toolchain.toml`, `release/` and this file, and push to https://github.com/GaretP/Syphon-Server.
3. **GitHub CLI** (only for `--publish`): `gh auth login`. Without it, upload the files by hand (below).
4. **Rust** as pinned in `rust-toolchain.toml` (rustup picks it up by itself).
5. **First install** on a node: clone the repository on it and run `sudo ./install.sh`. That installs the update helper, the signers file and the update address.

## Making a release

    release/release.sh v0.2.0 --key ~/syphon-signing --publish

It refuses to run if the working tree has uncommitted changes, `Cargo.lock` is not committed, the compiler differs from the pinned one, or the signature does not verify against `release/allowed_signers`. It creates the git tag, builds with `--locked`, packs `syphon-v0.2.0-x86_64-linux.tar.gz`, writes and signs `manifest.txt` and, with `--publish`, pushes the tag and creates the GitHub release. Without `--publish`, upload every file in `dist/v0.2.0/` to a GitHub release named `v0.2.0`.

The release must be the "latest" non-draft, non-pre-release on GitHub: nodes read `releases/latest/download/manifest.txt`.

### ARM

Add a target per architecture. Cross-building needs the target and a C cross compiler (the database is compiled in):

    rustup target add aarch64-unknown-linux-gnu
    sudo apt install gcc-aarch64-linux-gnu
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    release/release.sh v0.2.0 --key ~/syphon-signing --target x86_64-unknown-linux-gnu --target aarch64-unknown-linux-gnu --publish

A node picks the archive that matches its own processor. A release without one for a node's processor is refused by that node with a clear message.

### Patches and ordering

`--requires v0.2.0` writes a `requires` line: a node older than that is told to update to it first. Use it when a release depends on a change that must be in place (for example a database change that older programs cannot read).

## Updating a node

Settings, Updates, Check, Install (or `sudo syphon-ctl update check|apply|rollback`). The node downloads through Tor, verifies, saves a copy of its database, installs, restarts with the library kept unlocked, and rolls back by itself if it does not come back.

## Testing the updater

`sudo tests/update_e2e.sh` runs the whole flow with real signatures and a local folder as the release server: good release, forged signature, tampered download, wrong version, unexpected archive contents, downgrade, a release that does not start, one that changes the database and does not start, manual rollback.
