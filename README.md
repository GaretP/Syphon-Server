# Syphon

A self-hosted media server for a small mesh of homes. Each home runs one node. Nodes find each other
through Tor onion services, sync their libraries when asked, and keep every video encrypted on disk.
Watch from any phone, laptop or TV on your home network, and from outside through the Syphon app and
a small VPN box.

```
   Home A                     Home B                     Home C
 ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
 │ mesh.onion   │◄────────►│ mesh.onion   │◄────────►│ mesh.onion   │   nodes only, key-authorised
 │ LAN :8096    │          │ LAN :8096    │          │ LAN :8096    │   phones, laptops, TVs at home
 │ VPN box      │          │ VPN box      │          │ VPN box      │   your devices, away from home
 └──────────────┘          └──────────────┘          └──────────────┘
```

Rust, SQLite, one program, no Docker. Linux (Debian, Ubuntu, Raspberry Pi OS).

## Install

On the computer that will be the node:

```bash
sudo ./install.sh
```

It asks what to call the node, what to call **you**, a password, and a few questions about the
computer (can it lose power without warning, is it used only for Syphon, which drives to use). Then
it installs Tor, ffmpeg and the video drivers for your graphics card, builds Syphon, and starts it as
a service. At the end it prints the address to open, for example `http://192.168.1.20:8096`.

Advanced: `--name`, `--owner`, `--data DIR`, and `--yes` (reads `SYPHON_PASSWORD` from the environment).
By hand: `cargo build --release`, then `syphon init` (it asks the same questions) and `syphon run`.
For development without Tor: `syphon init --transport direct`.

## Using it

- **At home.** Any device on your network opens the node's address and signs in. Settings shows the
  address and a QR code. The **Syphon app** (separate project, Windows and Linux) finds the node by
  itself and has profiles and a TV mode.
- **Away from home.** Through the **VPN box** (separate project, `syphon-vpn`) and the Syphon app. See
  [Away from home](#away-from-home).
- **Library.** Rows of posters: Recently added (switch it off or choose how many days it covers in
  Settings > Node > Library), one row per genre, then the rest. Movies, series and anime are all sorted
  into the same genre rows.
- **Upload.** Send your own videos from the browser. Large files go in 8 MB pieces and pick up where
  they stopped if the connection drops. Folders on your drives and NAS can also be pulled in
  automatically (Settings > Storage).
- **Review.** Everything new waits here, encrypted, until it has been scanned and you approve it.
  Nothing in Review is played or shared with other nodes.
- **Mesh.** Connect your other nodes and decide what syncs.
- **Console** (owner). Syphon's own commands, and the computer's terminal. See [Console](#console).
- **Dark and light.** The sun/moon button switches.

## Shows, seasons and episodes

Episodes of one show appear as **one poster**, with a season picker, an episode list and a Play /
Continue button (it resumes where you stopped; "Next episode" crosses seasons).

- **Automatic:** the node reads the file name (`S01E02`, `1x02`, `Season 1 Episode 2`, `- 05`, and
  fansub-style names; release tags like 1080p or WEB-DL are ignored) and groups by show title. Seasons
  in a title ("S2", "Season 3", "2nd Season") become seasons of one show.
- **Details and posters** are looked up through Tor (title and year only): TVmaze for series, Jikan
  and AniList for anime, Wikidata and other public catalogues for movies, or TMDB if you add a free key
  in `metadata.tmdb_key`. Posters are stored encrypted. Genres you type by hand win.
- **By hand, when names are too messy:** Library > Organize > Combine into one series, or Rename on a
  show page. Every change is a signed edit, so your other nodes see the same grouping.

## Connecting two nodes

Pairing works like a friend request:

1. On either node: **Mesh > Create invite code**, and send the code to the other owner. It works once
   and expires after 24 hours.
2. On the other node: paste it and press **Ask to connect**.
3. The first owner sees the request, with a fingerprint to check, and presses **Accept**.

Nobody has to press anything at the same moment; the request is stored and retried.

## Sync

Nothing is pushed. For each connected node: heartbeat > compare catalogs > request what is missing >
the holder answers **yes, no or ask the owner** > capped, verified transfer. The stop switch and every
cap (sending and receiving speed, parallel transfers, free disk, library size, daily window, which
kinds to mirror) are checked before every chunk on both sides. The Mesh page shows each step live.

Every file arriving from another node is scanned by *this* node before it joins the library or is
passed on, so one infected node can't infect the others.

## Storage

Settings > Storage. Videos can live on several drives and on a NAS.

- **Drives are found by themselves.** The list shows the drives in the computer that Syphon isn't
  using yet: mounted ones get **Use this drive**, and ones nothing has mounted get **Connect and use**
  (the system helper mounts them by their ID under `/mnt/syphon/<name>`, with `nofail` so a missing
  drive never holds up the start). Syphon never formats a drive: one without a file system, a locked
  (encrypted) one or a FAT32 one is listed with what to do first. Adding a folder by hand is at the
  bottom, for when a drive isn't listed.
- **Two modes:** *use all drives* (every internal drive, including ones added later) or *only the drives
  I choose*. New videos go to the drive with the most room, or fill drives in order. Each drive keeps
  some space free (by default the larger of 5 GB or 2%).
- **NAS:** SMB or NFS, mounted by the helper; the SMB password is kept in a root-only file. Or mount it
  yourself and choose "Already mounted".
- A drive can be switched off for new files, emptied onto the others ("Move files off"), or removed.
- Deleted videos wait in the Trash (Settings > Storage) for 30 days and can be restored.

CLI: `syphon drives`, `syphon set storage all|selected`, `syphon set storage-add PATH`,
`sudo syphon-ctl storage allow PATH`.

## Playback and conversion

The node looks inside each video. Files a browser can play are sent as they are; MKV files with a
browser-friendly picture are re-wrapped without re-encoding; HEVC, 10-bit and old formats are
converted while you watch. Settings > Node > Playback and conversion sets the sharpness (480p to
1440p, or the same size) and the format (AV1, smaller; or H.264, plays everywhere).

**Graphics cards.** Conversions run on the graphics card when there is a working one: Intel and AMD
through VA-API (Intel can also use Quick Sync), NVIDIA through NVENC. At start Syphon looks for cards
and runs a short test encode on each, so it only uses an encoder that really works with the installed
driver. Decoding uses the card too where it can. A file the card can't handle is converted on the
processor by itself, and with no working card everything runs on the processor. The settings panel
shows the card in use, what it can make (H.264, AV1), and what is missing when a card was found but
can't be used (usually the driver: `intel-media-va-driver-non-free`, `mesa-va-drivers`, or NVIDIA's
own driver). The installer adds the service account to the `render` and `video` groups.

## Away from home

Tor is too slow to stream from outside, so people come in through a separate small box at home running
**syphon-vpn**, with WireGuard built into the Syphon app. Settings > Node > Outside access, owner at home:

- **Link the box:** on the box run `sudo syphon-vpn link` and paste the code. From then on the box's
  address counts as **outside**: the first sign-in on a new device needs your approval or an
  authenticator code, and the home-only settings are closed to VPN visitors.
- The panel lists the box's devices, makes a VPN code for a new device, and removes devices, which cuts
  them off at once.
- The link is sealed with a key only the box and Syphon have (XChaCha20-Poly1305), time-stamped and
  never accepted twice.
- **Tor for people from outside** is off by default. A switch turns it on for a browser like Tor
  Browser; away from home the player then starts on a smooth 480p version with a capped bit rate.

`tests/vpnbox_e2e.sh` (as root, next to the syphon-vpn source) checks the link against a real box.

## Sleep

Settings > Device > **Sleep**, owner at home. The computer suspends and wakes over the network.

- **When nobody uses it:** after a number of minutes without use (at least 5). Background polling and
  heartbeats between nodes don't count as use.
- **On a schedule:** a sleep time and optionally a wake time, set in the computer's clock (`rtcwake`).
- **Never cut off:** a video being watched, a transfer, a conversion, an upload or the periodic check
  keeps it awake. After waking it stays up at least 5 minutes.
- **Waking it:** the VPN box wakes it when a device away from home opens Syphon; the Syphon app wakes it
  at home. Both send a wake-on-LAN packet straight to the node's network card. When a router or firewall
  sits between them (separate VLANs or subnets), it needs a permanent ARP entry for the node's card and
  must let UDP 9 through from the box to the node. The Sleep panel lists what to set, with this node's
  addresses filled in.
- While it sleeps, other nodes can't sync with it.

**Rest mode** (Settings > Device > Performance) is the lighter version: on a dedicated node nobody has
used for 10 minutes, the housekeeping loops slow down while the computer stays on.

## Console

The **Console** page is for the owner.

- **Syphon commands** (from anywhere you are signed in as the owner): `status`, `users`, `devices`,
  `storage`, `peers`, `gpu`, `logs [lines]`, `update [check|now]`, `restart`, `help`.
- **The computer's terminal** (from the home network only). Off until you switch it on (Syphon password
  needed). Opening it asks for your Syphon password and an authenticator code **every time**, so
  two-step sign-in must be set up. It then shows the computer's own `login` prompt: you sign in with a
  Linux account and its password, exactly as at the computer itself. The web server, which runs as the
  unprivileged `syphon` account, only ever reaches that login prompt; a small root relay
  (`syphon shell-pty`, started by `syphon-shell.socket`) runs it. Sessions end after 30 minutes without
  use, when you sign out or leave the page. Wrong passwords or codes lock it for 15 minutes after five
  tries.

## Security

Access is split into two zones.

| | At home (LAN) | Away (VPN box, Tor, any public address) |
|---|---|---|
| Sign in on a known device | password | password |
| Sign in on a new device | password; the device becomes trusted | password **plus** an authenticator code, or approval from a signed-in device at home |
| Pairing, people, passwords, storage, security settings, the terminal | allowed | refused |

- A session only works in the zone it was created in.
- **Trusted devices** are listed per person with when each was last used. Signing in again from a
  device with the same name replaces its old entry instead of adding another, devices unused for 90
  days are forgotten, and "Remove all my other devices" clears the rest.
- Failed sign-ins lock out per zone and name, with growing delays. Unknown names and wrong passwords
  give the same answer.
- Authenticator codes are standard TOTP (RFC 6238) and each code works once.
- The mesh answers anything that is not a signed request from a connected node with a plain `404`.
- Library content: Argon2id password > random master key > XChaCha20-Poly1305 per 1 MiB chunk. Keys
  exist only in memory while unlocked.
- Web: HttpOnly SameSite=Strict cookies, a CSRF header, a strict Content-Security-Policy, no
  cross-origin loading, no referrers.

### Safety scanner

Every file is scanned over its whole length when it is uploaded, imported or arrives from another node:
hidden-program signatures, MP4 and Matroska structure checks, a blocklist (`blocklist.txt` in the data
folder), ffprobe, a sandboxed ffmpeg decode test, and ClamAV if installed. *Dangerous* findings can
never be approved; *suspicious* ones are your call. Only videos are accepted, by name and by content.
No scanner can prove a file is safe; keep your players updated.

### Metadata

- **Other nodes** get a clean title and a safe file extension, never the original file name or where a
  file came from.
- **Browsers** get titles, sizes and kinds. File names and scan reports are only shown to the owner at
  home. Error messages never contain file system paths.
- **Not encrypted:** titles and the catalog are in plain SQLite on the node. Use full-disk encryption if
  that matters.
- Tags *inside* a video file are stored as they are; only someone who can play the video sees them.
- Node clocks must agree to within 5 minutes.

## Tor

Tor carries the mesh between nodes and the poster and cast lookups. Syphon watches its own Tor and
restarts it when it stops, gets stuck connecting, or the network can no longer find the node's address
(Settings > Device > Power and privacy has a **Restart Tor** button).

**Bridges** make Tor traffic look like ordinary traffic where Tor is blocked (obfs4, webtunnel,
Snowflake, meek):

```
sudo syphon-ctl bridge add "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0"
sudo syphon-ctl bridge clear
```

Get lines from https://bridges.torproject.org. `sudo syphon-ctl torify on` sends everything the computer
does through Tor (TCP and DNS; other UDP and IPv6 are blocked rather than leaked; the home network stays
direct).

## Power cuts, restarts and shutting down

The installer asks whether the computer can lose power or crash without warning.

- **Always on:** every write is flushed to disk and the service restarts itself. After a crash the node
  removes half-written files and repairs its records; interrupted syncs resume.
- **On demand:** the node is switched off properly, and unfinished work is forgotten.

Both shut down gracefully on SIGTERM. Change the mode with `sudo syphon-ctl persistence on|off`. Use a
decent SSD or card, and a small UPS if you can.

## Performance

`sudo syphon-ctl perf dedicated|shared` (or Settings > Device > Performance). **Shared** uses small fixed
limits. **Dedicated** reads the processor, memory, disk and network speed and sizes transfers, streams
and scans to fit, re-checking every 30 seconds. An upload is refused when it would leave less than the
free-space floor (5 GB by default).

## Updates

Releases are programs you build and sign on your own computer. Nodes download them through Tor and
install only what your signature covers; nothing is compiled on a node. Before installing, the node
saves a copy of its database and keys, and goes back by itself if the new version doesn't come up.
The library stays unlocked across an update. Settings > Updates, or `sudo syphon-ctl update
check|apply|rollback`. Full steps: RELEASING.md.

## Kill node

Settings > Device > Danger zone, owner at home. Three screens of warnings, then the node name, KILL NODE
and your password. It removes the library, keys, accounts, the program, its services and the `syphon`
user. Packages from your system's package manager are left in place.

## Privacy and cookies

The page only talks to its own node: no web fonts, scripts or images from elsewhere. Two cookies, both
only after signing in, both unreadable by scripts: `syphon` (your sign-in, up to 12 hours) and
`syphon_dev` (marks a device you signed in from, up to a year). The browser's own storage holds the
light or dark choice.

## Layout

```
src/keyring.rs     password KDF, chunked encryption, encrypted secrets
src/security.rs    zones, trusted devices, approvals, lockouts, two-step sign-in
src/pair.rs        invite codes and the request/accept flow
src/catalog.rs     signed operation log and merge rules
src/mesh.rs        node-to-node protocol      src/sync.rs   the sync engine
src/library.rs     ingest, review, trash, streaming, conversion
src/gpu.rs         graphics cards for conversion
src/storage.rs     drives, NAS, placement     src/console.rs   the owner's console
src/shellpty.rs    the root relay for the computer's terminal
src/tor.rs         managed Tor and onion services
src/lifecycle.rs   crash recovery and graceful shutdown
src/api.rs         web API                    ui/   the web app
systemd/           the service, the root helper (syphon-update) and syphon-ctl
tests/             end-to-end tests with several nodes in one process
```

On-disk labels such as `hearth-master-v1` and the file magic `HRTH1` are the project's original internal
names, kept so libraries made before the rename keep opening.

## Tests

`cargo test` runs the unit and end-to-end tests: multi-node replication, the request/answer flow, caps and
the stop switch, forged and replayed mesh requests, pairing, the home/away sign-in rules, lockouts and
authenticator codes, trusted devices that sign in again, metadata leaks, scanning and conversion, drive
detection, and the graphics card arguments. `sudo tests/update_e2e.sh` runs the update flow with real
signatures.

## Known limits

- The live Tor path between nodes was verified up to the generated configuration, not across the live
  Tor network in testing. The first connection between two nodes can take a minute or two.
- Graphics card conversion was tested for the arguments it builds and the detection, not on every card
  and driver. A card that refuses a file falls back to the processor.
- The UI was checked in Chromium, not on every browser or phone.

## License

Syphon is free software under the **GNU Affero General Public License, version 3** (see `LICENSE`). You
may use, study, change and share it. If you distribute a modified version, or let other people use a
modified version over a network, you must make your changes available under the same license. There is
no warranty.
