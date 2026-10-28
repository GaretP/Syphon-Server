# Syphon

A media server for a small mesh of houses. Each house runs one node. Nodes find each other through
Tor onion services, sync the library between themselves when asked, and keep every video encrypted
on disk. Use it from any phone or laptop on your home network, or from anywhere through Tor.

```
   House A                    House B                    House C
 ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
 │ mesh.onion   │◄────────►│ mesh.onion   │◄────────►│ mesh.onion   │   nodes only, key-authorised
 │ access.onion │          │ access.onion │          │ access.onion │   you, away from home
 │ LAN :8096    │          │ LAN :8096    │          │ LAN :8096    │   phones and laptops at home
 └──────────────┘          └──────────────┘          └──────────────┘
```

Rust, SQLite, one binary, no Docker. Linux first.

## Install

On the machine that will be the node (Debian, Ubuntu or Raspberry Pi OS):

```bash
sudo ./install.sh
```

It asks three things: what to call the node, what to call **you**, and a password. Then it installs
Tor and ffmpeg, builds Syphon, and starts it as a service. At the end it prints the address to open
on your phone or laptop, for example `http://192.168.1.20:8096`.

Advanced: `--name`, `--owner`, `--data DIR`, and `--yes` (reads `SYPHON_PASSWORD` from the environment).
Manual: `cargo build --release`, then `syphon init` (it asks the same questions) and `syphon run`.
For development without Tor: `syphon init --transport direct`.

## Using it

* **At home.** Any device on your network opens the node's address and signs in. A dedicated node
  works fine: nothing needs to run on the device you watch from. Settings shows the address and a QR code.
* **Away from home.** Open the node's Tor address in Tor Browser. See [Security](#security).
* **Library, Add, Review.** New videos (downloaded, uploaded or imported) wait in the encrypted
  Review area. They are scanned, and nothing is played or shared until the owner approves them.
* **Vault.** A private shelf for each person. Vault files are never shared with other nodes, never
  listed in the library, and the Vault only opens from the home network. They are encrypted like everything else.
* **Mesh.** Connect your houses, and control what syncs (see below).
* **Dark and light.** Dark (grey-black with purple) is the default; the sun/moon button switches to cream and purple.

## Shows, seasons and episodes

Episodes of one show appear as **one poster**. Click it for a page with a season picker, an episode
list, and a Play / Continue button (it resumes where you stopped; "Next episode" crosses seasons).

* **Automatic:** the node reads the file name (`S01E02`, `1x02`, `Season 1 Episode 2`, `Episode 5`, `- 05`, release tags like 1080p/WEB-DL are ignored) and groups by show title, ignoring case, punctuation, a trailing year and a leading "The". Different spellings of one show end up together. Review groups the same way, with one **Approve N episodes** button per show (and one for files that need attention).
* **Manual, when names are too messy:** Library → **Organize**, pick the posters that belong together, **Combine into one series**: set the title, optionally force a season, and number the episodes in order. On a show page, **Rename or change type** changes every episode at once, and each episode has its own Edit (title, season, episode).
* Every change is a normal signed edit, so your other nodes see the same grouping.
* Uploading many files shows one summary with a collapsible list, two uploads at a time.
* No online metadata: titles come from file names, so a badly named file may need the manual step. Movies are never grouped. Episodes with no episode number at all stay as separate items until you combine them with "number in order".

## Connecting two nodes

Pairing is a request, like a friend request:

1. On either node: **Mesh → Create invite code**. Send the code to the other owner (a message is fine; it works once and expires after 24 hours).
2. On the other node: paste it and press **Ask to connect**.
3. The first node's owner sees *"Home wants to connect"* (with a fingerprint to check) and presses **Accept**.

Both nodes then connect by themselves. Nobody has to press anything at the same moment, and either
node can be off for a while in between: the request is stored and retried.

Over Tor the invite carries a throwaway key so the other node can knock on a mesh address that is
otherwise closed to strangers. It is revoked shortly after the answer is delivered.

## Sync

Nothing is pushed. For each connected node, in order: heartbeat out → compare what each side has →
does this node need anything? → **request** it → the holder answers **yes, no, or ask-the-owner** →
capped, verified transfer. The stop switch and all caps (upload/download speed, parallel streams, free
disk, library size, daily window, which kinds to mirror) are checked before every chunk on both
sides, so they take effect mid-transfer. The Mesh page shows each step live.

## Search and download

**Add** searches your sources. Built in: the Internet Archive, RSS feeds you configure, and "Paste a
link" for a direct link to a video file. In **Settings → Your own servers** you can add a **Plex**
or **Jellyfin** server you have access to; it appears as a source, and its token is stored
encrypted with your library key. Results never go straight into the library: they land in Review.
You are responsible for only using sources whose content you have the right to download.

**Downloads go through Tor.** On a Tor node, searches and downloads leave through Tor's SOCKS
proxy by default (`[acquire] route = "auto"`), so the sites cannot see where you are. Nothing falls
back to a direct connection: if Tor is still connecting, a download waits for it. The one
exception is your own Plex or Jellyfin on the home network (a private address): Tor cannot reach
those and nothing leaves your network, so they are reached directly. Set `route = "direct"` only
if you really want to opt out; Settings shows what is in effect.

Adding a new kind of source means implementing the `Provider` trait in `src/acquire.rs`.

## Power cuts, restarts and shutting down

The installer asks whether the computer can lose power or crash without warning.

* **Always on (yes):** every write is flushed to disk (database `synchronous=FULL`, fsync on stored videos and received chunks, keyring/identity/config written to a temp file and renamed), and the service restarts itself. After a crash or power cut the node removes half-written files, repairs its records of received chunks, and pauses unfinished downloads; they start again when the owner signs in (the library key is only available then). Interrupted syncs resume from the chunks that survived.
* **On demand (no):** the node is switched off properly. Shutting down also forgets unfinished work (queued downloads, half-received files, waiting sign-in approvals), so nothing half-finished is left behind.

Both modes shut down gracefully on SIGTERM/Ctrl-C (power button, `shutdown`, `systemctl stop`): new work stops, running chunk transfers and downloads wind down (up to about 10 s), sessions are cleared, the library key is wiped from memory, the database is folded into one file and Tor is asked to exit. Videos already in the library are kept in both modes. Change the mode later with `sudo syphon-ctl persistence on|off`.

A node cannot protect against the power failing *while it is writing to a failing or unsafe disk* (SD cards that lie about flushing, drives with a volatile write cache). Use a decent SSD or card, and a small UPS if you can.

## Where Tor is blocked, or you do not want your provider to see it

Some countries and networks block Tor, and some people simply do not want their internet provider
to see that they use it. Syphon supports **Tor bridges**, which make Tor traffic look like ordinary
traffic (obfs4, webtunnel, Snowflake, meek). The installer asks; later:

```
sudo syphon-ctl bridge add "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0"
sudo syphon-ctl bridge clear
```

Get lines from https://bridges.torproject.org (also by email to bridges@torproject.org from a
Gmail or Riseup address). Add two or three. Each line is checked before it reaches Tor's
configuration. The bridge covers everything Tor does on this node: the mesh, the access onion, and
downloads. Settings → Power and privacy shows whether bridges are on and whether the transport
program (`obfs4proxy`, `snowflake-client`) is installed. If Tor stays unconnected, Settings says
your network may block it and points here.

There is deliberately **no built-in VPN client**. A VPN needs system-level network control, and a
bridge solves the same two problems (a blocked Tor, a provider that can see Tor) more directly. If
you want a VPN as well, set it up on the computer itself (WireGuard or OpenVPN): Tor then runs
through it with no change. Your VPN provider can then see Tor use instead of your internet provider,
and bridges do not make that VPN reachable if it is blocked itself. The old generic "proxy" download
route was removed: any leftover setting for it now means Tor.

## Sending the whole computer through Tor

`sudo syphon-ctl torify on` makes a dedicated node route **everything it does** through Tor, not
just Syphon. Tor also runs a transparent proxy (TransPort and DNSPort) and an nftables firewall
table (`syphon-torify.service`, printed by `syphon torify-rules`) redirects the computer's TCP
connections and DNS to it. Rules load before the network starts and fail closed. Turn off with
`sudo syphon-ctl torify off`.

This is a *transparent Tor proxy*, not a VPN tunnel, and it is honest about what that means:
* Only the computer it runs on is covered. Phones on your network are not routed through it.
* TCP and DNS only. Other UDP (video calls, QUIC, games) and IPv6 are blocked rather than leaked. NTP (time) is the one thing let through, because Tor needs a correct clock.
* The home network (10/8, 172.16/12, 192.168/16) and loopback stay direct, so Syphon's web UI keeps working.
* The account that runs Syphon and Tor is exempt, otherwise Tor could not connect. Anything else running as that account is not protected.
* It does not stop a program from identifying you by logging in or sending identifying data. Tor Browser is still the right way to browse.
* Updating the system (apt) works but is slow, and needs an internet-facing Tor to be connected first.

Settings → Power and privacy shows the state. Not tested on a live system here: the rules were syntax-checked with `nft -c`.

## Security

Over Tor a node cannot see a visitor's IP address, so an "allowed addresses" list cannot work there.
Syphon applies the same idea to **devices** instead, and splits access into two zones.

| | At home (LAN) | Away (Tor, or any public address) |
|---|---|---|
| Sign in on a known device | password | password |
| Sign in on a new device | password; the device becomes trusted | password **plus** either a code from an authenticator app, or approval from a signed-in device at home (shown with a short code on both screens) |
| Pairing, people, passwords, sources, security settings, Vault | allowed | refused |

More details:

* A session only works in the zone it was created in. Anything arriving through a reverse proxy is treated as away.
* Failed sign-ins lock out per zone and name, with growing delays, so someone outside cannot lock the owner out at home. Unknown names and wrong passwords give the same answer.
* Authenticator codes are standard TOTP (RFC 6238; tested against its vectors) and each code works once. Approvals are single-use and expire in 10 minutes.
* Trusted devices are listed in Settings and can be removed at any time.
* An optional extra lock on the Tor address: Tor client authorization per device (Settings → Extra lock).
* The mesh answers anything that is not a signed request from a connected node with a plain `404`, so scanning it reveals nothing.
* Library content: Argon2id password → random master key → XChaCha20-Poly1305 per 1 MiB chunk. Keys exist only in memory while unlocked. Tampering and truncation are detected.
* The review scan runs `ffprobe` inside a `bubblewrap` sandbox.
* Web: HttpOnly SameSite=Strict cookies, CSRF header, strict Content-Security-Policy, no cross-origin loading, no referrers.

### Metadata

* **Other nodes** receive a clean title and a safe file extension, never the original file name (release groups, sources), never where a file came from, and never scan details.
* **Browsers** get titles, sizes and kinds. File names, sources and scan reports are only shown to the owner at home. Away from home, addresses and node ids are hidden. Error messages never contain file system paths. Before sign-in, outsiders are not even told the node's name.
* **Not covered:** tags *inside* a video file (title, encoder, creation time, GPS) are stored as they are, because removing them would mean writing the unencrypted video to disk. They are only visible to someone who can already play the video.
* **Not encrypted:** titles and the catalog are in plain SQLite on the node. Use full-disk encryption (LUKS) if that matters. The node's signing key and Tor keys sit on disk so it can start unattended: stealing the disk allows impersonating the node, not reading any video.
* Node clocks must agree to within 5 minutes.

## Layout

```
src/keyring.rs     password KDF, chunked encryption, sealed chunks, encrypted secrets
src/security.rs    zones, trusted devices, approvals, lockouts, two-step sign-in
src/totp.rs        authenticator codes
src/pair.rs        invite codes and the request/accept flow
src/catalog.rs     signed operation log, merge rules, tombstones
src/mesh.rs        node-to-node protocol
src/sync.rs        the sync engine and stop switch
src/library.rs     ingest, review, trash, Vault, streaming, transcode
src/acquire.rs     sources (Internet Archive, RSS, links, Plex, Jellyfin) and the download queue
src/tor.rs         managed tor, onion services, client authorization
src/torify.rs      firewall rules for system-wide Tor
src/lifecycle.rs   crash recovery and graceful shutdown
src/api.rs         web API       ui/   the web UI
tests/             end-to-end tests with several nodes in one process
```

On-disk labels such as `hearth-master-v1` and the file magic `HRTH1` are the project's original
internal names. They are deliberately unchanged so libraries made before the rename keep opening.

## Tests

`cargo test` runs 34 unit tests and 21 end-to-end tests (crash recovery, shutdown, Tor-by-default downloads included): three-node replication, request/answer
flow, caps and the stop switch, locked receivers, forged and replayed mesh requests, the pairing
request flow, the home/away sign-in rules, lockouts and authenticator codes, the private Vault,
metadata leaks, Plex and Jellyfin sources, real MP4 scanning and transcoding.

## Known limits

* The Tor path (two onion services per node, client authorization, the invite's throwaway key) was verified up to the generated configuration and the files Tor reads. It has **not** been exercised across the live Tor network. Expect the first connection between two nodes to take a minute or two.
* The UI was checked in Chromium, not on every browser or phone.
* No poster art or online metadata: titles come from file names and posters are generated.
* The scan reads the first 32 MiB; MP4s with the index at the end fail the probe and need *Approve anyway*.
* Low-bitrate mode seeks with jump buttons.
* The sign-in approval prompt appears in the UI at home; there is no email or push notification (the node has no mail capability).

## Downloads, Review and the Vault (round four)

- **Dropped connections.** A download that loses its connection (including "peer closed connection without sending TLS close_notify") no longer fails. It shows *Connection dropped, retrying* and resumes from the byte it reached (HTTP Range, with a safe restart if the server cannot resume). It gives up after 6 tries or a 90 second stall, with a plain-English reason and a **Retry** button.
- **Queue.** Each queued or running download has **Cancel**; failed or cancelled ones have **Retry**; finished ones have **Remove**, and **Clear finished** tidies the list. When you approve or reject a file in Review, its download row changes to *Added to the library* / *Rejected* and disappears after ten minutes.
- **Type detection.** Fansub-style names (`[Group] Show - 05 [CRC32]`, OVA/NCED/Dual Audio) are filed as anime, `SxxEyy` names as series, the rest as movies. The Add page has a type selector (Auto / Movie / TV series / Anime), and Review has **Fix title or type** per file plus **Set type for all** per show.
- **Review is isolation, not secrecy from you.** A file in Review is kept apart from the library and is never offered to other nodes until you approve it. You can **Preview** it (owner, home network only). It is still stored encrypted on disk, like everything else.
- **Vault** is private to one account, home network only, never synced, never in the catalog.

## Safety scanner (round five)

Every file is scanned over its **whole length** when it is uploaded, downloaded, imported, put in the Vault, **or arrives from another node**. A file from the mesh is assembled in the isolated area, scanned by *this* node, and only then joins your library or gets passed on; if it fails it is "blocked" (kept encrypted, never served, never streamed) and shows in Review. That is what stops one infected node from infecting the others.

Layers: hidden-program signatures (Windows, Linux, macOS, Java, shortcuts, scripts, archives, EICAR) anywhere in the file; MP4 and Matroska structure checks (no hidden data after the video, no program attachments, no disguised ZIP); a blocklist (`blocklist.txt` in the data folder, one SHA-256 or content id per line); ffprobe; a sandboxed ffmpeg decode test (a decoder that crashes is treated as an exploit attempt); and ClamAV (`clamdscan` or `clamscan`) if installed (the installer tries to add it). *Dangerous* findings can never be approved; *suspicious* ones are your call. Settings → Safety scan re-scans the whole library (do this after updates or new virus signatures). Honest limit: no scanner can prove a file is safe. This catches known malware, disguised programs and malformed files; keep your players updated. The decode test covers the first 512 MiB of each file (`scan.decode_max_mib`).

## Details, posters and genres

Descriptions, genres, cast and posters are looked up **through Tor** (title and year only): TVmaze for series, MyAnimeList (Jikan) for anime, Wikidata for movies, or TMDB for movies if you put a free key in `metadata.tmdb_key`. Posters are stored encrypted. The Library shows scrolling rows (Recently added, one per genre, then anything left by type). You can type genres by hand (Edit, Rename, or Review → Fix title, type or genres); those win over looked-up ones.

## Profile pictures

Each person (including newly created ones) can set or remove their own picture under Settings → Your profile. It appears beside their name.

## Updates

Releases are **programs you build and sign on your own computer**. Nodes download them through Tor and install only what your signature covers. Nothing is compiled on a node and nothing from the download runs as root. Full steps: RELEASING.md.

- **Trust.** `release/release.sh` builds with the exact dependencies in `Cargo.lock` (`--locked`; `Cargo.toml` pins every dependency to an exact version and `rust-toolchain.toml` pins the compiler), packs the program with its two helper scripts, writes a manifest (version, SHA-256 hashes, sizes, the hash of `Cargo.lock`) and signs it with your private SSH key. A node installs only if the signature verifies against `/etc/syphon/allowed_signers`, the archive matches the signed hash and size, it holds exactly the three expected files, the new program reports the signed version when run as the node's own unprivileged account, and the version is newer than the one running. Downgrades are refused.
- **Safe to try.** Before installing, the node saves a consistent copy of its database and keys (`update/snapshots/`, the three newest are kept). If the new version does not come up, the old program goes back; if that is not enough (the new version changed the database), the saved copy goes back too. "Go back a version" works the same way.
- **The library stays unlocked.** The key lives only in memory, so a restart used to lock the library. Now, just before restarting, the update helper arms a hand-over: the stopping node leaves its key in a memory-only folder (`/run/syphon-handoff`, private to the node's account) and the next start takes it, unlocks and deletes it. A reboot or power cut still needs the password, because that folder is gone. (The first update after installing this version cannot do it, because the old program that is stopped does not know the hand-over yet.)
- **First time.** Install from your repository with `install.sh` (it installs `release/allowed_signers` and the update address from `release/update.default`). After that: Settings, Updates, Check, Install, or `sudo syphon-ctl update check|apply|rollback`.
- **Limits.** If your signing key leaks, whoever has it can ship code to every node: keep it offline with a passphrase. There is no remote revocation; to change the key, run `sudo syphon-ctl update-source set <address> --signers <file>` on each node. Intermediate versions can be forced with a `requires vX.Y.Z` line in the manifest (`release.sh --requires`).

## Videos only, uploads that resume, scanning that keeps going (round eight)

- **Only videos.** Syphon is not a file server. Every way in (browser upload, Vault upload, downloads, sync) refuses anything that is not a video, by name and by what is inside the file. Something that merely wears a video name but is not a video is thrown away.
- **Uploads resume.** The browser sends large files in 8 MB pieces. If the connection drops, or the node restarts, it asks where the node got to and carries on from there by itself.
- **Scanning is a background job.** An upload, download or sync only hands the file to the scanner and returns. One worker scans the waiting files one at a time, retries a failed attempt by itself, and picks up again after a restart or unlock. Looking up titles and posters waits while uploads, downloads or scans are busy, so it never holds them up.
- **Finding titles.** Names like `[AnimePahe] Trinity Seven - 01 [BD 1080p Eng Dub].mkv` are cleaned (site tags, quality, dub and release words), several spellings of the title are tried against TVmaze, Jikan, AniList and TMDB or Wikidata through Tor, and the closest match above a similarity threshold wins. A title that is an anime is shown as anime wherever it was filed, even a single-episode film in the movie slot. Anything that cannot be matched can still be fixed by hand in the title's "⋯" menu.
- **Kill node** (Settings, Danger zone, owner at home only). Three screens of warnings, then you type the node name and KILL NODE and enter your password. It removes the library, Vault, keys, accounts, the program, its service, updater and Tor rules, and the `syphon` user. Packages from your system's package manager (Tor, ffmpeg, ClamAV, bubblewrap) are left in place. Without the installer's helper it wipes the data folder and exits.
- **Look.** A matte, pastel palette with soft shadows instead of borders, dark and light.

## Performance: shared or dedicated (round nine)

Syphon asks at install whether the computer is used only for Syphon. You can change the answer any time in Settings, Performance, or with `sudo syphon-ctl perf dedicated|shared`. `syphon perf` shows what this computer has and what each mode would pick.

- **Shared** (the default): small, fixed limits, as before: 3 parallel transfers, 2 downloads, 2 low-bitrate streams, one scan at a time at low priority.
- **Dedicated**: the node reads the processor cores, memory (also a container's memory limit), free disk, load and network speed, and sizes everything to fit: parallel transfers (about one per 25 Mb/s, at most two per core), downloads, low-bitrate streams, how many files are scanned at once, how big the antivirus window and the decoded part are, and how many files a browser uploads at once.
- **It keeps looking.** Every 30 seconds the limits are worked out again, so a faster internet plan, more RAM or a different processor is picked up without a restart. The network speed is the card's own rating when the computer reports one, otherwise the fastest speed seen in the last day. A busy machine (high load) makes scans run one at a time at lower priority until it calms down.
- **Disk is guarded in both modes.** An upload or download is refused when it would leave less than the free-space floor (default 5 GB, the same number the sync policy uses). Over the limit, a low-bitrate stream gets a plain "busy" answer instead of slowing everyone down.
- The speed caps and the sync window on the Mesh page still apply in both modes.

Seasons in a title ("Youjo Senki S2", "Season 3", "2nd Season") are treated as seasons of one show. Movies are looked up in TMDB (with a key), Wikidata, Apple's catalogue, IMDb and Wikipedia, each filling in what the one before lacked.

## Round eleven: storage, formats, settings

**Storage (Settings > Storage).** Videos can live on several drives and on a NAS. Every drive keeps its own encrypted
`library`, `quarantine`, `inbox` and `vault` folders; a file is finished on the drive it started on. New videos go to
the drive with the most room above its reserve (or fill drives in order). Each drive keeps free space back (by default
the larger of 5 GB or 2% of the drive, 8 GB or 3% on the system drive; change it per drive). Two modes: *use all drives*
(a dedicated node: every internal, non-removable drive is used, including ones added later) or *only the drives I choose*.
A drive can be switched off for new files, emptied onto the others ("Move files off"), or removed.
Link a NAS (SMB or NFS, or one you mounted yourself): the installer's helper mounts it with a systemd mount unit under
`/mnt/syphon/<name>`; the SMB password is kept in a root-only file. For each drive or share you can list **folders to pull
videos from** (the dir layout, e.g. `Shows/Name/Season 2/03.mkv`); they are copied in, scanned and put in Review, and the
originals are left alone. CLI: `syphon drives`, `syphon set storage all|selected`, `syphon set storage-add PATH`,
`sudo syphon-ctl storage allow PATH`. The installer asks which drives to use when it finds more than one.
For drives outside /mnt, /media and /srv the helper adds the path to the service's allowed folders and restarts it.

**Formats.** The node looks inside each video. Files a browser can play are sent as they are; MKV and others with a
browser-friendly picture are re-wrapped without re-encoding; HEVC, 10-bit and old codecs are converted. Settings > Node >
Playback sets the conversion quality (480p to 1440p, or same size); the player can pick another per video and has a seek bar.

**Settings** are now tabs: Account, Node (software), Device (hardware, power, kill node) and Storage. The trash section is
gone from Settings. The extra lock on the outside address lists its keys, lets you remove one or turn the lock off
(`syphon device all --remove` on the node).

**Shows.** Episodes show a preview picture and "Episode 3: Title". A season released under its own name (Highschool DxD Hero)
joins the show when AniList lists it as a sequel; spin-offs and alternate versions (Beyblade: Metal Fusion) stay separate.

## Round twelve

- **Rest mode** (Settings > Device > Performance). On a dedicated node that nobody has used for 10 minutes (changeable), the housekeeping loops (folder watchers, detail lookups, hardware sampling, drive checks, scan polling) stretch their waits to minutes. Tor, the web address and the mesh server never stop. The first real request (a page load, a click, a video, work asked by another node; not background polling or heartbeats) wakes everything at once. Nothing rests while downloads, uploads, scans, transfers or conversions are running. Modes: automatic (dedicated only), always allow, never. A true OS suspend is deliberately not used: a sleeping computer cannot answer an incoming Tor connection, so nothing could wake it.
- **AV1 conversion.** Conversions now produce AV1 (SVT-AV1, falling back to libaom or rav1e) when the node's ffmpeg has an encoder and the browser can show AV1; otherwise H.264. Before this round conversions were H.264 only. Settings > Node > Playback and conversion chooses AV1 or H.264 for the whole node.
- The next-episode button sits under the video; Settings panels are wider and more spaced.

### Round twelve, part two: settings layout

- Settings panels flow into two balanced columns.
- Deep sleep (suspending the whole computer) was tried and removed: it could not be made to wake reliably on every network. Rest mode (software housekeeping pauses) is what remains, and the computer stays on.

## Tor keeps itself connected

Syphon watches its own Tor. If Tor stops, gets stuck connecting for ten minutes, or the Tor network can no longer find this node's address (three checks in a row, a few minutes apart), Syphon restarts Tor by itself. The address never changes: it comes from keys that stay on the node, and Tor lists it again as soon as it reconnects. Settings > Device > Power and privacy shows whether the address can be found, how many times Tor was restarted and why, and has a **Restart Tor** button. The address check needs Tor 0.4.3 or newer; with an older Tor, only the first two protections apply.

## Sleep (the computer suspends, and wakes over the network)

Settings > Device > **Sleep**, owner at home. The computer itself suspends: a few watts, back in seconds.

- **When nobody uses it:** after a number of minutes without use (at least 5). Use is the same as for rest mode: pages, videos, clicks, work another node asks for. Background polling and heartbeats don't count.
- **On a schedule:** a sleep time, and optionally a wake time. At the sleep time it sleeps once nothing is running; woken in the night, it sleeps again after 5 quiet minutes. The wake time is set in the computer's clock (`rtcwake`), so it wakes on its own, for example for the morning sync with the other houses.
- **Never cut off:** a video being watched, a download, a transfer, a conversion, an upload, or the periodic check keeps it awake. After waking it always stays up at least 5 minutes.
- **Waking it:**
  - the **VPN box** wakes it when a device away from home opens a connection to Syphon. An app sitting idle on the VPN doesn't, so the node still gets to sleep;
  - the **Syphon app** wakes it at home before connecting;
  - a browser doesn't.
  Both send a wake-on-LAN packet straight to the node's network card. Wake packets don't cross VLANs by themselves, so the SRX300 needs a permanent ("static ARP") entry for the node's card, plus policies for UDP 9. The Sleep panel shows the lines with this node's address filled in.
- **How:** the node asks its system helper to suspend (`syphon-update`, action `suspend`). The helper makes sure the card listens for wake packets (`ethtool -s <card> wol g`, installed by the installer) and sets the clock's wake time. If the computer doesn't actually suspend, the panel says so and the node stops asking for half an hour.
- While it sleeps, the other houses can't sync with it, and Tor reconnects after it wakes.

## Rest mode and the periodic check

Settings > Rest mode shows what is holding the node awake right now and what the last real activity was. Routine traffic between nodes (heartbeats, catalog pulls, requests waiting for approval) never counts as use; a video being fetched, a page being used, a download, a live upload or a running scan does. A locked library does not hold the node awake for scans it cannot run, and an upload nobody touched for five minutes is treated as abandoned.

The periodic check runs every 6 hours. It checks the database, keeps stored file names equal to the title shown, retries titles whose details were not found, reports videos whose stored file is missing (it never deletes anything), clears forgotten uploads and empties the trash past its retention. "Check now" runs it on demand.

## The Syphon app and the TV view

The **Syphon app** (separate project, `syphon-app`, Windows and Linux) opens straight into your library without an address or a browser: at home over your own network, away from home through its own Tor. It has "Who's watching?" profiles and a **TV mode** for a computer plugged into a TV. The node helps it in three small ways:

- **It can be found on the home network.** The app sends a broadcast on UDP port 8095 and the node answers with its name and web port. Only home-network addresses get an answer, and nothing secret is in it. A broadcast does not cross into another VLAN; the app then lets you type the address. Allow UDP 8095 on the node if a firewall runs on it.
- **Remembered sign-in.** A trusted device can be told to remember someone (the app's "Remember me on this computer"): that person then signs in on that device without the password. Settings > Account > Trusted devices shows which devices remember you, and removing a device there ends it at once. After a restart the owner still signs in with the password first, because that unlocks the library.
- **VPN codes.** Under Settings > Account > Open Syphon on your other devices, the owner (at home) makes a VPN code for a person's Syphon app, from the linked VPN box (the same as Settings > Node > Outside access). The older Tor connection codes are gone: the app no longer uses Tor.
- **The TV view** (`#/tv`, also in the avatar menu as "TV view"): the library as big rows of posters, a show page with seasons and episodes, and a full-screen player, all usable with arrows, OK and Back (keyboard, TV remote, air mouse, game controller or media keys). Hold Back for the menu. Away from home it starts on the smooth 480p version. It also works in a smart TV's own browser.

## Watching away from home: the VPN box

Tor is too slow to stream from outside, so people come in through a separate small box at home running **syphon-vpn** (its own project), with WireGuard built into the Syphon app. The Syphon app no longer uses Tor. Settings > Node > **Outside access**, owner at home:

- **Link the box:** on the box run `sudo syphon-vpn link` and paste the code. Syphon checks the link works before keeping it. From then on:
  - the box's address counts as **outside**: the first sign-in on a new device needs your approval or an authenticator code, and the home-only settings are closed to VPN visitors;
  - the panel lists the box's devices (connected now / ready / code not used yet / code expired, and when each last connected), makes a VPN code for a new device, and removes devices, which cuts them off at once;
  - it warns when nothing from the internet has reached the box, which points at the port forward.
- **The link** is sealed with a key only the box and Syphon have (XChaCha20-Poly1305), time-stamped, never accepted twice, and the box only listens to this node's address. `sudo syphon-vpn link --new` on the box cuts off an old link.
- **VPN box addresses:** linking fills this in. More boxes can be added by hand. The node refuses public addresses, and refuses the device you are using, so you can't lock yourself out.
- **Tor for people from outside** is **off** by default now. The switch turns it back on for a browser like Tor Browser. The mesh between houses and grabbing keep using Tor either way.

Run `tests/vpnbox_e2e.sh` as root, next to the syphon-vpn source, to check the link against a real box: wrong key refused, add, list, remove, and no answer to anyone else.

## Watching away from home over Tor (when Tor access is switched on)

Tor carries much less than a home connection, so a video at its full quality stalls. Three things help: away from home the player starts on the smooth Low (480p) version (the Quality picker next to the video lets you ask for more); every converted stream has a bit-rate cap, so it cannot spike above what the link carries; and a converted stream starts a new picture every 2 seconds, so playback begins after the first couple of seconds instead of the first ten. Seeking in a converted stream starts a new conversion at that point. Files whose index sits at the end (some MP4s) need an extra round trip to start; no setting here changes that.

## Look

Matte throughout: solid colours and plain 1px edges, no glow, blur, see-through panels or gradient sheen. The focused item on the TV view gets a solid white frame.

## Privacy and cookies

The site only talks to its own node: no web fonts, scripts or images from elsewhere, and the page's security policy forbids it (a test checks both). Two cookies exist, both only after signing in, both unreadable by the page's scripts: `syphon` (your sign-in, up to 12 hours) and `syphon_dev` (marks this browser as a device you signed in from, up to a year, removable under Settings > Account > Trusted devices). A visitor who does not sign in gets no cookie. The browser's own storage holds one entry, the light or dark choice. Settings > Account > Privacy and cookies says the same in the app.

Deleted videos wait in Settings > Storage > Trash and can be restored; sending a video that is in the trash again brings it back.

## License

Syphon is free software under the **GNU Affero General Public License, version 3** (see `LICENSE`). You may use, study, change and share it. If you distribute a modified version, or let other people use a modified version over a network, you must make your changes available under the same license. There is no warranty.
