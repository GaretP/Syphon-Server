//! Encryption at rest.
//!
//! NOTE: labels such as "hearth-master-v1" and the file magic are the project's original internal
//! identifiers. They are part of the on-disk format and are deliberately NOT renamed, so libraries
//! created before the rename to Syphon keep opening.
//!
//! * A random master key is wrapped by a key derived from the owner's password (Argon2id).
//! * Library files are encrypted in 1 MiB chunks with XChaCha20-Poly1305. Every chunk binds
//!   its index and a "final" flag in the AAD, so reordering and truncation are detected, and
//!   any byte range can be decrypted without touching the rest of the file.
//! * "Sealed chunks" are encrypted to the keyring's public key. A node that is locked can keep
//!   receiving synced data this way; only reading it back needs the password.

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
const MAGIC: &[u8; 6] = b"HRTH1\0";
const HDR: usize = 22; // magic + 16-byte nonce prefix

#[derive(Serialize, Deserialize, Clone)]
struct KeyringFile {
    salt: String,
    m_kib: u32,
    t: u32,
    p: u32,
    wrapped_master: String,
    sealed_pub: String,
    wrapped_sealed_secret: String,
}

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams { m_kib: 65536, t: 3, p: 1 }
    }
}

pub struct Keys {
    master: Zeroizing<[u8; 32]>,
    content: Zeroizing<[u8; 32]>,
    sealed_secret: StaticSecret,
}

impl Keys {
    pub fn content_key(&self) -> [u8; 32] {
        *self.content
    }
    pub fn sealed_secret(&self) -> &StaticSecret {
        &self.sealed_secret
    }
}

pub struct Keyring {
    path: PathBuf,
    file: RwLock<KeyringFile>,
    keys: RwLock<Option<Arc<Keys>>>,
}

fn kdf(password: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|e| anyhow!("kdf params: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(password.as_bytes(), salt, &mut *out)
        .map_err(|e| anyhow!("kdf: {e}"))?;
    Ok(out)
}

fn wrap(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Result<String> {
    use base64::Engine;
    let c = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = c
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad })
        .map_err(|_| anyhow!("wrap failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

fn unwrap(key: &[u8; 32], aad: &[u8], b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64)?;
    if raw.len() < 24 + TAG {
        bail!("wrapped blob too short");
    }
    let c = XChaCha20Poly1305::new(key.into());
    c.decrypt(XNonce::from_slice(&raw[..24]), Payload { msg: &raw[24..], aad })
        .map_err(|_| anyhow!("wrong password or corrupted keyring"))
}

impl Keyring {
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn create(path: &Path, password: &str, params: KdfParams) -> Result<Keyring> {
        if path.exists() {
            bail!("keyring already exists at {}", path.display());
        }
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut master = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *master);
        let kek = kdf(password, &salt, params.m_kib, params.t, params.p)?;
        let sealed_secret = StaticSecret::random_from_rng(OsRng);
        let sealed_pub = PublicKey::from(&sealed_secret);
        let file = KeyringFile {
            salt: hex::encode(salt),
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
            wrapped_master: wrap(&kek, b"hearth-master-v1", &*master)?,
            sealed_pub: hex::encode(sealed_pub.as_bytes()),
            wrapped_sealed_secret: wrap(&master, b"hearth-sealed-v1", &sealed_secret.to_bytes())?,
        };
        crate::util::write_atomic(path, &serde_json::to_vec_pretty(&file)?)?;
        restrict(path);
        Ok(Keyring { path: path.to_path_buf(), file: RwLock::new(file), keys: RwLock::new(None) })
    }

    pub fn open(path: &Path) -> Result<Keyring> {
        let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let file: KeyringFile = serde_json::from_slice(&raw)?;
        Ok(Keyring { path: path.to_path_buf(), file: RwLock::new(file), keys: RwLock::new(None) })
    }

    pub fn is_unlocked(&self) -> bool {
        self.keys.read().unwrap().is_some()
    }

    pub fn keys(&self) -> Option<Arc<Keys>> {
        self.keys.read().unwrap().clone()
    }

    /// Public half of the sealed-inbox key. Available while locked.
    pub fn sealed_pub(&self) -> [u8; 32] {
        let hexs = self.file.read().unwrap().sealed_pub.clone();
        let mut out = [0u8; 32];
        if let Ok(b) = hex::decode(hexs) {
            if b.len() == 32 {
                out.copy_from_slice(&b);
            }
        }
        out
    }

    pub fn unlock(&self, password: &str) -> Result<()> {
        let f = self.file.read().unwrap().clone();
        let salt = hex::decode(&f.salt)?;
        let kek = kdf(password, &salt, f.m_kib, f.t, f.p)?;
        let m = unwrap(&kek, b"hearth-master-v1", &f.wrapped_master)?;
        if m.len() != 32 {
            bail!("bad master key length");
        }
        let mut master = Zeroizing::new([0u8; 32]);
        master.copy_from_slice(&m);
        let s = unwrap(&master, b"hearth-sealed-v1", &f.wrapped_sealed_secret)?;
        let mut sb = [0u8; 32];
        if s.len() != 32 {
            bail!("bad sealed key length");
        }
        sb.copy_from_slice(&s);
        let content = Zeroizing::new(blake3::derive_key("hearth content key v1", &*master));
        let keys = Keys { master, content, sealed_secret: StaticSecret::from(sb) };
        *self.keys.write().unwrap() = Some(Arc::new(keys));
        Ok(())
    }

    /// The master key, for the short hand-over across an update restart (see handoff.rs). None while locked.
    pub fn export_master(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.keys.read().unwrap().as_ref().map(|k| Zeroizing::new(*k.master))
    }

    /// Unlock with the master key itself. It is checked against the sealed key, so a wrong key is refused.
    pub fn unlock_with_master(&self, master_bytes: &[u8; 32]) -> Result<()> {
        let f = self.file.read().unwrap().clone();
        let mut master = Zeroizing::new([0u8; 32]);
        master.copy_from_slice(master_bytes);
        let s = unwrap(&master, b"hearth-sealed-v1", &f.wrapped_sealed_secret)?;
        if s.len() != 32 {
            bail!("bad sealed key length");
        }
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&s);
        let content = Zeroizing::new(blake3::derive_key("hearth content key v1", &*master));
        let keys = Keys { master, content, sealed_secret: StaticSecret::from(sb) };
        *self.keys.write().unwrap() = Some(Arc::new(keys));
        Ok(())
    }

    pub fn lock(&self) {
        *self.keys.write().unwrap() = None;
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let f = self.file.read().unwrap().clone();
        let Ok(salt) = hex::decode(&f.salt) else { return false };
        let Ok(kek) = kdf(password, &salt, f.m_kib, f.t, f.p) else { return false };
        unwrap(&kek, b"hearth-master-v1", &f.wrapped_master).is_ok()
    }

    pub fn change_password(&self, old: &str, new: &str) -> Result<()> {
        let keys = self.keys().ok_or_else(|| anyhow!("the library is locked: sign in as the owner to unlock it"))?;
        if !self.verify_password(old) {
            bail!("current password is wrong");
        }
        let mut f = self.file.read().unwrap().clone();
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let kek = kdf(new, &salt, f.m_kib, f.t, f.p)?;
        f.salt = hex::encode(salt);
        f.wrapped_master = wrap(&kek, b"hearth-master-v1", &*keys.master)?;
        crate::util::write_atomic(&self.path, &serde_json::to_vec_pretty(&f)?)?;
        *self.file.write().unwrap() = f;
        Ok(())
    }
}

fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let _ = path;
}

// ---------------------------------------------------------------- chunked files

fn chunk_nonce(prefix: &[u8; 16], idx: u64) -> XNonce {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&idx.to_be_bytes());
    *XNonce::from_slice(&n)
}

fn chunk_aad(idx: u64, fin: bool) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[..8].copy_from_slice(&idx.to_be_bytes());
    a[8] = fin as u8;
    a
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub size: u64,
    /// hex BLAKE3 of every 1 MiB plaintext chunk
    pub chunk_hashes: Vec<String>,
}

impl Manifest {
    /// Content id: binds the full chunk-hash list and the size.
    pub fn id(&self) -> String {
        manifest_id(self.size, &self.chunk_hashes)
    }
}

pub fn manifest_id(size: u64, hashes: &[String]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"hearth-item-v1");
    h.update(&size.to_le_bytes());
    for c in hashes {
        h.update(c.as_bytes());
    }
    h.finalize().to_hex().to_string()
}

pub struct EncWriter<W: Write> {
    w: W,
    cipher: XChaCha20Poly1305,
    prefix: [u8; 16],
    idx: u64,
    buf: Vec<u8>,
    hashes: Vec<String>,
    total: u64,
}

impl<W: Write> EncWriter<W> {
    pub fn new(mut w: W, content_key: &[u8; 32]) -> Result<Self> {
        let mut prefix = [0u8; 16];
        OsRng.fill_bytes(&mut prefix);
        w.write_all(MAGIC)?;
        w.write_all(&prefix)?;
        Ok(EncWriter {
            w,
            cipher: XChaCha20Poly1305::new(content_key.into()),
            prefix,
            idx: 0,
            buf: Vec::with_capacity(CHUNK + 4096),
            hashes: vec![],
            total: 0,
        })
    }

    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(data);
        // Keep at least one byte buffered so the last chunk can be flagged final.
        while self.buf.len() > CHUNK {
            let chunk: Vec<u8> = self.buf.drain(..CHUNK).collect();
            self.emit(&chunk, false)?;
        }
        Ok(())
    }

    fn emit(&mut self, pt: &[u8], fin: bool) -> Result<()> {
        self.hashes.push(blake3::hash(pt).to_hex().to_string());
        let ct = self
            .cipher
            .encrypt(
                &chunk_nonce(&self.prefix, self.idx),
                Payload { msg: pt, aad: &chunk_aad(self.idx, fin) },
            )
            .map_err(|_| anyhow!("encrypt failed"))?;
        self.w.write_all(&ct)?;
        self.idx += 1;
        self.total += pt.len() as u64;
        Ok(())
    }

    pub fn bytes_so_far(&self) -> u64 {
        self.total + self.buf.len() as u64
    }

    pub fn finish(mut self) -> Result<(W, Manifest)> {
        let last = std::mem::take(&mut self.buf);
        self.emit(&last, true)?;
        self.w.flush()?;
        Ok((self.w, Manifest { size: self.total, chunk_hashes: self.hashes }))
    }
}

pub struct EncReader {
    f: File,
    cipher: XChaCha20Poly1305,
    prefix: [u8; 16],
    pub len: u64,
    pub nchunks: u64,
    file_len: u64,
}

impl EncReader {
    pub fn open(path: &Path, content_key: &[u8; 32]) -> Result<Self> {
        let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let file_len = f.metadata()?.len();
        if file_len < (HDR + TAG) as u64 {
            bail!("encrypted file too short");
        }
        let mut hdr = [0u8; HDR];
        f.read_exact(&mut hdr)?;
        if &hdr[..6] != MAGIC {
            bail!("not a syphon file");
        }
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&hdr[6..]);
        let body = file_len - HDR as u64;
        let full = body / (CHUNK + TAG) as u64;
        let rem = body % (CHUNK + TAG) as u64;
        let (nchunks, len) = if rem == 0 {
            if full == 0 {
                bail!("corrupt file");
            }
            (full, full * CHUNK as u64)
        } else if rem >= TAG as u64 {
            (full + 1, full * CHUNK as u64 + rem - TAG as u64)
        } else {
            bail!("corrupt file (partial tag)");
        };
        Ok(EncReader { f, cipher: XChaCha20Poly1305::new(content_key.into()), prefix, len, nchunks, file_len })
    }

    pub fn read_chunk(&mut self, idx: u64) -> Result<Vec<u8>> {
        if idx >= self.nchunks {
            bail!("chunk {idx} out of range");
        }
        let off = HDR as u64 + idx * (CHUNK + TAG) as u64;
        let fin = idx == self.nchunks - 1;
        let ct_len = if fin { self.file_len - off } else { (CHUNK + TAG) as u64 };
        let mut ct = vec![0u8; ct_len as usize];
        self.f.seek(SeekFrom::Start(off))?;
        self.f.read_exact(&mut ct)?;
        self.cipher
            .decrypt(&chunk_nonce(&self.prefix, idx), Payload { msg: &ct, aad: &chunk_aad(idx, fin) })
            .map_err(|_| anyhow!("chunk {idx} failed authentication (tampered, truncated or wrong key)"))
    }

    /// Plaintext bytes [start, end_excl).
    pub fn read_range(&mut self, start: u64, end_excl: u64) -> Result<Vec<u8>> {
        let end = end_excl.min(self.len);
        if start >= end {
            return Ok(vec![]);
        }
        let mut out = Vec::with_capacity((end - start) as usize);
        let first = start / CHUNK as u64;
        let last = (end - 1) / CHUNK as u64;
        for idx in first..=last {
            let pt = self.read_chunk(idx)?;
            let c0 = idx * CHUNK as u64;
            let s = start.saturating_sub(c0) as usize;
            let e = ((end - c0) as usize).min(pt.len());
            out.extend_from_slice(&pt[s..e]);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- sealed chunks

fn sealed_key(shared: &[u8], eph_pub: &[u8], recipient: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(shared);
    m.extend_from_slice(eph_pub);
    m.extend_from_slice(recipient);
    blake3::derive_key("hearth sealed chunk v1", &m)
}

/// Encrypt `plaintext` so that only the holder of the keyring's sealed secret can open it.
pub fn seal(recipient_pub: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_pub));
    let key = sealed_key(shared.as_bytes(), eph_pub.as_bytes(), recipient_pub);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: b"hearth-sealed" })
        .map_err(|_| anyhow!("seal failed"))?;
    let mut out = Vec::with_capacity(56 + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unseal(secret: &StaticSecret, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 32 + 24 + TAG {
        bail!("sealed blob too short");
    }
    let mut ep = [0u8; 32];
    ep.copy_from_slice(&blob[..32]);
    let recipient = PublicKey::from(secret);
    let shared = secret.diffie_hellman(&PublicKey::from(ep));
    let key = sealed_key(shared.as_bytes(), &ep, recipient.as_bytes());
    XChaCha20Poly1305::new((&key).into())
        .decrypt(XNonce::from_slice(&blob[32..56]), Payload { msg: &blob[56..], aad: b"hearth-sealed" })
        .map_err(|_| anyhow!("sealed chunk failed authentication"))
}

/// Small secrets (for example a Plex token) are stored encrypted with the library key.
pub fn encrypt_blob(content_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(content_key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: b"revid-secret-v1" })
        .map_err(|_| anyhow!("encrypt failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_blob(content_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 + TAG {
        bail!("secret blob too short");
    }
    XChaCha20Poly1305::new(content_key.into())
        .decrypt(XNonce::from_slice(&blob[..24]), Payload { msg: &blob[24..], aad: b"revid-secret-v1" })
        .map_err(|_| anyhow!("secret failed authentication"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn secret_blobs_roundtrip_and_reject_tampering() {
        let k = [7u8; 32];
        let b = encrypt_blob(&k, b"plex-token").unwrap();
        assert_eq!(decrypt_blob(&k, &b).unwrap(), b"plex-token");
        let mut bad = b.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(decrypt_blob(&k, &bad).is_err());
        assert!(decrypt_blob(&[8u8; 32], &b).is_err());
    }

    fn fast() -> KdfParams {
        KdfParams { m_kib: 64, t: 1, p: 1 }
    }

    fn data(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        OsRng.fill_bytes(&mut v);
        v
    }

    fn encrypt(key: &[u8; 32], pt: &[u8]) -> (Vec<u8>, Manifest) {
        let mut w = EncWriter::new(Vec::new(), key).unwrap();
        for piece in pt.chunks(100_000) {
            w.push(piece).unwrap();
        }
        w.finish().unwrap()
    }

    fn open_bytes(key: &[u8; 32], ct: &[u8]) -> EncReader {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.enc");
        std::fs::write(&p, ct).unwrap();
        let r = EncReader::open(&p, key).unwrap();
        // keep the temp dir alive for the open handle's lifetime on unix by leaking it
        std::mem::forget(dir);
        r
    }

    #[test]
    fn roundtrip_and_ranges() {
        let key = [7u8; 32];
        for n in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 12345] {
            let pt = data(n);
            let (ct, m) = encrypt(&key, &pt);
            assert_eq!(m.size as usize, n);
            let mut r = open_bytes(&key, &ct);
            assert_eq!(r.len as usize, n, "len for n={n}");
            assert_eq!(r.read_range(0, n as u64).unwrap(), pt);
            if n > 10 {
                let a = (n / 3) as u64;
                let b = (n * 2 / 3) as u64;
                assert_eq!(r.read_range(a, b).unwrap(), pt[a as usize..b as usize]);
            }
            let _ = Cursor::new(ct);
        }
    }

    #[test]
    fn detects_tamper_and_truncation() {
        let key = [9u8; 32];
        let pt = data(2 * CHUNK + 500);
        let (ct, _) = encrypt(&key, &pt);

        let mut bad = ct.clone();
        bad[HDR + 100] ^= 1;
        let mut r = open_bytes(&key, &bad);
        assert!(r.read_chunk(0).is_err());

        // drop the final chunk entirely: the new last chunk is not flagged final
        let cut = HDR + 2 * (CHUNK + TAG);
        let mut r = open_bytes(&key, &ct[..cut]);
        assert!(r.read_chunk(1).is_err(), "truncation must be detected");

        let mut r = open_bytes(&[1u8; 32], &ct);
        assert!(r.read_chunk(0).is_err(), "wrong key must fail");
    }

    #[test]
    fn manifest_hashes_match_chunks() {
        let key = [3u8; 32];
        let pt = data(CHUNK + 10);
        let (_, m) = encrypt(&key, &pt);
        assert_eq!(m.chunk_hashes.len(), 2);
        assert_eq!(m.chunk_hashes[0], blake3::hash(&pt[..CHUNK]).to_hex().to_string());
        assert_eq!(m.id(), manifest_id(m.size, &m.chunk_hashes));
    }

    #[test]
    fn password_unlock_lock_change() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("keyring.json");
        let v = Keyring::create(&p, "correct horse", fast()).unwrap();
        assert!(!v.is_unlocked());
        assert!(v.unlock("wrong").is_err());
        v.unlock("correct horse").unwrap();
        assert!(v.is_unlocked());
        let k1 = v.keys().unwrap().content_key();
        v.lock();
        assert!(!v.is_unlocked());

        let v2 = Keyring::open(&p).unwrap();
        v2.unlock("correct horse").unwrap();
        assert_eq!(v2.keys().unwrap().content_key(), k1);
        v2.change_password("correct horse", "battery staple").unwrap();
        v2.lock();
        assert!(v2.unlock("correct horse").is_err());
        v2.unlock("battery staple").unwrap();
        assert_eq!(v2.keys().unwrap().content_key(), k1, "master key survives a password change");
    }

    #[test]
    fn sealed_chunks_open_only_with_vault_secret() {
        let dir = tempfile::tempdir().unwrap();
        let v = Keyring::create(&dir.path().join("v.json"), "pw", fast()).unwrap();
        let pubk = v.sealed_pub(); // readable while locked
        let blob = seal(&pubk, b"hello sealed world").unwrap();
        assert!(v.keys().is_none());
        v.unlock("pw").unwrap();
        let keys = v.keys().unwrap();
        assert_eq!(unseal(keys.sealed_secret(), &blob).unwrap(), b"hello sealed world");
        let other = StaticSecret::random_from_rng(OsRng);
        assert!(unseal(&other, &blob).is_err());
    }
}
