//! RFC 6238 time-based one-time passwords (SHA-1, 6 digits, 30 s): the format every authenticator
//! app understands. Used as a second factor for sign-ins that arrive from outside the home network.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

pub const PERIOD: u64 = 30;

pub fn new_secret() -> String {
    let mut b = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut b);
    BASE32_NOPAD.encode(&b)
}

pub fn code_for(secret_b32: &str, step: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret_b32.trim().to_ascii_uppercase().as_bytes()).ok()?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&step.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let off = (r[19] & 0x0f) as usize;
    let bin = ((r[off] as u32 & 0x7f) << 24) | ((r[off + 1] as u32) << 16) | ((r[off + 2] as u32) << 8) | r[off + 3] as u32;
    Some(format!("{:06}", bin % 1_000_000))
}

/// Checks `code` against the current 30-second step and one step either side (clock drift).
/// Returns the matched step so the caller can refuse to accept the same code twice.
pub fn verify(secret_b32: &str, code: &str, now: i64, last_used_step: u64) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let cur = (now.max(0) as u64) / PERIOD;
    for step in [cur.saturating_sub(1), cur, cur + 1] {
        if step <= last_used_step {
            continue;
        }
        if let Some(expect) = code_for(secret_b32, step) {
            if constant_time_eq(expect.as_bytes(), code.as_bytes()) {
                return Some(step);
            }
        }
    }
    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// otpauth:// URI, the thing authenticator apps read from a QR code.
pub fn uri(user: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        enc("Syphon"),
        enc(user),
        secret_b32,
        enc("Syphon")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc6238_vectors() {
        // RFC 6238 appendix B, secret "12345678901234567890" (SHA-1). The RFC lists 8-digit codes;
        // the 6-digit code is the last six digits of the same value.
        let secret = BASE32_NOPAD.encode(b"12345678901234567890");
        assert_eq!(code_for(&secret, 1).unwrap(), "287082"); // T = 59        -> 94287082
        assert_eq!(code_for(&secret, 37037036).unwrap(), "081804"); // T = 1111111109 -> 07081804
        assert_eq!(code_for(&secret, 37037037).unwrap(), "050471"); // T = 1111111111 -> 14050471
        assert_eq!(code_for(&secret, 41152263).unwrap(), "005924"); // T = 1234567890 -> 89005924
        assert_eq!(code_for(&secret, 66666666).unwrap(), "279037"); // T = 2000000000 -> 69279037
        assert_eq!(code_for(&secret, 666666666).unwrap(), "353130"); // T = 20000000000 -> 65353130
    }

    #[test]
    fn verify_window_and_replay() {
        let secret = new_secret();
        let now = 1_700_000_000i64;
        let step = now as u64 / PERIOD;
        let code = code_for(&secret, step).unwrap();
        assert_eq!(verify(&secret, &code, now, 0), Some(step));
        assert_eq!(verify(&secret, &format!("{} {}", &code[..3], &code[3..]), now, 0), Some(step), "spaces are fine");
        assert_eq!(verify(&secret, &code, now, step), None, "a used code is refused");
        let prev = code_for(&secret, step - 1).unwrap();
        assert_eq!(verify(&secret, &prev, now, 0), Some(step - 1), "one step of drift is tolerated");
        let far = code_for(&secret, step + 5).unwrap();
        assert_eq!(verify(&secret, &far, now, 0), None);
        assert_eq!(verify(&secret, "12345", now, 0), None);
        assert_eq!(verify(&secret, "abcdef", now, 0), None);
    }

    #[test]
    fn uri_is_escaped() {
        let u = uri("Yasu Q", "ABC");
        assert!(u.starts_with("otpauth://totp/Syphon:Yasu%20Q?secret=ABC"), "{u}");
    }
}
