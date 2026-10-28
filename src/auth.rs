use crate::state::App;
use anyhow::{anyhow, bail, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::rngs::OsRng;
use rusqlite::{params, OptionalExtension};

pub const ROLES: [&str; 3] = ["owner", "contributor", "viewer"];

pub fn hash_pw(pw: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("hashing failed: {e}"))
}

pub fn check_pw(hash: &str, pw: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(h) => Argon2::default().verify_password(pw.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

pub fn create_user(app: &App, name: &str, password: &str, role: &str) -> Result<()> {
    if !ROLES.contains(&role) {
        bail!("role must be one of {ROLES:?}");
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 40 {
        bail!("user name must be 1-40 characters");
    }
    if password.len() < 8 {
        bail!("password must be at least 8 characters");
    }
    let h = hash_pw(password)?;
    app.db.with(|c| {
        let exists: Option<i64> = c.query_row("SELECT 1 FROM users WHERE name=?1", [name], |r| r.get(0)).optional()?;
        if exists.is_some() {
            bail!("user {name} already exists");
        }
        c.execute("INSERT INTO users(name,pw_hash,role) VALUES(?1,?2,?3)", params![name, h, role])?;
        Ok(())
    })
}

pub fn delete_user(app: &App, name: &str) -> Result<()> {
    app.db.with(|c| {
        let role: Option<String> = c.query_row("SELECT role FROM users WHERE name=?1", [name], |r| r.get(0)).optional()?;
        match role.as_deref() {
            None => bail!("no such user"),
            Some("owner") => bail!("the owner account cannot be deleted"),
            _ => {}
        }
        c.execute("DELETE FROM users WHERE name=?1", [name])?;
        c.execute("DELETE FROM progress WHERE user=?1", [name])?;
        c.execute("DELETE FROM devices WHERE user=?1", [name])?;
        c.execute("DELETE FROM approvals WHERE user=?1", [name])?;
        c.execute("DELETE FROM avatars WHERE user=?1", [name])?;
        Ok(())
    })?;
    app.sessions.lock().unwrap().retain(|_, s| s.user != name);
    Ok(())
}

pub fn list_users(app: &App) -> Result<Vec<(String, String)>> {
    app.db.with(|c| {
        let mut st = c.prepare("SELECT name,role FROM users ORDER BY name")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub fn change_owner_password(app: &App, old: &str, new: &str) -> Result<()> {
    if new.len() < 8 {
        bail!("password must be at least 8 characters");
    }
    app.keyring.change_password(old, new)?;
    let h = hash_pw(new)?;
    app.db.with(|c| {
        c.execute("UPDATE users SET pw_hash=?1 WHERE role='owner'", [h])?;
        Ok(())
    })
}

/// Any user can change their own password; the owner's also re-wraps the library key.
pub fn change_user_password(app: &App, user: &str, old: &str, new: &str) -> Result<()> {
    if new.len() < 8 {
        bail!("password must be at least 8 characters");
    }
    let (hash, role): (String, String) = app
        .db
        .with(|c| Ok(c.query_row("SELECT pw_hash,role FROM users WHERE name=?1", [user], |r| Ok((r.get(0)?, r.get(1)?)))?))?;
    if role == "owner" {
        return change_owner_password(app, old, new);
    }
    if !check_pw(&hash, old) {
        bail!("the current password is not right");
    }
    let h = hash_pw(new)?;
    app.db.with(|c| {
        c.execute("UPDATE users SET pw_hash=?1 WHERE name=?2", params![h, user])?;
        Ok(())
    })
}
