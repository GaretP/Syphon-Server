// Stamps the build with its release name. A release build names itself (SYPHON_VERSION=v1.2.3); otherwise the
// git tag when built from the repository, else the crate version.
fn main() {
    println!("cargo:rerun-if-env-changed=SYPHON_VERSION");
    let from_env = std::env::var("SYPHON_VERSION").ok().filter(|s| !s.is_empty());
    let from_git = || {
        std::process::Command::new("git")
            .args(["describe", "--tags", "--always", "--dirty"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let v = from_env.or_else(from_git).unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    println!("cargo:rustc-env=SYPHON_VERSION={v}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}
