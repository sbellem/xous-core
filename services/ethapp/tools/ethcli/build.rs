fn main() {
    // Version priority:
    // 1. ETHCLI_VERSION env var (set by Guix/Nix build systems)
    // 2. git describe (for dev builds in a git checkout)
    // 3. CARGO_PKG_VERSION from Cargo.toml (fallback)
    let version = std::env::var("ETHCLI_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::process::Command::new("git")
                .args(["describe", "--always", "--dirty", "--tags"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
        });

    println!("cargo:rustc-env=ETHCLI_VERSION={}", version);
}
