fn main() {
    // Try git describe for a rich version string (e.g. "v0.1.0-3-gabcdef1-dirty").
    // Falls back to CARGO_PKG_VERSION if git isn't available (Nix clean builds, tarballs).
    let version = std::process::Command::new("git")
        .args(["describe", "--always", "--dirty", "--tags"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=ETHCLI_VERSION={}", version);
}
