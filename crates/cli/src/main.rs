//! PassGuardian CLI. For now it only prints the version; commands arrive in Sprint 4.

fn main() {
    println!(
        "passguardian {} (vault format v{})",
        env!("CARGO_PKG_VERSION"),
        passguardian_core::VAULT_FORMAT_VERSION
    );
}
