//! Build script for nono
//!
//! Embeds security lists and built-in profiles into the binary at compile time.
//!
//! # Signature Handling
//!
//! Signatures are OPTIONAL at build time to support development workflows:
//! - Development builds: Work without signatures, sets SECURITY_LISTS_SIGNED=0
//! - Release builds: Include signatures (created during release), sets SECURITY_LISTS_SIGNED=1
//!
//! Runtime code uses these env vars to decide verification behavior.
//! Official releases should always include signatures.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Rebuild if data files change
    println!("cargo:rerun-if-changed=data/");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);

    // === Embed security lists ===
    let security_lists_path = Path::new("data/security-lists.toml");
    if security_lists_path.exists() {
        let content =
            fs::read_to_string(security_lists_path).expect("Failed to read security-lists.toml");

        // Write to OUT_DIR for include_str! macro
        fs::write(out_path.join("security-lists.toml"), &content)
            .expect("Failed to write security-lists.toml to OUT_DIR");

        println!("cargo:rustc-env=SECURITY_LISTS_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/security-lists.toml not found");
        println!("cargo:rustc-env=SECURITY_LISTS_EMBEDDED=0");
    }

    // === Embed built-in profiles ===
    let profiles_dir = Path::new("data/profiles");
    if profiles_dir.exists() {
        let mut profile_names = Vec::new();

        for entry in fs::read_dir(profiles_dir).expect("Failed to read profiles directory") {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "toml") {
                let name = path
                    .file_stem()
                    .expect("No file stem")
                    .to_string_lossy()
                    .to_string();

                let content = fs::read_to_string(&path).expect("Failed to read profile");

                // Write profile to OUT_DIR
                let out_profile_path = out_path.join(format!("profile-{}.toml", name));
                fs::write(&out_profile_path, &content).expect("Failed to write profile to OUT_DIR");

                profile_names.push(name);
            }
        }

        // Write list of profile names for runtime enumeration
        let names_content = profile_names.join("\n");
        fs::write(out_path.join("profile-names.txt"), &names_content)
            .expect("Failed to write profile names");

        println!(
            "cargo:rustc-env=BUILTIN_PROFILES={}",
            profile_names.join(",")
        );
    }

    // === Signature files (optional for development) ===
    // During development, signatures won't exist yet.
    // For release builds, run scripts/sign-release.sh to create them.
    let sig_path = Path::new("data/security-lists.toml.minisig");
    if sig_path.exists() {
        let sig_content = fs::read_to_string(sig_path).expect("Failed to read signature file");
        fs::write(out_path.join("security-lists.toml.minisig"), &sig_content)
            .expect("Failed to write signature to OUT_DIR");
        println!("cargo:rustc-env=SECURITY_LISTS_SIGNED=1");
    } else {
        // Not an error - signatures are optional during development
        println!("cargo:rustc-env=SECURITY_LISTS_SIGNED=0");
    }
}
