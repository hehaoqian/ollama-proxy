fn main() {
    // Re-run the build script if Cargo.toml changes
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Enable link-time optimization in release builds
    if std::env::var("PROFILE").unwrap() == "release" {
        println!("cargo:rustc-cfg=release");
    }

    // Check if the current build is a CI build (GitHub Actions)
    if std::env::var("CI").is_ok() {
        println!("cargo:rustc-cfg=ci");
    }
}
