fn main() {
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEVELOPMENT_GATE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEVELOPMENT_GATE_CLIENT");
    if std::env::var("PROFILE").as_deref() == Ok("release")
        && (std::env::var_os("CARGO_FEATURE_DEVELOPMENT_GATE").is_some()
            || std::env::var_os("CARGO_FEATURE_DEVELOPMENT_GATE_CLIENT").is_some())
    {
        panic!("development-gate is forbidden in release builds");
    }
}
