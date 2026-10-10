mod build_script {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/build.rs"));
    pub fn run() {
        main();
    }
}

#[test]
fn build_environment_probe() {
    if std::env::var_os("CVLD_BUILD_POLICY_PROBE").is_some() {
        build_script::run();
    }
}

#[test]
fn actual_build_script_refuses_development_authority_in_release() {
    for (profile, development, accepted) in [
        ("debug", true, true),
        ("release", false, true),
        ("release", true, false),
    ] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "build_environment_probe", "--nocapture"])
            .env("CVLD_BUILD_POLICY_PROBE", "1")
            .env("PROFILE", profile)
            .env_remove("CARGO_FEATURE_DEVELOPMENT_GATE");
        if development {
            command.env("CARGO_FEATURE_DEVELOPMENT_GATE", "1");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.success(), accepted);
        if !accepted {
            assert!(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("development-gate is forbidden in release builds")
            );
        }
    }
}
