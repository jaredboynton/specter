#[test]
fn quiche_is_not_in_the_h3_runtime() {
    let manifest = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml should be readable");

    let default_line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("default ="))
        .expect("Cargo.toml should declare default features");
    assert!(
        !default_line.contains("h3-quiche-compat") && !default_line.contains("quiche"),
        "quiche compatibility must not be enabled by default: {default_line}"
    );

    assert!(
        !manifest.contains("h3-quiche-compat"),
        "Specter's H3 runtime must not expose a quiche compatibility feature"
    );
    assert!(
        !manifest.contains("quiche-fixtures"),
        "Specter's package features must not expose quiche; fixture-only usage should stay in dev-dependencies"
    );
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("quiche =")),
        "Specter must not depend on quiche anywhere in the main package manifest"
    );

    let dependencies = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("[dev-dependencies]").next())
        .expect("Cargo.toml should have dependencies before dev-dependencies");
    assert!(
        !dependencies
            .lines()
            .any(|line| line.trim_start().starts_with("quiche =")),
        "quiche must not be a normal runtime dependency"
    );

    let h3_runtime_sources = [
        "src/transport/h3/mod.rs",
        "src/transport/h3/connection.rs",
        "src/transport/h3/handle.rs",
        "src/transport/h3/native_driver.rs",
    ];
    for path in h3_runtime_sources {
        let source = std::fs::read_to_string(path).expect("runtime source should be readable");
        assert!(
            !source.contains("quiche"),
            "{path} must not reference quiche in the runtime H3 client path"
        );
    }

    let h3_fixture_sources = [
        "tests/helpers/mock_h3_server.rs",
        "benches/streaming_vs_reqwest.rs",
    ];
    for path in h3_fixture_sources {
        let source = std::fs::read_to_string(path).expect("H3 fixture source should be readable");
        assert!(
            !source.contains("quiche"),
            "{path} must not reference quiche; fixtures and benches must use Specter's native H3"
        );
    }
}
