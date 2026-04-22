#![cfg(feature = "std")]

use std::fs;
use std::path::PathBuf;

fn read(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let full = root.join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|err| panic!("read {} failed: {}", full.display(), err))
}

#[test]
fn lifecycle_surface_uses_attach_helpers_not_raw_program_exports() {
    let src = read("src/lib.rs");
    let kinds = read("src/control_kinds.rs");

    assert!(
        src.contains("pub fn attach_controller") && src.contains("pub fn attach_cluster"),
        "hibana-epf surface must expose attach helpers"
    );
    assert!(
        src.contains("pub mod control_kinds;"),
        "hibana-epf surface must expose its lifecycle kind owner module"
    );

    for forbidden in [
        "pub const PROGRAM",
        "pub const PREFIX",
        "g::advanced::steps",
        "const APP: g::Program<_>",
        "static APP: g::Program<_>",
        "const PROGRAM: g::Program<_>",
        "static PROGRAM: g::Program<_>",
        "project(&PROGRAM)",
        "project::<",
    ] {
        assert!(
            !src.contains(forbidden),
            "hibana-epf surface must not export raw choreography values: {forbidden}"
        );
    }

    for required in [
        "pub struct PolicyLoadKind;",
        "pub struct PolicyActivateKind;",
        "pub struct PolicyRevertKind;",
        "pub struct PolicyAnnotateKind;",
        "GenericCapToken<PolicyLoadKind>",
        "GenericCapToken<PolicyActivateKind>",
        "GenericCapToken<PolicyRevertKind>",
        "GenericCapToken<PolicyAnnotateKind>",
    ] {
        assert!(
            kinds.contains(required) || src.contains(required),
            "hibana-epf must own lifecycle kind vocabulary and use control-kind messages: {required}"
        );
    }

    for forbidden in [
        "Msg<LABEL_POLICY_LOAD, u32>",
        "Msg<LABEL_POLICY_ACTIVATE, u8>",
        "Msg<LABEL_POLICY_REVERT, u8>",
        "Msg<LABEL_POLICY_ANNOTATE, PolicyAnnotation>",
        "Role<ROLE_CONTROLLER>,\n        hibana::g::Role<ROLE_CLUSTER>,",
    ] {
        assert!(
            !src.contains(forbidden),
            "hibana-epf attach helpers must not use the old raw label/payload path: {forbidden}"
        );
    }
}

#[test]
fn dependency_surface_uses_exact_git_rev_with_local_overlay_config() {
    let cargo_toml = read("Cargo.toml");
    let cargo_config = read(".cargo/config.toml");

    assert!(cargo_toml.contains("git = \"https://github.com/hibanaworks/hibana\""));
    assert!(cargo_toml.contains("rev = \""));
    assert!(!cargo_toml.contains("path = \"../hibana\""));

    assert!(cargo_config.contains("[patch.\"https://github.com/hibanaworks/hibana\"]"));
    assert!(cargo_config.contains("hibana = { path = \"../hibana\" }"));
}
