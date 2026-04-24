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
        src.contains("pub fn attach_controller"),
        "hibana-epf surface must expose the controller attach helper"
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
        "Msg<LABEL_POLICY_RESTORE, u8>",
        "Msg<LABEL_POLICY_ANNOTATE, PolicyAnnotation>",
        "pub fn attach_cluster",
        "ROLE_CLUSTER",
        "Role<ROLE_CONTROLLER>,\n        hibana::g::Role<ROLE_CLUSTER>,",
    ] {
        assert!(
            !src.contains(forbidden),
            "hibana-epf attach helpers must not use the old raw label/payload path: {forbidden}"
        );
    }
}

#[test]
fn loader_commit_does_not_materialize_full_image_copy() {
    let src = read("src/loader.rs");

    for forbidden in [
        "Header::SIZE + verify_buffer_len()",
        "let mut image = [0u8;",
        "copy_from_slice(code)",
    ] {
        assert!(
            !src.contains(forbidden),
            "loader commit must verify borrowed header/code parts without a full stack image copy: {forbidden}"
        );
    }
    assert!(
        src.contains("VerifiedImage::from_parts"),
        "loader commit must use the zero-copy verifier entry"
    );
}

#[test]
fn dependency_surface_uses_local_sibling_path_dependency() {
    let cargo_toml = read("Cargo.toml");
    let cargo_config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".cargo/config.toml");

    assert!(cargo_toml.contains("hibana = { path = \"../hibana\""));
    assert!(!cargo_toml.contains("git = \"https://github.com/hibanaworks/hibana\""));
    assert!(!cargo_toml.contains("rev = \""));
    assert!(!cargo_config.exists());
}
