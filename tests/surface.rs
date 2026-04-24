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
        "pub use vm::{Slot",
        "#[allow(private_bounds)]",
        "#[expect(private_bounds",
        "g::advanced",
        "hibana::g::advanced",
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
        "pub struct PolicyAnnotation",
        "PolicyAnnotation {",
        "WirePayload for PolicyAnnotation",
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
        "pub fn commit(",
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
        src.contains("VerifiedImage::from_parts_for_slot"),
        "loader commit must use the slot-bound zero-copy verifier entry"
    );
}

#[test]
fn image_header_surface_has_no_unchecked_flags() {
    let verifier = read("src/verifier.rs");

    assert!(
        !verifier.contains("pub flags:"),
        "EPF image flags must not remain a public unchecked field"
    );
    assert!(
        verifier.contains("UnsupportedFlags"),
        "EPF verifier must reject non-zero reserved header flags"
    );
    assert!(
        !verifier.contains("pub fn new(bytes"),
        "EPF verifier public surface must require slot-specific verification"
    );
}

#[test]
fn host_install_error_surface_has_single_recovery_path() {
    let host = read("src/host.rs");

    assert!(
        !host.contains("pub fn into_parts("),
        "InstallError must not expose a duplicate public decomposition path"
    );
    assert!(
        host.contains("pub const fn error(&self) -> HostError"),
        "InstallError must keep error inspection without consuming the scratch lease"
    );
    assert!(
        host.contains("pub fn into_scratch(self) -> ScratchLease"),
        "InstallError must keep the retry-oriented scratch recovery path"
    );
}

#[test]
fn dependency_surface_uses_immutable_hibana_git_rev() {
    let cargo_toml = read("Cargo.toml");
    let cargo_config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".cargo/config.toml");
    let dep = cargo_toml
        .lines()
        .find(|line| line.starts_with("hibana = { git = \"https://github.com/hibanaworks/hibana\""))
        .expect("hibana-epf must depend on an immutable hibana GitHub rev");
    let rev = dep
        .split("rev = \"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("hibana dependency must include a rev");

    assert_eq!(rev.len(), 40);
    assert!(rev.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(!cargo_toml.contains("hibana = { path = \"../hibana\""));
    assert!(!cargo_config.exists());
}

#[test]
fn substrate_imports_use_final_form_paths() {
    for path in [
        "src/lib.rs",
        "src/control_kinds.rs",
        "src/host.rs",
        "src/vm.rs",
    ] {
        let src = read(path);
        for forbidden in [
            "g::advanced",
            "hibana::g::advanced",
            "hibana::substrate::Lane",
            "hibana::substrate::SessionId",
            "hibana::substrate::RendezvousId",
            "use hibana::substrate::{\n    Lane",
            "use hibana::substrate::{Lane",
            "use hibana::substrate::{\n    SessionId",
            "use hibana::substrate::{SessionId",
        ] {
            assert!(
                !src.contains(forbidden),
                "hibana-epf must not keep old substrate/g paths in {path}: {forbidden}"
            );
        }
    }
}
