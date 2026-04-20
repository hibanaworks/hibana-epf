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
    ] {
        assert!(
            kinds.contains(required),
            "hibana-epf must own lifecycle kind vocabulary: {required}"
        );
    }
}
