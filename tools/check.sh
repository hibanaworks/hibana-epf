#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
cargo +stable fmt --all -- --check
cargo +stable test --locked --all-targets --features std -- --test-threads=1
cargo +stable clippy --locked --all-targets --features std -- -D warnings
cargo +stable test --locked --doc
cargo +stable build --locked --lib --no-default-features
cargo +stable build --locked --lib --no-default-features --target thumbv6m-none-eabi
export MIRIFLAGS="${MIRIFLAGS:+$MIRIFLAGS }-Zmiri-strict-provenance"
cargo +"$(cat tools/miri-toolchain)" miri test --locked \
    --lib --test production_path --test endpoint_observation --test endpoint_history \
    --test source_unfolding --test source_path --test source_word --test source_interpretation --test automatic_audit \
    --test protocol --test capture -- --test-threads=1
bash tools/check_proofs.sh
bash tools/check_history_sensitivity.sh
