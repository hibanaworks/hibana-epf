#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
stage="${1:-all}"
if [ "$#" -gt 1 ]; then exit 2; fi
case "$stage" in
    all|native|miri-unit|miri-integration) ;;
    *) echo "usage: $0 [all|native|miri-unit|miri-integration]" >&2; exit 2 ;;
esac
case "$stage" in all|native)
    cargo +stable fmt --all -- --check
    cargo +stable test --locked --all-targets --features std -- --test-threads=1
    cargo +stable clippy --locked --all-targets --features std -- -D warnings
    cargo +stable test --locked --doc
    cargo +stable build --locked --lib --no-default-features
    cargo +stable build --locked --lib --no-default-features --target thumbv6m-none-eabi
esac
export MIRIFLAGS="${MIRIFLAGS:+$MIRIFLAGS }-Zmiri-strict-provenance"
case "$stage" in all|miri-unit)
    cargo +"$(cat tools/miri-toolchain)" miri test --locked --lib -- --test-threads=1
esac
case "$stage" in all|miri-integration)
    cargo +"$(cat tools/miri-toolchain)" miri test --locked \
        --test production_path --test endpoint_observation --test endpoint_history \
        --test source_unfolding --test source_path --test source_word --test source_interpretation --test automatic_audit \
        --test protocol --test capture -- --test-threads=1
esac
case "$stage" in all|native)
    bash tools/check_proofs.sh
    bash tools/check_history_sensitivity.sh
esac
