#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
stage="${1:-all}"
if [ "$#" -gt 1 ]; then exit 2; fi
targets="$(cargo +stable metadata --locked --no-deps --format-version 1 |
    jq -c '[.packages[] | select(.name == "hibana-epf").targets[] |
        select(.kind == ["test"] and ((.["required-features"] // []) | length == 0)) |
        .name] | sort |
        if length > 0 then . else error("no integration targets") end')"
if [ "$stage" = plan ]; then
    printf '%s\n' "$targets" |
        jq -c '{stage: (["native", "miri-unit"] + map("miri-" + .))}'
    exit 0
fi
case "$stage" in
    all|native|miri-unit|miri-integration) ;;
    miri-*)
        printf '%s\n' "$targets" | jq -e --arg name "${stage#miri-}" 'index($name) != null' >/dev/null ;;
    *) echo "usage: $0 [all|native|miri-unit|miri-integration|miri-TARGET|plan]" >&2; exit 2 ;;
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
case "$stage" in all|miri-*)
    core_manifest="$(cargo +stable metadata --locked --format-version 1 |
        jq -er '[.packages[] | select(.name == "hibana") | .manifest_path] |
            if length == 1 then .[0] else error("expected exactly one core") end')"
    result_tool="$(dirname "$core_manifest")/.github/scripts/lib/test_result_tool.sh"
esac
run_miri() {
    log="$(mktemp)"
    if cargo +"$(cat tools/miri-toolchain)" miri test --locked "$@" \
        -- --test-threads=1 > "$log" 2>&1; then
        cat "$log"
        if ! bash "$result_tool" check "$log" "EPF $stage" 0; then
            rm -f "$log"
            return 1
        fi
    else
        status=$?
        cat "$log" >&2
        rm -f "$log"
        return "$status"
    fi
    rm -f "$log"
}
case "$stage" in all|miri-unit)
    run_miri --lib
esac
case "$stage" in all|miri-integration|miri-*)
    if [ "$stage" != miri-unit ]; then
        selected="$(printf '%s\n' "$targets" | jq -r '.[]')"
        case "$stage" in all|miri-integration) ;; *) selected="${stage#miri-}" ;; esac
        for target in $selected; do
            run_miri --test "$target"
        done
    fi
esac
case "$stage" in all|native)
    bash tools/check_proofs.sh
    bash tools/check_history_sensitivity.sh
esac
