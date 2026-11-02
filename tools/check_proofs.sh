#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi
out="$PWD/target/commit-observation-proof"
mkdir -p "$out"
cargo +stable metadata --locked --format-version 1 > "$out/metadata.json"
manifest="$(jq -r '.packages[] | select(.name == "hibana") | .manifest_path' "$out/metadata.json")"
core="$(cd "$(dirname "$manifest")" && pwd -P)"
selected="$(jq -r '.packages[] | select(.name == "hibana") | .source | split("#")[1]' "$out/metadata.json")"
test "$(git -C "$core" rev-parse HEAD)" = "$selected"
git -C "$core" diff --exit-code HEAD > "$out/core-source.patch"
git rev-parse HEAD > "$out/epf-revision.txt"
git diff --binary HEAD > "$out/epf-source.patch"
printf '%s\n' "$selected" > "$out/core-revision.txt"
shasum -a 256 proofs/CommitObservations.lean proofs/Capture.lean proofs/SendCalls.lean \
  proofs/DeliveryOrder.lean proofs/CaptureExecution.lean tools/check_proofs.sh > "$out/source.sha256"
cp proofs/CommitObservations.lean "$out/CommitObservations.lean"
cp proofs/Capture.lean "$out/Capture.lean"
cp proofs/SendCalls.lean "$out/"
cp proofs/DeliveryOrder.lean "$out/"
cp proofs/CaptureExecution.lean "$out/"
(
  cd "$core"
  git ls-files -z proofs/lean | xargs -0 shasum -a 256 --
) > "$out/core-source.sha256"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export ELAN_TOOLCHAIN="$(cat "$core/proofs/lean/lean-toolchain")"
lean --version > "$out/lean-version.txt"
bash "$core/.github/scripts/lib/lean_audit_tool.sh" build-serial \
  "$core/proofs/lean" --native Hibana.SourceOccurrenceTrace
LEAN_PATH="$core/proofs/lean/.lake/build/lib/lean" \
  lean proofs/CommitObservations.lean 2>&1 | tee "$out/lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" lean "$out/lean.log" 10
lean proofs/Capture.lean 2>&1 | tee "$out/capture-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" lean "$out/capture-lean.log" 4
lean proofs/SendCalls.lean 2>&1 | tee "$out/send-calls-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" lean "$out/send-calls-lean.log" 13
lean proofs/DeliveryOrder.lean 2>&1 | tee "$out/delivery-order-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" lean "$out/delivery-order-lean.log" 5
LEAN_PATH="$core/proofs/lean/.lake/build/lib/lean" \
  lean proofs/CaptureExecution.lean 2>&1 | tee "$out/capture-execution-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" lean "$out/capture-execution-lean.log" 14
shasum -a 256 --check "$out/source.sha256" > "$out/source-check.log"
(cd "$core" && shasum -a 256 --check "$out/core-source.sha256") > "$out/core-source-check.log"
echo "Observation proofs: ten source boundaries, four complete-prefix, thirteen send/reset/word, five causal-order and fourteen capture/source-execution claims"
