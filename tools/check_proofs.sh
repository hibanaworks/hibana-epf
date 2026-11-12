#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi
mkdir -p target/commit-observation-proof
out="$(mktemp -d "$PWD/target/commit-observation-proof/run.XXXXXXXX")"
printf 'Proof evidence: %s\n' "$out"
cargo +stable metadata --locked --format-version 1 > "$out/metadata.json"
manifest="$(jq -er '[.packages[] | select(.name == "hibana")] | if length == 1 then .[0].manifest_path else error("one resolved Hibana core is required") end' "$out/metadata.json")"
core="$(cd "$(dirname "$manifest")" && pwd -P)"
git -C "$core" rev-parse HEAD > "$out/core-git-base.txt"
git -C "$core" diff --binary HEAD > "$out/core-source.patch"
git rev-parse HEAD > "$out/epf-git-base.txt"
git diff --binary HEAD > "$out/epf-source.patch"
source "$core/.github/scripts/lib/protocol_model_inputs.sh"
shasum -a 256 proofs/CommitObservations.lean proofs/Capture.lean proofs/SendCalls.lean \
  proofs/DeliveryOrder.lean proofs/CaptureExecution.lean proofs/CompactSource.lean \
  Cargo.toml Cargo.lock tools/check_proofs.sh > "$out/source.sha256"
cp proofs/CommitObservations.lean "$out/CommitObservations.lean"
cp proofs/Capture.lean "$out/Capture.lean"
cp proofs/SendCalls.lean "$out/"
cp proofs/DeliveryOrder.lean "$out/"
cp proofs/CaptureExecution.lean "$out/"
cp proofs/CompactSource.lean "$out/"
hibana_protocol_population_inputs "$core" > "$out/core-source.sha256"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export ELAN_TOOLCHAIN="$(cat "$core/proofs/lean/lean-toolchain")"
lean --version > "$out/lean-version.txt"
bash "$core/.github/scripts/lib/lean_audit_tool.sh" build-serial \
  "$core/proofs/lean" --native Hibana.SourceOccurrenceTrace
export LEAN_PATH="$core/proofs/lean/.lake/build/lib/lean"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" module \
  proofs/CommitObservations.lean 2>&1 | tee "$out/lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" module \
  proofs/Capture.lean 2>&1 | tee "$out/capture-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" module \
  proofs/SendCalls.lean 2>&1 | tee "$out/send-calls-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" module \
  proofs/DeliveryOrder.lean 2>&1 | tee "$out/delivery-order-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" module \
  proofs/CaptureExecution.lean 2>&1 | tee "$out/capture-execution-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" module \
  proofs/CompactSource.lean 2>&1 | tee "$out/compact-source-lean.log"
shasum -a 256 --check "$out/source.sha256" > "$out/source-check.log"
(cd "$core" && shasum -a 256 --check "$out/core-source.sha256") > "$out/core-source-check.log"
hibana_protocol_population_inputs "$core" > "$out/core-source-after.sha256"
cmp "$out/core-source.sha256" "$out/core-source-after.sha256"
echo "Observation proofs: every local theorem and axiom checked in all six compiled modules"
