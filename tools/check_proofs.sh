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
shasum -a 256 proofs/CommitObservations.lean proofs/Capture.lean tools/check_proofs.sh > "$out/source.sha256"
cp proofs/CommitObservations.lean "$out/CommitObservations.lean"
cp proofs/Capture.lean "$out/Capture.lean"
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
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" lean "$out/lean.log" 7
lean proofs/Capture.lean 2>&1 | tee "$out/capture-lean.log"
bash "$core/.github/scripts/lib/supplemental_proofs_tool.sh" lean "$out/capture-lean.log" 4
shasum -a 256 --check "$out/source.sha256" > "$out/source-check.log"
(cd "$core" && shasum -a 256 --check "$out/core-source.sha256") > "$out/core-source-check.log"
echo "Observation proofs: seven source boundary claims and four complete-prefix claims"
