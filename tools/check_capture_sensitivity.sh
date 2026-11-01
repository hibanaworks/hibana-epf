#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
out="$root/target/capture-sensitivity"
mkdir -p "$out"
cargo +stable test --locked --test capture > "$out/positive.log" 2>&1
for mutation in Length Ordinals; do
  source="$out/$mutation"
  test ! -e "$source"
  git clone --quiet --shared --no-checkout "$root" "$source"
  git ls-files --cached --others --exclude-standard -z |
    perl -0ne 'print "$_\0" for grep { -f $_ } split /\0/' |
    rsync -a --from0 --files-from=- ./ "$source/"
  git -C "$source" add -A
  git -C "$source" diff --cached --binary HEAD > "$out/$mutation-source.patch"
  git -C "$source" apply --check "$root/proofs/OmitCapture$mutation.patch"
  git -C "$source" apply "$root/proofs/OmitCapture$mutation.patch"
  git -C "$source" diff --binary > "$out/$mutation-mutation.patch"
  status=0
  (
    cd "$source"
    git ls-files -z | xargs -0 shasum -a 256 -- > "$out/$mutation-source.sha256"
    cargo +stable test --locked --test capture
  ) > "$out/$mutation.log" 2>&1 || status=$?
  test "$status" = 101
  grep -Fq 'test result: FAILED. 3 passed; 1 failed;' "$out/$mutation.log"
  case "$mutation" in
    Length) name=deleting_any_record_including_the_last_is_incomplete ;;
    Ordinals) name=duplicate_reordered_and_saturated_ordinals_cannot_replace_missing_records ;;
  esac
  grep -Fxq "test $name ... FAILED" "$out/$mutation.log"
  find "$source/target" -type f -perm -100 -exec shasum -a 256 -- {} + > "$out/$mutation-binaries.sha256"
  printf 'mutation=%s\nexit=%s\n' "$mutation" "$status" > "$out/$mutation-result.txt"
  rm -r -- "$source"
done
echo "Capture sensitivity: both omitted checks fail their corresponding regression test"
