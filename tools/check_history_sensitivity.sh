#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
out="$root/target/history-sensitivity"
mkdir -p "$out"
cargo +stable test --locked --test capture > "$out/positive.log" 2>&1
cargo +stable test --locked --lib --features std protocol::history::tests \
  > "$out/positive-links.log" 2>&1
for mutation in Length Ordinals CallOverlap CallCoverage; do
  source="$out/$mutation"
  test ! -e "$source"
  git clone --quiet --shared --no-checkout "$root" "$source"
  git ls-files --cached --others --exclude-standard -z |
    perl -0ne 'print "$_\0" for grep { -f $_ } split /\0/' |
    rsync -a --from0 --files-from=- ./ "$source/"
  git -C "$source" add -A
  git -C "$source" diff --cached --binary HEAD > "$out/$mutation-source.patch"
  case "$mutation" in
    Length|Ordinals)
      git -C "$source" apply --check "$root/proofs/OmitCapture$mutation.patch"
      git -C "$source" apply "$root/proofs/OmitCapture$mutation.patch"
      ;;
    CallOverlap)
      perl -0pi -e 's/for pair in roots\.windows\(2\)/for pair in roots[..0].windows(2)/g == 1 or die "missing call interval check\n"' \
        "$source/src/protocol/history.rs"
      ;;
    CallCoverage)
      perl -0pi -e 's/if required != present \{/if wire_publication \&\& required != present {/g == 1 or die "missing poll coverage check\n"' \
        "$source/src/protocol/history.rs"
      ;;
  esac
  git -C "$source" diff --binary > "$out/$mutation-mutation.patch"
  status=0
  (
    cd "$source"
    git ls-files -z | xargs -0 shasum -a 256 -- > "$out/$mutation-source.sha256"
    case "$mutation" in
      Length|Ordinals) cargo +stable test --locked --test capture ;;
      CallOverlap) cargo +stable test --locked --lib --features std \
        protocol::history::tests::link_checker_rejects_overlapping_calls_with_complete_unique_coverage \
        -- --exact ;;
      CallCoverage) cargo +stable test --locked --lib --features std \
        protocol::history::tests::link_checker_rejects_lost_polls_cycles_and_reused_publications \
        -- --exact ;;
    esac
  ) > "$out/$mutation.log" 2>&1 || status=$?
  test "$status" = 101
  case "$mutation" in
    Length|Ordinals) grep -Fq 'test result: FAILED. 3 passed; 1 failed;' "$out/$mutation.log" ;;
    CallOverlap|CallCoverage) grep -Fq 'test result: FAILED. 0 passed; 1 failed;' "$out/$mutation.log" ;;
  esac
  case "$mutation" in
    Length) name=deleting_any_record_including_the_last_is_incomplete ;;
    Ordinals) name=duplicate_reordered_and_saturated_ordinals_cannot_replace_missing_records ;;
    CallOverlap) name=protocol::history::tests::link_checker_rejects_overlapping_calls_with_complete_unique_coverage ;;
    CallCoverage) name=protocol::history::tests::link_checker_rejects_lost_polls_cycles_and_reused_publications ;;
  esac
  grep -Fxq "test $name ... FAILED" "$out/$mutation.log"
  find "$source/target" -type f -perm -100 -exec shasum -a 256 -- {} + > "$out/$mutation-binaries.sha256"
  printf 'mutation=%s\nexit=%s\n' "$mutation" "$status" > "$out/$mutation-result.txt"
  rm -r -- "$source"
done
echo "History sensitivity: omitted length, ordinal, call interval and poll coverage checks fail their regression tests"
