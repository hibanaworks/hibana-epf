#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
mkdir -p "$root/target/history-sensitivity"
out="$(mktemp -d "$root/target/history-sensitivity/run.XXXXXXXX")"
printf 'Sensitivity evidence: %s\n' "$out"
cargo +stable test --locked --test capture > "$out/positive.log" 2>&1
cargo +stable test --locked --lib --features std protocol::history::tests \
  > "$out/positive-links.log" 2>&1
cargo +stable test --locked --lib --features std protocol::delivery::tests \
  > "$out/positive-deliveries.log" 2>&1
cargo +stable test --locked --test source_word > "$out/positive-source-word.log" 2>&1
for mutation in Length Ordinals CallOverlap CallCoverage CallPreparation ResetEvidence DeliveryProducerOrder DeliveryEdgeOrder DeliveryAmbiguity DeliveryCoverage SourceOrder ResumptionAdmission InvocationContext PollAdmission AcceptanceEvidence ConstructorValidation ConstructorOrder SplitInsertion SplitBoundary ResolverEvidence ScopeLookup HeadPrefix BranchDemand TypedArmSeed InsertionPrune QuerySelection QueryDecision QueryFinished CommittedSelection; do
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
    CallPreparation)
      perl -0pi -e 's/poll\.arg1\(\) as u16 != first\.arg1\(\) as u16/poll.arg1() != first.arg1()/g == 1 or die "missing per-poll preparation check\n"' \
        "$source/src/protocol/history.rs"
      ;;
    ResetEvidence)
      perl -0pi -e 's/resets\[after\] <= before \+ 1/false/g == 1 or die "missing reset correspondence check\n"' \
        "$source/src/protocol/history.rs"
      ;;
    DeliveryProducerOrder)
      perl -0pi -e 's/ranks\[interval\[0\]\.\.interval\[1\]\]/ranks[interval[0]..interval[0]]/g == 1 or die "missing producer order check\n"' \
        "$source/src/protocol/delivery.rs"
      ;;
    DeliveryEdgeOrder)
      perl -0pi -e 's/ranks\[send\] >= rank/false/g == 1 or die "missing delivery order check\n"' \
        "$source/src/protocol/delivery.rs"
      ;;
    DeliveryAmbiguity)
      perl -0pi -e 's/locate\(offsets, index\)\.producer != producer/locate(offsets, index).producer != producer \&\& false/g == 1 or die "missing ambiguity check\n"' \
        "$source/src/protocol/delivery.rs"
      ;;
    DeliveryCoverage)
      perl -0pi -e 's/receives\.get\(sends\.len\(\)\)/receives.get(receives.len())/g == 1 or die "missing receive coverage check\n"' \
        "$source/src/protocol/delivery.rs"
      ;;
    SourceOrder)
      perl -0pi -e 's/source\.before\(event, point\.event\(\)\)/false/g == 1 or die "missing source-order check\n"' \
        "$source/src/protocol/word.rs"
      ;;
    ResumptionAdmission)
      perl -0pi -e 's/let resumption = can_resume/let resumption = false/g == 1 or die "missing resumption prerequisite\n"' \
        "$source/src/protocol/word.rs"
      ;;
    InvocationContext)
      perl -0pi -e 's/InsertPart::Earlier\(event\)/if earlier == next { InsertPart::Resumed(event) } else { InsertPart::Earlier(event) }/g == 1 or die "missing constructor-child identity\n"' \
        "$source/src/protocol/unfolding.rs"
      ;;
    PollAdmission)
      perl -0pi -e 's/if !self\.query_ready\(/if false \&\& !self.query_ready(/g == 1 or die "missing per-poll admission query\n"' \
        "$source/src/protocol/execution.rs"
      ;;
    QuerySelection)
      perl -0pi -e 's/if compatible \&\& available\(\&path\)/if false \&\& compatible \&\& available(\&path)/g == 1 or die "missing checked query selection\n"' "$source/src/protocol/query.rs"
      ;;
    QueryDecision)
      perl -0pi -e 's/\&\& audit\.causal_key\(\) as u8 != u8::from\(right\)/\&\& false \&\& audit.causal_key() as u8 != u8::from(right)/g == 1 or die "missing query decision correspondence\n"' "$source/src/protocol/execution.rs"
      ;;
    QueryFinished)
      perl -0pi -e 's/\&\& !history\.clone\(\)\.any\(\|prior\| prior == finish\)/\&\& (!history.clone().any(|prior| prior == finish) || true)/g == 1 or die "missing unfinished query check\n"' "$source/src/protocol/query.rs"
      ;;
    CommittedSelection)
      perl -0pi -e 's/\|\| self\.actors\(event\)\.is_some\(\)/|| true/g == 1 or die "missing committed selection membership\n"' "$source/src/protocol/execution.rs"
      ;;
    AcceptanceEvidence)
      perl -0pi -e 's/if !completed \{/if false \&\& !completed {/g == 1 or die "missing completion evidence check\n"' \
        "$source/src/protocol/execution.rs"
      ;;
    ConstructorValidation)
      perl -0pi -e 's/match self\.check_execution\(captures, \&trial, tail\)/match Ok::<(), ExecutionError>(())/g == 1 or die "missing completed-candidate validation\n"' \
        "$source/src/protocol/interpret.rs"
      ;;
    ConstructorOrder)
      perl -0pi -e 's/if taken\[producer\] == captures\[producer\]\.records\(\)\.len\(\)/if order[..depth].iter().any(|prior| prior.producer > producer) || taken[producer] == captures[producer].records().len()/g == 1 or die "missing record interleaving search\n"' \
        "$source/src/protocol/interpret.rs"
      ;;
    SplitInsertion)
      perl -0pi -e 's/event = focus\[0\] \+ event\.saturating_sub\(focus\[0\] \+ count\(next\)\);/event = event.saturating_sub(count(next));/g == 1 or die "missing insertion event mapping\n"' \
        "$source/src/protocol/unfolding.rs"
      ;;
    SplitBoundary)
      perl -0pi -e 's/if left \{\n                first = middle \+ 1;/if !left {\n                first = middle + 1;/g == 1 or die "missing structural boundary search\n"' \
        "$source/src/protocol/unfolding.rs"
      ;;
    ScopeLookup)
      perl -0pi -e 's/records\[index\]\.causal_key\(\) < key/records[index].causal_key() <= key/g == 1 or die "missing indexed scope lower bound\n"' "$source/src/protocol.rs"
      ;;
    HeadPrefix)
      perl -0pi -e 's/(fn head\(.*?partition_point\(\|row\| \(row.arg0\(\) as usize\)) < region.start/$1 <= region.start/s == 1 or die "missing source head boundary\n"' "$source/src/protocol/unfolding.rs"
      ;;
    BranchDemand)
      perl -0pi -e 's/\+ scratch\[split\.\.end\]\.iter\(\)\.max\(\)\.copied\(\)\.unwrap_or\(0\)/.max(scratch[split..end].iter().max().copied().unwrap_or(0))/g == 1 or die "missing alternative visit demand\n"' "$source/src/protocol/unfolding/generate.rs"
      ;;
    TypedArmSeed)
      perl -0pi -e 's/record\.id\(\) != tap::SEND_POLL/record.id() == tap::ROUTE_ARM_SELECTION/g == 2 or die "missing typed operation preference\n"' "$source/src/protocol/audit.rs"
      ;;
    InsertionPrune)
      perl -0pi -e 's/source\.has_insertions\(\)/false/g == 1 or die "missing insertion condition\n"' "$source/src/protocol/word.rs"
      ;;
    ResolverEvidence)
      perl -0pi -e 's/if audit\.is_none_or\(/if false \&\& audit.is_none_or(/g == 1 or die "missing resolver evidence check\n"' \
        "$source/src/protocol/routes.rs"
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
      CallPreparation|ResetEvidence) cargo +stable test --locked --test endpoint_history \
        pending_siblings_can_share_the_reset_published_by_the_first_completed_send \
        -- --exact ;;
      DeliveryProducerOrder|DeliveryEdgeOrder) cargo +stable test --locked --lib --features std \
        protocol::delivery::tests::the_order_certificate_must_preserve_both_producer_and_delivery_edges -- --exact ;;
      DeliveryAmbiguity|DeliveryCoverage) cargo +stable test --locked --lib --features std \
        protocol::delivery::tests::missing_reused_or_unordered_producer_evidence_cannot_supply_a_receive -- --exact ;;
      SourceOrder) cargo +stable test --locked --test source_word \
        later_publication_cannot_hide_an_acceptance_before_its_source_predecessor -- --exact ;;
      ResumptionAdmission) cargo +stable test --locked --test source_word \
        only_a_committed_resumed_body_delays_the_outgoing_continuation -- --exact ;;
      InvocationContext) cargo +stable test --locked --test source_word \
        reusing_a_proof_dag_does_not_share_a_resumption_entry_across_invocations -- --exact ;;
      PollAdmission) cargo +stable test --locked --test endpoint_history \
        source_order_is_checked_before_a_pending_transport_send_can_expose_its_frame -- --exact ;;
      ConstructorValidation) cargo +stable test --locked --test source_interpretation \
        a_committed_route_selection_cannot_name_an_unselected_query_occurrence -- --exact ;;
      AcceptanceEvidence) cargo +stable test --locked --test endpoint_history \
        an_observed_send_poll_can_end_in_a_transport_error_without_a_commit -- --exact ;;
      ConstructorOrder) cargo +stable test --locked --test source_interpretation \
        causal_order_search_matches_every_interleaving_and_rejects_an_early_reply -- --exact ;;
      SplitInsertion|SplitBoundary) cargo +stable test --locked --lib \
        protocol::unfolding::tests::structural_splits_match_full_cut_enumeration_across_all_unfolding_constructors -- --exact ;;
      ScopeLookup) cargo +stable test --locked --lib protocol::index_tests::retained_scope_index_matches_exhaustive_marker_lookup -- --exact ;;
      HeadPrefix) cargo +stable test --locked --test source_unfolding compiled_scope_nesting_preserves_sequence_parallel_and_choice -- --exact ;;
      BranchDemand) cargo +stable test --locked --lib protocol::unfolding::generate::tests::branch_demands_add_while_sequence_parallel_and_nested_roll_share_visits -- --exact ;;
      TypedArmSeed) cargo +stable test --locked --lib protocol::audit::tests::typed_operations_seed_distinct_branch_visits_before_later_offer_evidence -- --exact ;;
      InsertionPrune) cargo +stable test --locked --lib protocol::word::tests::prerequisite_factoring_matches_the_unfactored_rule_for_every_point_subset -- --exact ;;
      ResolverEvidence) cargo +stable test --locked --test endpoint_observation \
        automatic_audit_checks_resolver_calls_from_outgoing_offers_in_each_visit -- --exact ;;
      QuerySelection|QueryDecision) cargo +stable test --locked --test endpoint_observation \
        cancelled_resolved_send_can_retry_the_other_arm_before_any_commit -- --exact ;;
      QueryFinished) cargo +stable test --locked --test endpoint_observation \
        cancelled_offer_records_a_decision_without_consuming_the_source_operation -- --exact ;;
      CommittedSelection) cargo +stable test --locked --test source_interpretation \
        a_committed_route_selection_cannot_name_an_unselected_query_occurrence -- --exact ;;
    esac
  ) > "$out/$mutation.log" 2>&1 || status=$?
  test "$status" = 101
  case "$mutation" in
    Length|Ordinals) grep -Fq 'test result: FAILED. 3 passed; 1 failed;' "$out/$mutation.log" ;;
    CallOverlap|CallCoverage|CallPreparation|ResetEvidence|Delivery*|SourceOrder|ResumptionAdmission|InvocationContext|PollAdmission|AcceptanceEvidence|Constructor*|Split*|ResolverEvidence|ScopeLookup|HeadPrefix|BranchDemand|TypedArmSeed|InsertionPrune|Query*|CommittedSelection) grep -Fq 'test result: FAILED. 0 passed; 1 failed;' "$out/$mutation.log" ;;
  esac
  case "$mutation" in
    Length) name=deleting_any_record_including_the_last_is_incomplete ;;
    Ordinals) name=duplicate_reordered_and_saturated_ordinals_cannot_replace_missing_records ;;
    CallOverlap) name=protocol::history::tests::link_checker_rejects_overlapping_calls_with_complete_unique_coverage ;;
    CallCoverage) name=protocol::history::tests::link_checker_rejects_lost_polls_cycles_and_reused_publications ;;
    CallPreparation|ResetEvidence) name=pending_siblings_can_share_the_reset_published_by_the_first_completed_send ;;
    DeliveryProducerOrder|DeliveryEdgeOrder) name=protocol::delivery::tests::the_order_certificate_must_preserve_both_producer_and_delivery_edges ;;
    DeliveryAmbiguity|DeliveryCoverage) name=protocol::delivery::tests::missing_reused_or_unordered_producer_evidence_cannot_supply_a_receive ;;
    SourceOrder) name=later_publication_cannot_hide_an_acceptance_before_its_source_predecessor ;;
    ResumptionAdmission) name=only_a_committed_resumed_body_delays_the_outgoing_continuation ;;
    InvocationContext) name=reusing_a_proof_dag_does_not_share_a_resumption_entry_across_invocations ;;
    PollAdmission) name=source_order_is_checked_before_a_pending_transport_send_can_expose_its_frame ;;
    ConstructorValidation) name=a_committed_route_selection_cannot_name_an_unselected_query_occurrence ;;
    AcceptanceEvidence) name=an_observed_send_poll_can_end_in_a_transport_error_without_a_commit ;;
    ConstructorOrder) name=causal_order_search_matches_every_interleaving_and_rejects_an_early_reply ;;
    SplitInsertion|SplitBoundary) name=protocol::unfolding::tests::structural_splits_match_full_cut_enumeration_across_all_unfolding_constructors ;;
    ScopeLookup) name=protocol::index_tests::retained_scope_index_matches_exhaustive_marker_lookup ;;
    HeadPrefix) name=compiled_scope_nesting_preserves_sequence_parallel_and_choice ;;
    BranchDemand) name=protocol::unfolding::generate::tests::branch_demands_add_while_sequence_parallel_and_nested_roll_share_visits ;;
    TypedArmSeed) name=protocol::audit::tests::typed_operations_seed_distinct_branch_visits_before_later_offer_evidence ;;
    InsertionPrune) name=protocol::word::tests::prerequisite_factoring_matches_the_unfactored_rule_for_every_point_subset ;;
    ResolverEvidence) name=automatic_audit_checks_resolver_calls_from_outgoing_offers_in_each_visit ;;
    QuerySelection|QueryDecision) name=cancelled_resolved_send_can_retry_the_other_arm_before_any_commit ;;
    QueryFinished) name=cancelled_offer_records_a_decision_without_consuming_the_source_operation ;;
    CommittedSelection) name=a_committed_route_selection_cannot_name_an_unselected_query_occurrence ;;
  esac
  grep -Fxq "test $name ... FAILED" "$out/$mutation.log"
  find "$source/target" -type f -perm -100 -exec shasum -a 256 -- {} + > "$out/$mutation-binaries.sha256"
  printf 'mutation=%s\nexit=%s\n' "$mutation" "$status" > "$out/$mutation-result.txt"
  rm -r -- "$source"
done
echo "History sensitivity: twenty-nine prefix, call, delivery, source-execution, index, construction, resolver-evidence and cancelled-query defects fail their regressions"
