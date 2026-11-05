use hibana::runtime::resolver::{DecisionArm, ResolverError, ResolverRef};
use hibana::runtime::tap::{TRANSPORT_MISMATCH, TRANSPORT_MISMATCH_SESSION, TapEvent};
use hibana_epf::{
    CompactOutRecord, EVIDENCE_SCHEMA_HASH, Epf, EpfStorage, Header, ImageIngress,
    ImageIngressStatus, ImageSpec, TapSpool, Target, compute_hash,
};

fn encode_image(target: Target, code: &[u8], out: &mut [u8]) -> usize {
    encode_image_with_fuel(target, code, 32, out)
}

fn encode_image_with_fuel(target: Target, code: &[u8], fuel_max: u16, out: &mut [u8]) -> usize {
    let header = Header {
        abi: Header::ABI,
        target,
        schema_hash: EVIDENCE_SCHEMA_HASH,
        code_len: code.len() as u16,
        fuel_max,
        mem_len: 0,
        code_hash: compute_hash(code),
    };
    let mut header_bytes = [0u8; Header::SIZE];
    header.encode_into(&mut header_bytes);
    out[..Header::SIZE].copy_from_slice(&header_bytes);
    out[Header::SIZE..Header::SIZE + code.len()].copy_from_slice(code);
    Header::SIZE + code.len()
}

fn mismatch_event() -> TapEvent {
    TapEvent::from([
        0, 0, 0, 1, 0x02, 0x05, 0, 1, 0x28, 0xfa, 0x7a, 0x4d, 0x39, 0xeb, 0x7a, 0x4d,
    ])
}

fn mismatch_event_on_lane(expected_lane: u8) -> TapEvent {
    let mut record: [u8; 16] = mismatch_event().into();
    record[6] = expected_lane;
    TapEvent::from(record)
}

fn feed_envelope<const N: usize>(ingress: &mut ImageIngress<N>, image: &[u8]) {
    let len = image.len() as u16;
    let hash = compute_hash(image);
    let mut header = [0u8; 10];
    header[0..4].copy_from_slice(&ImageIngress::<N>::MAGIC);
    header[4..6].copy_from_slice(&len.to_le_bytes());
    header[6..10].copy_from_slice(&hash.to_le_bytes());
    for byte in header {
        assert_eq!(ingress.push(byte), ImageIngressStatus::Pending);
    }
    let mut status = ImageIngressStatus::Pending;
    for byte in image {
        status = ingress.push(*byte);
    }
    assert_eq!(
        status,
        ImageIngressStatus::Ready {
            len: image.len(),
            hash
        }
    );
}

#[test]
fn production_epf_runs_loaded_observe_bytecode_from_tap_event() {
    let code = [
        0x12, 0x03, 0x01, 0x00, 0x05,
        0x02, // require input[3] == transport mismatch/session mismatch
        0x11, 0x00, 0x01, 0x00, 0x00, 0x00, // r0 = report kind
        0x11, 0x01, 0x01, 0x00, 0x00, 0x00, // r1 = reason
        0x10, 0x02, 0x00, // r2 = expected session
        0x10, 0x03, 0x01, // r3 = observed session
        0x10, 0x04, 0x03, // r4 = typed transport tag
        0x20, 0x00, 0x01, 0x02, 0x03, 0x04, // emit r0,r1,r2,r3,r4
        0xff,
    ];
    let mut image = [0u8; 64];
    let len = encode_image(Target::Observe, &code, &mut image);
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);

    let loaded = epf.load(&image[..len]).expect("observe image loads");
    let out = epf.run(mismatch_event());

    assert_eq!(loaded.target(), Target::Observe);
    assert_eq!(out.epoch(), loaded.epoch());
    assert_eq!(out.kind(), 1);
    assert_eq!(out.reason(), 1);
    assert_eq!(out.arg0(), 0x28fa_7a4d);
    assert_eq!(out.arg1(), 0x39eb_7a4d);
    assert_eq!(out.arg2(), 0x0205_0001);
    assert_eq!(out.fuel_used(), 7);
}

#[test]
fn loaded_observe_preserves_commit_fields_and_the_ring_ordinal() {
    let event = TapEvent::from([
        0x10, 0x20, 0x30, 0x40, 0x02, 0x02, 0x81, 1, 0x03, 0x10, 0x20, 0x30, 6, 0x7f, 0x12, 0x34,
    ]);
    let code = [
        0x11, 0, 1, 0, 0, 0, // kind
        0x11, 1, 0, 0, 0, 0, // reason
        0x10, 2, 0, // session
        0x10, 3, 1, // view, lane and full source-event identity
        0x10, 4, 2, // ring ordinal
        0x20, 0, 1, 2, 3, 4, 0xff,
    ];
    let mut image = [0; 64];
    let len = encode_image(Target::Observe, &code, &mut image);
    let mut storage = EpfStorage::<0, 64>::new();
    let epf = Epf::new(&mut storage);
    epf.load(&image[..len]).unwrap();
    let out = epf.run(event);
    assert_eq!(out.arg0(), 0x0310_2030);
    assert_eq!(out.arg1(), 0x067f_1234);
    assert_eq!(out.arg2(), 0x1020_3040);
    assert_eq!(
        hibana_epf::EvidenceInput::from_tap_event(event).words()[3],
        0x8101
    );
}

#[test]
fn an_image_for_a_different_evidence_layout_cannot_replace_the_current_image() {
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let mut image = [0; 64];
    let len = ImageSpec::ObserveEcho.write(&mut image).unwrap();
    let loaded = epf.load(&image[..len]).unwrap();
    for schema in [0x4845_0001u32, 0x4845_0002, 0x4845_0003] {
        image[16..20].copy_from_slice(&schema.to_le_bytes());
        assert!(matches!(
            epf.load(&image[..len]),
            Err(hibana_epf::Error::Verify(hibana_epf::VerifyError::SchemaMismatch {
                expected: EVIDENCE_SCHEMA_HASH,
                found,
            })) if found == schema
        ));
        let observed = epf.run(mismatch_event());
        assert_eq!(observed.epoch(), loaded.epoch());
        assert_eq!(observed.kind(), u32::from(TRANSPORT_MISMATCH));
        assert_eq!(observed.arg0(), 0x28fa_7a4d);
    }
}

#[test]
fn production_default_observe_vm_is_available_without_loaded_image() {
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);

    let out = epf.run(mismatch_event());

    assert_eq!(out.kind(), TRANSPORT_MISMATCH as u32);
    assert_eq!(out.reason(), TRANSPORT_MISMATCH_SESSION as u32);
    assert_eq!(out.arg0(), 0x28fa_7a4d);
    assert_eq!(out.fuel_used(), 6);
}

#[test]
fn production_image_ingress_loads_generic_envelope_without_uart_code() {
    let code = [
        0x11, 0x00, 0x07, 0x00, 0x00, 0x00, // r0 = report kind
        0x11, 0x01, 0x09, 0x00, 0x00, 0x00, // r1 = reason
        0x10, 0x02, 0x00, // r2 = expected session
        0x20, 0x00, 0x01, 0x02, 0x02, 0x02, // emit
        0xff,
    ];
    let mut image = [0u8; 64];
    let len = encode_image(Target::Observe, &code, &mut image);
    let mut ingress = ImageIngress::<64>::new();
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);

    feed_envelope(&mut ingress, &image[..len]);

    let loaded = epf
        .load_ingress(&mut ingress)
        .expect("ingress load result")
        .expect("ready ingress loads");
    let out = epf.run(mismatch_event());

    assert_eq!(loaded.target(), Target::Observe);
    assert!(!ingress.is_ready());
    assert_eq!(out.kind(), 7);
    assert_eq!(out.reason(), 9);
    assert_eq!(out.arg0(), 0x28fa_7a4d);
}

#[test]
fn production_tap_spool_replays_retained_events_after_image_load() {
    let code = [
        0x12, 0x03, 0x01, 0x00, 0x05, 0x02, // require mismatch/session
        0x11, 0x00, 0x33, 0x00, 0x00, 0x00, // r0 = report kind
        0x10, 0x01, 0x00, // r1 = expected session
        0x20, 0x00, 0x00, 0x01, 0x01, 0x01,
    ];
    let mut image = [0u8; 64];
    let len = encode_image(Target::Observe, &code, &mut image);
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let mut spool = TapSpool::<2>::new();

    spool.push(mismatch_event()).expect("retain first event");
    assert_eq!(spool.len(), 1);

    epf.load(&image[..len]).expect("observe image loads");
    let out = epf.run_spool(&mut spool).expect("spooled event emits");

    assert_eq!(out.kind(), 0x33);
    assert_eq!(out.arg0(), 0x28fa_7a4d);
    assert_eq!(spool.pending(), 0);
}

#[test]
fn production_compact_out_record_roundtrips_without_device_io() {
    let out = hibana_epf::Out::emit((Target::Policy(57), 3), [1, 2, 3, 4, 5], 6);
    let record = CompactOutRecord::from_out(1, out);
    let mut encoded = [0u8; CompactOutRecord::SIZE];

    record.encode(&mut encoded);
    let decoded = CompactOutRecord::decode(&encoded).expect("decode compact out");

    assert_eq!(decoded, record);
    assert_eq!(&encoded[0..4], b"HEPO");
    assert_eq!(decoded.site, 1);
    assert_eq!(decoded.target, Target::Policy(57));
    assert_eq!(decoded.kind, 1);
    assert_eq!(decoded.fuel_used, 6);
}

#[test]
fn production_tap_event_record_roundtrips_hibana_physical_record() {
    let event = mismatch_event();
    let encoded: [u8; 16] = event.into();
    let decoded = TapEvent::from(encoded);

    assert_eq!(decoded, event);
    assert_eq!(&encoded[0..4], &event.ts().to_be_bytes());
    assert_eq!(&encoded[4..6], &event.id().to_be_bytes());
}

#[test]
fn production_image_spec_observe_echo_builds_loadable_image() {
    let mut image = [0u8; 64];
    let len = ImageSpec::ObserveEcho
        .write(&mut image)
        .expect("build observe image");
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);

    let load = epf.load(&image[..len]).expect("load observe image");
    let out = epf.run(mismatch_event());

    assert_eq!(load.target(), Target::Observe);
    assert_eq!(out.kind(), TRANSPORT_MISMATCH as u32);
    assert_eq!(out.reason(), TRANSPORT_MISMATCH_SESSION as u32);
    assert_eq!(out.arg0(), 0x28fa_7a4d);
}

#[test]
fn production_image_spec_observe_session_mismatch_is_named_debug_recipe() {
    let mut image = [0u8; 64];
    let len = ImageSpec::ObserveSessionMismatch
        .write(&mut image)
        .expect("build session mismatch image");
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);

    epf.load(&image[..len]).expect("load observe image");
    let out = epf.run(mismatch_event_on_lane(7));

    assert_eq!(out.kind(), 1);
    assert_eq!(out.reason(), TRANSPORT_MISMATCH_SESSION as u32);
    assert_eq!(out.arg0(), 0x28fa_7a4d);
    assert_eq!(out.arg1(), 0x39eb_7a4d);
    assert_eq!(out.arg2(), 0x0205_0701);
}

#[test]
fn production_image_spec_policy_choose_on_input_is_loadable_resolver_policy() {
    let mut image = [0u8; 64];
    let len = ImageSpec::PolicyChooseOnInput {
        policy_id: 7,
        input: 0,
        value: 0x28fa_7a4d,
        arm: 1,
    }
    .write(&mut image)
    .expect("build policy image");
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let resolver = epf
        .resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .unwrap();

    epf.run(mismatch_event());
    epf.load(&image[..len]).expect("load policy image");

    assert_eq!(resolver.decide(), Ok(DecisionArm::Right));
    let mut different: [u8; 16] = mismatch_event().into();
    different[11] ^= 1;
    epf.run(TapEvent::from(different));
    assert!(
        resolver.decide().is_err(),
        "a nonmatching active policy must reject rather than use its fallback"
    );
}

fn fallback_left() -> Result<DecisionArm, ResolverError> {
    Ok(DecisionArm::Left)
}

#[test]
fn resolver_configuration_reports_exhausted_capacity_without_reserving_a_policy_id() {
    let mut empty_storage = EpfStorage::<0, 64>::new();
    let empty = Epf::new(&mut empty_storage);
    assert!(matches!(
        empty.resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left())),
        Err(hibana_epf::Error::PolicySlotUnavailable { policy_id: 7 })
    ));
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let resolver = epf
        .resolver::<{ u16::MAX }>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .expect("Hibana permits every u16 resolver identifier");
    assert_eq!(resolver.decide(), Ok(DecisionArm::Left));
    assert!(
        epf.resolver::<{ u16::MAX }>(ResolverRef::decision_state(&(), |_| fallback_left()))
            .is_ok(),
        "registering the same identifier must reuse its slot"
    );
    assert!(matches!(
        epf.resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left())),
        Err(hibana_epf::Error::PolicySlotUnavailable { policy_id: 7 })
    ));
}

#[test]
fn a_resolver_callback_can_observe_the_appliance_after_its_storage_borrow_ends() {
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let fallback = ResolverRef::<7>::decision_state(&epf, |epf| {
        let observed = epf.run(mismatch_event());
        assert_eq!(observed.kind(), u32::from(TRANSPORT_MISMATCH));
        assert_eq!(observed.arg2(), 0x0205_0001);
        Ok(DecisionArm::Left)
    });
    let resolver = epf.resolver::<7>(fallback).unwrap();
    assert_eq!(resolver.decide(), Ok(DecisionArm::Left));
}

#[test]
fn production_policy_resolver_uses_fallback_until_policy_image_is_loaded() {
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let resolver = epf
        .resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .unwrap();

    assert_eq!(resolver.decide(), Ok(DecisionArm::Left));
}

#[test]
fn production_policy_resolver_runs_loaded_policy_vm_and_ignores_fallback() {
    let code = [
        0x11, 0x00, 0x01, 0x00, 0x00, 0x00, // r0 = Choose
        0x11, 0x01, 0x00, 0x00, 0x00, 0x00, // r1 = reason
        0x11, 0x02, 0x01, 0x00, 0x00, 0x00, // r2 = Right arm
        0x20, 0x00, 0x01, 0x02, 0x01, 0x01, // emit kind, reason, arg0
        0xff,
    ];
    let mut image = [0u8; 64];
    let len = encode_image(Target::Policy(7), &code, &mut image);
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let resolver = epf
        .resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .unwrap();

    let loaded = epf.load(&image[..len]).expect("policy image loads");

    assert_eq!(loaded.target(), Target::Policy(7));
    assert_eq!(resolver.decide(), Ok(DecisionArm::Right));
}

#[test]
fn production_policy_resolver_unload_restores_fallback() {
    let code = [
        0x11, 0x00, 0x01, 0x00, 0x00, 0x00, // r0 = Choose
        0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x11, 0x02, 0x01, 0x00, 0x00,
        0x00, // r2 = Right arm
        0x20, 0x00, 0x01, 0x02, 0x01, 0x01, 0xff,
    ];
    let mut image = [0u8; 64];
    let len = encode_image(Target::Policy(7), &code, &mut image);
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let resolver = epf
        .resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .unwrap();

    epf.load(&image[..len]).expect("policy image loads");
    epf.unload(Target::Policy(7)).expect("policy unloads");

    assert_eq!(resolver.decide(), Ok(DecisionArm::Left));
}

#[test]
fn production_policy_vm_trap_fails_closed_without_silent_fallback() {
    let code = [
        0x11, 0x00, 0x01, 0x00, 0x00, 0x00, // valid first instruction, then fuel exhausts
        0xff,
    ];
    let mut image = [0u8; 64];
    let len = encode_image_with_fuel(Target::Policy(7), &code, 1, &mut image);
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let resolver = epf
        .resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .unwrap();

    epf.load(&image[..len]).expect("policy image loads");

    assert!(resolver.decide().is_err());
}

#[test]
fn production_policy_image_preserves_the_largest_resolver_identifier() {
    let mut image = [0u8; 64];
    let len = ImageSpec::PolicyChoose {
        policy_id: u16::MAX,
        arm: 1,
    }
    .write(&mut image)
    .unwrap();
    let mut storage = EpfStorage::<2, 64>::new();
    let epf = Epf::new(&mut storage);

    let resolver = epf
        .resolver::<{ u16::MAX }>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .unwrap();
    let zero = epf
        .resolver::<0>(ResolverRef::decision_state(&(), |_| Ok(DecisionArm::Right)))
        .unwrap();
    let mut other_image = [0u8; 64];
    let other_len = ImageSpec::PolicyChoose {
        policy_id: 0,
        arm: 0,
    }
    .write(&mut other_image)
    .unwrap();
    epf.load(&other_image[..other_len]).unwrap();
    let loaded = epf.load(&image[..len]).unwrap();
    assert_eq!(loaded.target(), Target::Policy(u16::MAX));
    assert_eq!(resolver.decide(), Ok(DecisionArm::Right));
    assert_eq!(zero.decide(), Ok(DecisionArm::Left));

    let len = ImageSpec::PolicyChoose {
        policy_id: u16::MAX,
        arm: 0,
    }
    .write(&mut image)
    .unwrap();
    epf.load(&image[..len]).unwrap();
    assert_eq!(resolver.decide(), Ok(DecisionArm::Left));
    epf.revert(Target::Policy(u16::MAX)).unwrap();
    assert_eq!(resolver.decide(), Ok(DecisionArm::Right));
    epf.unload(Target::Policy(u16::MAX)).unwrap();
    assert_eq!(resolver.decide(), Ok(DecisionArm::Left));
    assert_eq!(zero.decide(), Ok(DecisionArm::Left));
}

#[cfg(not(miri))]
#[test]
fn target_encoding_preserves_every_u16_resolver_identifier() {
    for policy_id in 0..=u16::MAX {
        let target = Target::Policy(policy_id);
        let (kind, encoded) = target.encode();
        assert_eq!(Target::decode(kind, encoded), Ok(target));
    }
    assert_eq!(Target::decode(0, 0), Ok(Target::Observe));
    assert!(Target::decode(0, 1).is_err());
    assert!(Target::decode(2, 0).is_err());
}

#[test]
fn production_policy_invalid_arm_output_fails_closed() {
    let code = [
        0x11, 0x00, 0x01, 0x00, 0x00, 0x00, // r0 = Choose
        0x11, 0x01, 0x00, 0x00, 0x00, 0x00, // r1 = reason
        0x11, 0x02, 0x02, 0x00, 0x00, 0x00, // r2 = invalid arm
        0x20, 0x00, 0x01, 0x02, 0x01, 0x01, // emit kind, reason, arg0
        0xff,
    ];
    let mut image = [0u8; 64];
    let len = encode_image(Target::Policy(7), &code, &mut image);
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    let resolver = epf
        .resolver::<7>(ResolverRef::decision_state(&(), |_| fallback_left()))
        .unwrap();

    epf.load(&image[..len]).expect("policy image loads");

    assert!(resolver.decide().is_err());
}

#[test]
fn unsupported_image_memory_is_rejected_without_replacing_the_active_filter() {
    let mut storage = EpfStorage::<0, 64>::new();
    let epf = Epf::new(&mut storage);
    let mut image = [0; 64];
    let len = ImageSpec::ObserveSessionMismatch.write(&mut image).unwrap();
    epf.load(&image[..len]).unwrap();
    let before = epf.run(mismatch_event());
    image[14] = 1;
    assert!(matches!(
        epf.load(&image[..len]),
        Err(hibana_epf::Error::Verify(
            hibana_epf::VerifyError::UnsupportedMemory { bytes: 1 }
        ))
    ));
    assert_eq!(epf.run(mismatch_event()), before);
}

#[test]
fn rejected_policy_image_does_not_reserve_a_configuration_slot() {
    let mut image = [0; 128];
    let len = encode_image(Target::Policy(9), &[0xff; 65], &mut image);
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    assert_eq!(
        epf.load(&image[..len]),
        Err(hibana_epf::Error::ImageTooLarge {
            requested: len,
            capacity: 64,
        })
    );
    let fallback = ResolverRef::<7>::decision_state(&(), |_| Ok(DecisionArm::Right));
    let resolver = epf
        .resolver::<7>(fallback)
        .expect("failed load consumed the only slot");
    assert_eq!(resolver.decide().unwrap(), DecisionArm::Right);
}

#[test]
fn unloading_an_absent_policy_does_not_reserve_a_configuration_slot() {
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    assert_eq!(
        epf.unload(Target::Policy(9)),
        Err(hibana_epf::Error::NoImage {
            target: Target::Policy(9)
        })
    );
    let fallback = ResolverRef::<7>::decision_state(&(), |_| Ok(DecisionArm::Right));
    let resolver = epf
        .resolver::<7>(fallback)
        .expect("failed unload consumed the only slot");
    assert_eq!(resolver.decide().unwrap(), DecisionArm::Right);
}

#[test]
fn reverting_an_absent_policy_does_not_reserve_a_configuration_slot() {
    let mut storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut storage);
    assert_eq!(
        epf.revert(Target::Policy(9)),
        Err(hibana_epf::Error::NoPrevious {
            target: Target::Policy(9)
        })
    );
    let fallback = ResolverRef::<7>::decision_state(&(), |_| Ok(DecisionArm::Right));
    let resolver = epf
        .resolver::<7>(fallback)
        .expect("failed revert consumed the only slot");
    assert_eq!(resolver.decide().unwrap(), DecisionArm::Right);
}
