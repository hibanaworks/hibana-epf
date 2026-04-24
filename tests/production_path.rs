use hibana::substrate::{
    policy::{ContextValue, PolicyAttrs, core as policy_core},
    tap::TapEvent,
};
use hibana_epf::{
    Action, ENGINE_FAIL_CLOSED, Header, HostSlots, ScratchLease, host::HostError,
    loader::ImageLoader, run_with, vm::Slot,
};

fn header_for(code: &[u8], mem_len: u16) -> Header {
    Header {
        code_len: code.len() as u16,
        fuel_max: 8,
        mem_len,
        hash: hibana_epf::verifier::compute_hash(code),
    }
}

fn queue_depth_attrs(queue_depth: u32) -> PolicyAttrs {
    let mut attrs = PolicyAttrs::new();
    assert!(
        attrs.insert(
            policy_core::QUEUE_DEPTH,
            ContextValue::from_u32(queue_depth),
        ),
        "queue depth attr must fit in PolicyAttrs"
    );
    attrs
}

#[test]
fn production_run_with_executes_route_program_from_policy_input() {
    let code = [0x4B, 0x00, 0x00, 0x33, 0x00];
    let header = header_for(&code, 16);
    let mut loader = ImageLoader::new();
    loader.begin(header).expect("begin");
    loader.write(0, &code).expect("write");
    let verified = loader.commit_for_slot(Slot::Route).expect("verify");

    let mut slots = HostSlots::new();
    let mut scratch = [0u8; 16];
    slots
        .install_verified(Slot::Route, verified, ScratchLease::new(&mut scratch))
        .expect("install");

    static EVENT: TapEvent = TapEvent::zero();
    let action = run_with(&slots, Slot::Route, &EVENT, None, None, |ctx| {
        ctx.set_policy_input([1, 0, 0, 0])
    });
    assert_eq!(action, Action::Route { arm: 1 });
}

#[test]
fn production_run_with_executes_route_program_from_policy_attrs() {
    let code = [0x41, 0x00, 0x33, 0x00];
    let header = header_for(&code, 16);
    let mut loader = ImageLoader::new();
    loader.begin(header).expect("begin");
    loader.write(0, &code).expect("write");
    let verified = loader.commit_for_slot(Slot::Route).expect("verify");

    let mut slots = HostSlots::new();
    let mut scratch = [0u8; 16];
    slots
        .install_verified(Slot::Route, verified, ScratchLease::new(&mut scratch))
        .expect("install");

    static EVENT: TapEvent = TapEvent::zero();
    let action = run_with(&slots, Slot::Route, &EVENT, None, None, |ctx| {
        ctx.set_policy_attrs(queue_depth_attrs(1))
    });
    assert_eq!(action, Action::Route { arm: 1 });
}

#[test]
fn production_install_owns_active_code_and_allows_loader_reuse() {
    let active_code = [0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0x00];
    let staged_code = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00];

    let mut loader = ImageLoader::new();
    loader
        .begin(header_for(&active_code, 16))
        .expect("begin active");
    loader.write(0, &active_code).expect("write active");
    let active = loader.commit_for_slot(Slot::Route).expect("verify active");

    let mut slots = HostSlots::new();
    let mut scratch_buf = [0u8; 16];
    slots
        .install_verified(Slot::Route, active, ScratchLease::new(&mut scratch_buf))
        .expect("install active");

    loader
        .begin(header_for(&staged_code, 16))
        .expect("begin staged");
    loader.write(0, &staged_code).expect("write staged");
    let staged = loader.commit_for_slot(Slot::Route).expect("verify staged");

    static EVENT: TapEvent = TapEvent::zero();
    let still_active = run_with(&slots, Slot::Route, &EVENT, None, None, |_| {});
    assert_eq!(still_active, Action::Route { arm: 1 });

    let scratch = slots.uninstall(Slot::Route).expect("uninstall active");
    slots
        .install_verified(Slot::Route, staged, scratch)
        .expect("reinstall staged");

    let replaced = run_with(&slots, Slot::Route, &EVENT, None, None, |_| {});
    assert_eq!(replaced, Action::Route { arm: 0 });
}

#[test]
fn production_failed_install_returns_scratch_for_retry() {
    let oversized_code = [0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x33, 0x00];
    let retry_code = [0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0x00];

    let mut loader = ImageLoader::new();
    loader
        .begin(header_for(&oversized_code, 32))
        .expect("begin oversized");
    loader.write(0, &oversized_code).expect("write oversized");
    let oversized = loader
        .commit_for_slot(Slot::Route)
        .expect("verify oversized");

    let mut slots = HostSlots::new();
    let mut scratch_buf = [0u8; 16];
    let err = slots
        .install_verified(Slot::Route, oversized, ScratchLease::new(&mut scratch_buf))
        .unwrap_err();
    let error = err.error();
    let scratch = err.into_scratch();
    assert!(matches!(
        error,
        HostError::ScratchTooSmall {
            requested: 32,
            available: 16
        }
    ));

    loader
        .begin(header_for(&retry_code, 16))
        .expect("begin retry");
    loader.write(0, &retry_code).expect("write retry");
    let retry = loader.commit_for_slot(Slot::Route).expect("verify retry");
    slots
        .install_verified(Slot::Route, retry, scratch)
        .expect("retry install");

    static EVENT: TapEvent = TapEvent::zero();
    let action = run_with(&slots, Slot::Route, &EVENT, None, None, |_| {});
    assert_eq!(action, Action::Route { arm: 1 });
}

#[test]
fn production_run_with_rejects_non_binary_route_arm() {
    let code = [0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x33, 0x00];
    let mut loader = ImageLoader::new();
    loader.begin(header_for(&code, 16)).expect("begin");
    loader.write(0, &code).expect("write");
    let verified = loader.commit_for_slot(Slot::Route).expect("verify");

    let mut slots = HostSlots::new();
    let mut scratch = [0u8; 16];
    slots
        .install_verified(Slot::Route, verified, ScratchLease::new(&mut scratch))
        .expect("install");

    static EVENT: TapEvent = TapEvent::zero();
    let action = run_with(&slots, Slot::Route, &EVENT, None, None, |_| {});
    assert!(matches!(
        action,
        Action::Abort(info) if info.reason == ENGINE_FAIL_CLOSED && info.trap.is_none()
    ));
}

#[test]
fn production_empty_slot_fails_closed() {
    let slots = HostSlots::new();
    static EVENT: TapEvent = TapEvent::zero();
    let action = run_with(&slots, Slot::Route, &EVENT, None, None, |_| {});
    assert!(matches!(
        action,
        Action::Abort(info) if info.reason == ENGINE_FAIL_CLOSED && info.trap.is_none()
    ));
}
