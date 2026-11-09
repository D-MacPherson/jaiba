//! Native discovery regressions. Fake enumeration/serial I/O, real policy.
use super::{TOKEN, db};
use challenge_response::{
    ChallengeResponse,
    error::ChallengeResponseError as Error,
    operation::{Cancellation, Operation},
    test_support::{Discovery, SerialRead as Read, backend_discovery},
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

// 0/1 list all; 2/3 explicitly select; 4 is the actual application key builder.
// No selection algorithm is reproduced here: all routes enter production code.
fn discover(route: usize) -> Result<(), String> {
    let mut native = ChallengeResponse::new().unwrap();
    match route {
        0 => native
            .find_all_devices()
            .map(|_| ())
            .map_err(|e| e.to_string()),
        1 => backend_discovery(None)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        2 => native
            .find_device_from_serial(TOKEN.serial)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        3 => backend_discovery(Some(TOKEN.serial))
            .map(|_| ())
            .map_err(|e| e.to_string()),
        4 => db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN))
            .map(|_| ())
            .map_err(|e| format!("{e:#}")),
        _ => unreachable!(),
    }
}

#[test]
fn authorized_policy_selects_either_present_serial_and_lowest_when_both_present() {
    use crate::config::YubikeyPolicy;
    for (serials, expected) in [
        (vec![39269826], 39269826),
        (vec![39269828], 39269828),
        (vec![39269828, 39269826], 39269826),
        (vec![39269826, 39269828], 39269826),
        (vec![123, 39269828], 39269828),
    ] {
        let _io = Discovery::new(serials.into_iter().map(Read::Serial).collect());
        let key = db::build_database_key_with_policy(
            "synthetic master",
            None,
            Some(YubikeyPolicy {
                slot: 2,
                serials: vec![39269828, 39269826],
            }),
        )
        .unwrap();
        assert!(
            format!("{key:?}").contains(&expected.to_string()),
            "concrete serial must be retained"
        );
    }
}

#[test]
fn physical_claim_lives_until_outer_operation_not_key_construction() {
    use challenge_response::test_support::{Event, Sessions};
    let io = Sessions::new(vec![Read::Serial(TOKEN.serial)]);
    let operation = Operation::standard();
    let key = db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN)).unwrap();
    assert_eq!(
        io.events(),
        vec![Event::Open(0), Event::Serial(0)],
        "serial read must use the retained physical handle"
    );
    drop(operation);
    assert_eq!(
        io.events(),
        vec![Event::Open(0), Event::Serial(0), Event::Close(0)]
    );
    drop(key); // the retained key must not keep USB claims alive
}

#[test]
fn nested_kdbx_challenges_reuse_the_same_opened_physical_session() {
    use challenge_response::test_support::{Event, Sessions};
    let io = Sessions::new(vec![Read::Serial(TOKEN.serial)]);
    let operation = Operation::standard();
    let key = db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN)).unwrap();
    let mut bytes = Vec::new();
    keepass::Database::new()
        .save(&mut bytes, key.clone())
        .unwrap();
    keepass::Database::open(&mut std::io::Cursor::new(&bytes), key.clone()).unwrap();
    assert_eq!(
        io.events(),
        vec![
            Event::Open(0),
            Event::Serial(0),
            Event::Hmac(0),
            Event::Hmac(0)
        ]
    );
    drop(operation);
    assert_eq!(io.events().last(), Some(&Event::Close(0)));
}

#[test]
fn keepass_direct_challenge_pins_serial_read_and_hmac_without_an_app_wrapper() {
    use challenge_response::test_support::{Event, Sessions};
    let io = Sessions::new(vec![Read::Serial(TOKEN.serial)]);
    let key = db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN)).unwrap();
    let before = io.events().len();
    keepass::Database::new().save(&mut Vec::new(), key).unwrap();
    assert_eq!(
        &io.events()[before..],
        &[
            Event::Open(0),
            Event::Serial(0),
            Event::Hmac(0),
            Event::Close(0)
        ],
        "the library adapter must own an enclosing scope even without Jaiba's outer handler"
    );
}

#[test]
fn native_open_diagnostics_retain_access_and_unsupported_distinctions() {
    let error = challenge_response::test_support::discovery_open_failure(true).unwrap_err();
    assert!(
        matches!(error, Error::IOError(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{error}"
    );
    let error = challenge_response::test_support::discovery_open_failure(false).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Unsupported OTP interface layout"),
        "{error}"
    );
}

#[test]
fn ordinary_failures_before_and_after_target_use_same_policy_in_both_entrypoints() {
    for failure in [Read::Denied, Read::Busy, Read::Gone, Read::Unsupported] {
        for position in [0, 2] {
            let mut reads = vec![Read::Serial(7), Read::Serial(TOKEN.serial), Read::Serial(8)];
            reads[position] = failure.clone();
            let _io = Discovery::new(reads);
            for route in 0..5 {
                discover(route).unwrap();
            }
            let mut native = ChallengeResponse::new().unwrap();
            let all = native.find_all_devices().unwrap();
            assert_eq!(all.len(), 3);
            assert_eq!(all.iter().filter(|d| d.serial.is_none()).count(), 1);
            let selected = native.find_device_from_serial(TOKEN.serial).unwrap();
            assert_eq!(selected.serial, Some(TOKEN.serial));
            assert_eq!(
                selected.address_id, 1,
                "must not select arbitrary first readable token"
            );
        }
    }
}

#[test]
fn no_matching_serial_with_unreadable_candidates_is_not_reported_missing() {
    for (failure, diagnostic) in [
        (Read::Denied, "synthetic serial access denied"),
        (Read::Busy, "synthetic serial busy"),
        (Read::Gone, "synthetic serial disconnected"),
        (Read::Unsupported, "Unsupported OTP interface layout"),
    ] {
        for position in [0, 1] {
            let mut reads = vec![Read::Serial(7), Read::Serial(8)];
            reads[position] = failure.clone();
            let _io = Discovery::new(reads);
            for route in 2..5 {
                let error = discover(route).unwrap_err();
                assert!(error.contains(diagnostic), "route {route}: {error}");
                assert!(!error.contains("Device not found"), "{error}");
            }
            assert!(discover(0).is_ok() && discover(1).is_ok());
        }
    }
}

#[test]
fn failed_single_pass_discovery_never_rescans_a_changed_device() {
    let next = std::rc::Rc::new(std::cell::Cell::new(0));
    let _io = Discovery::new(vec![Read::Sequence(
        next,
        vec![Read::Denied, Read::Serial(TOKEN.serial)],
    )]);
    let error = discover(4).unwrap_err();
    assert!(error.contains("synthetic serial access denied"), "{error}");
}

#[test]
fn truly_absent_serial_never_falls_back_to_another_readable_token() {
    for reads in [
        vec![],
        vec![Read::Serial(7)],
        vec![Read::Serial(7), Read::Serial(8)],
    ] {
        let _io = Discovery::new(reads);
        for route in 2..5 {
            let error = discover(route).unwrap_err();
            assert!(error.contains("Device not found"), "route {route}: {error}");
        }
        assert!(discover(0).is_ok() && discover(1).is_ok());
    }
}

#[test]
fn cancellation_and_deadline_errors_are_fatal_at_every_observed_position() {
    for (failure, diagnostic) in [
        (Read::Cancelled, "cancelled"),
        (Read::Deadline, "deadline exceeded"),
    ] {
        for position in 0..3 {
            for route in 0..5 {
                let mut reads = vec![Read::Serial(7), Read::Serial(TOKEN.serial), Read::Serial(8)];
                reads[position] = failure.clone();
                let _io = Discovery::new(reads);
                let result = discover(route);
                // Explicit serial discovery stops at its match. All-list and
                // the app's KeePass initial selection must still inspect later devices.
                if (route == 2 || route == 3) && position == 2 {
                    result.unwrap();
                } else {
                    let error = result.unwrap_err();
                    assert!(
                        error.contains(diagnostic),
                        "route {route}, position {position}: {error}"
                    );
                }
            }
        }
    }
}

#[test]
fn enumeration_failure_inside_serial_io_is_global_even_after_a_match() {
    for route in 0..5 {
        for position in 0..3 {
            let mut reads = vec![Read::Serial(7), Read::Serial(TOKEN.serial), Read::Serial(8)];
            reads[position] = Read::EnumerationFailure;
            let _io = Discovery::new(reads);
            if (route == 2 || route == 3) && position == 2 {
                discover(route).unwrap();
            } else {
                let error = discover(route).unwrap_err();
                assert!(
                    error.contains("Could not list available devices"),
                    "route {route}, position {position}: {error}"
                );
            }
        }
    }
}

#[test]
fn global_enumeration_failure_is_fatal_not_a_per_device_error() {
    for (failure, diagnostic) in [
        (Read::Denied, "access denied"),
        (Read::Cancelled, "cancelled"),
        (Read::Deadline, "deadline exceeded"),
    ] {
        for route in 0..5 {
            let _io = Discovery::with_enumeration(
                vec![Read::Serial(TOKEN.serial)],
                Some(failure.clone()),
            );
            let error = discover(route).unwrap_err();
            assert!(error.contains(diagnostic), "route {route}: {error}");
        }
    }
}

#[test]
fn cancellation_racing_success_or_failure_cannot_be_classified_ordinary() {
    for route in 0..5 {
        for position in 0..3 {
            for result in [Read::Denied, Read::Serial(TOKEN.serial)] {
                let flag = Arc::new(AtomicBool::new(false));
                let _cancel = Cancellation::install(Arc::clone(&flag));
                let mut reads = vec![Read::Serial(7), Read::Serial(TOKEN.serial), Read::Serial(8)];
                reads[position] = Read::CancelDuring(flag, Box::new(result));
                let _io = Discovery::new(reads);
                if (route == 2 || route == 3) && position == 2 {
                    discover(route).unwrap();
                } else {
                    assert!(discover(route).unwrap_err().contains("cancelled"));
                }
            }
        }
        // Empty enumeration with cancellation racing an ordinary error.
        let flag = Arc::new(AtomicBool::new(false));
        let _cancel = Cancellation::install(Arc::clone(&flag));
        let _io = Discovery::with_enumeration(
            vec![],
            Some(Read::CancelDuring(flag, Box::new(Read::Denied))),
        );
        assert!(discover(route).unwrap_err().contains("cancelled"));
    }
}

#[test]
fn deadlines_racing_success_or_failure_do_not_restart_the_shared_budget() {
    for route in 0..5 {
        for during_enumeration in [false, true] {
            for result in [Read::Denied, Read::Serial(TOKEN.serial)] {
                let _budget = Operation::new(Duration::from_millis(50));
                let action = Read::ExpireDuring(Box::new(result));
                let _io = if during_enumeration {
                    Discovery::with_enumeration(vec![Read::Serial(TOKEN.serial)], Some(action))
                } else {
                    Discovery::new(vec![action])
                };
                let error = discover(route).unwrap_err();
                assert!(
                    error.contains("deadline exceeded"),
                    "route {route}: {error}"
                );
            }
        }
        // Expiry after a match remains fatal for all-list/app selection.
        if route == 0 || route == 1 || route == 4 {
            let _budget = Operation::new(Duration::from_millis(50));
            let _io = Discovery::new(vec![
                Read::Serial(TOKEN.serial),
                Read::ExpireDuring(Box::new(Read::Denied)),
            ]);
            assert!(discover(route).unwrap_err().contains("deadline exceeded"));
        }
    }
}

#[test]
fn already_cancelled_or_expired_discovery_cannot_return_a_device() {
    for route in 0..5 {
        {
            let _io = Discovery::new(vec![Read::Serial(TOKEN.serial)]);
            let _cancel = Cancellation::install(Arc::new(AtomicBool::new(true)));
            assert!(discover(route).unwrap_err().contains("cancelled"));
        }
        let _io = Discovery::new(vec![Read::Serial(TOKEN.serial)]);
        let _budget = Operation::new(Duration::ZERO);
        assert!(discover(route).unwrap_err().contains("deadline exceeded"));
    }
}

#[test]
fn fresh_native_challenge_selection_preserves_the_unreadable_diagnostic() {
    let key = {
        let _io = Discovery::new(vec![Read::Serial(TOKEN.serial)]);
        db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN)).unwrap()
    };
    let _io = Discovery::new(vec![Read::Denied]);
    // The real retained native key is consumed only through a clone by KeePass.
    // Failure must occur in rediscovery, before any actual challenge/USB access.
    let error = keepass::Database::new()
        .save(&mut Vec::new(), key.clone())
        .unwrap_err();
    assert!(
        error.to_string().contains("synthetic serial access denied"),
        "{error}"
    );
}
