//! Header safety tests: synthetic native discovery only; no USB is available.
use challenge_response::test_support::{Discovery, SerialRead};
use keepass::DatabaseKey;
use sha2::{Digest, Sha256};
use std::{cell::Cell, io::Cursor, rc::Rc};

use super::kdbx_test_fixtures as fixtures;

const TOKEN: crate::config::YubikeyConfig = crate::config::YubikeyConfig { serial: 7, slot: 2 };

fn outer_field(id: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    out
}

// Replace one KDF entry, preserving the valid container layout/header SHA256.
// HMAC remains invalid deliberately: these rejection cases must fail before KDF
// authentication, and do not pretend to be successful long-salt fixtures.
fn changed_kdf(name: &[u8], replacement: &[u8]) -> Vec<u8> {
    let bytes = fixtures::decode(fixtures::KDBX4_LONG_SALT);
    let mut header = bytes[..12].to_vec();
    let mut pos = 12;
    loop {
        let id = bytes[pos];
        let len = u32::from_le_bytes(bytes[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let value = &bytes[pos + 5..pos + 5 + len];
        if id == 11 {
            let mut dictionary = value[..2].to_vec();
            let mut entry = 2;
            while value[entry] != 0 {
                let start = entry;
                let kind = value[entry];
                let key_len =
                    u32::from_le_bytes(value[entry + 1..entry + 5].try_into().unwrap()) as usize;
                let key = &value[entry + 5..entry + 5 + key_len];
                let size_pos = entry + 5 + key_len;
                let size =
                    u32::from_le_bytes(value[size_pos..size_pos + 4].try_into().unwrap()) as usize;
                entry = size_pos + 4 + size;
                if key == name {
                    dictionary.push(kind);
                    dictionary.extend_from_slice(&(key_len as u32).to_le_bytes());
                    dictionary.extend_from_slice(key);
                    dictionary.extend_from_slice(&(replacement.len() as u32).to_le_bytes());
                    dictionary.extend_from_slice(replacement);
                } else {
                    dictionary.extend_from_slice(&value[start..entry]);
                }
            }
            dictionary.push(0);
            header.extend_from_slice(&outer_field(id, &dictionary));
        } else {
            header.extend_from_slice(&outer_field(id, value));
        }
        pos += 5 + len;
        if id == 0 {
            break;
        }
    }
    let hash = Sha256::digest(&header);
    header.extend_from_slice(&hash);
    header.extend_from_slice(&bytes[pos + 32..]);
    header
}

#[test]
fn hardware_seed_limits_precede_discovery() {
    let counter = Rc::new(Cell::new(0));
    let _discovery = Discovery::with_enumeration(
        vec![],
        Some(SerialRead::Sequence(
            counter.clone(),
            vec![SerialRead::EnumerationFailure],
        )),
    );
    for size in [0, 65, 128] {
        let bytes = changed_kdf(b"S", &vec![1; size]);
        let dir =
            std::env::temp_dir().join(format!("jaiba-seed-limit-{}-{size}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("synthetic.kdbx");
        std::fs::write(&path, bytes).unwrap();
        let error =
            crate::db::unlock_database_snapshot_with_yubikey(&path, "synthetic", None, Some(TOKEN))
                .err()
                .expect("invalid hardware seed must fail");
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            error.to_string().contains("challenge seed length"),
            "{error:#}"
        );
    }
    assert_eq!(
        counter.get(),
        0,
        "invalid seeds must not attempt device discovery"
    );
}

#[test]
fn independent_decrypt_native_key_keeps_typed_seed_guard() {
    // This produces the real keepass YubikeyChallenge variant, not LocalChallenge.
    // The fake descriptor/serial seam admits discovery only. A missing length
    // guard would attempt unavailable USB or panic, neither of which we credit.
    let _discovery = Discovery::new(vec![SerialRead::Serial(TOKEN.serial)]);
    let key = crate::db::build_database_key_with_yubikey("synthetic", None, Some(TOKEN)).unwrap();
    for size in [0, 65, 128] {
        let bytes = changed_kdf(b"S", &vec![1; size]);
        let error = crate::db::open_with_key(&mut Cursor::new(bytes), &key).unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<keepass::error::DatabaseOpenError>(),
                Some(keepass::error::DatabaseOpenError::Key(
                    keepass::error::DatabaseKeyError::ChallengeResponse(
                        keepass::error::ChallengeResponseKeyError::Api(
                            challenge_response::error::ChallengeResponseError::InvalidChallenge
                        )
                    )
                ))
            ),
            "must retain typed native length failure, not absent USB or wrong-key: {error:#}"
        );
    }
}

#[test]
fn password_only_malformed_dictionary_scalars_stay_rejected() {
    let key = DatabaseKey::new().with_password("synthetic");
    for id in [11, 12] {
        for (kind, width) in [(0x04, 4), (0x0c, 4), (0x05, 8), (0x0d, 8), (0x08, 1)] {
            for size in (0..width).chain([width + 1]) {
                let mut dictionary = vec![0, 1, kind];
                dictionary.extend_from_slice(&1u32.to_le_bytes());
                dictionary.push(b'x');
                dictionary.extend_from_slice(&(size as u32).to_le_bytes());
                dictionary.resize(dictionary.len() + size, 0);
                dictionary.push(0);
                let mut bytes = fixtures::decode(fixtures::KDBX4_LONG_SALT)[..12].to_vec();
                bytes.extend_from_slice(&outer_field(id, &dictionary));
                bytes.extend_from_slice(&outer_field(0, &[]));
                let error = crate::db::open_with_key(&mut Cursor::new(bytes), &key).unwrap_err();
                assert!(
                    error.to_string().contains("dictionary value"),
                    "id {id} kind {kind} size {size}: {error:#}"
                );
            }
        }
    }
}

#[test]
fn invalid_small_argon2_parameters_return_controlled_errors() {
    let key = DatabaseKey::new().with_password("synthetic");
    for (name, width) in [(b"P", 4), (b"I", 8), (b"M", 8)] {
        let bytes = changed_kdf(name, &vec![0; width]);
        let error = crate::db::open_with_key(&mut Cursor::new(bytes), &key).unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<keepass::error::DatabaseOpenError>(),
                Some(keepass::error::DatabaseOpenError::Cryptography(
                    keepass::error::CryptographyError::Argon2(_)
                ))
            ),
            "upstream must reject zero parameters before HMAC/KDF resource use: {error:#}"
        );
    }
}
