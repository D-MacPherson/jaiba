use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "jaiba-kdbx-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("synthetic.kdbx");
        fs::write(&path, bytes).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.0.parent().unwrap());
    }
}

use super::kdbx_test_fixtures as fixtures;

const PASSWORD: &str = "synthetic regression password";

#[test]
fn legitimate_legacy_imports_remain_readable() {
    for encoded in [fixtures::KDBX3_PLAIN, fixtures::KDBX3_GZIP] {
        let bytes = fixtures::decode(encoded);
        let key = keepass::DatabaseKey::new().with_password(PASSWORD);
        let db =
            keepass::Database::parse(&bytes, key).expect("fixture must genuinely decrypt upstream");
        assert!(matches!(
            db.config.version,
            keepass::config::DatabaseVersion::KDB3(1)
        ));
        let fixture = Fixture::new(&bytes);
        let imported = super::import_kdbx(&fixture.0, PASSWORD).expect("valid legacy import");
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].name, "legacy compatible entry");
        assert_eq!(imported[0].notes, "synthetic compatibility notes");
        assert!(super::import_kdbx(&fixture.0, "wrong synthetic password").is_err());
        assert_eq!(
            fs::read(&fixture.0).unwrap(),
            bytes,
            "import must not convert legacy source"
        );
    }
}

#[test]
fn password_only_long_argon2_salt_is_accepted() {
    let bytes = fixtures::decode(fixtures::KDBX4_LONG_SALT);
    let key = keepass::DatabaseKey::new().with_password(PASSWORD);
    let upstream =
        keepass::Database::parse(&bytes, key.clone()).expect("valid 128-byte Argon2 salt fixture");
    assert_eq!(upstream.iter_all_entries().count(), 1);
    let fixture = Fixture::new(&bytes);
    let imported = super::import_kdbx(&fixture.0, PASSWORD)
        .expect("password-only salt is not a USB challenge");
    assert_eq!(imported.len(), 1);
    let opened = crate::db::open_with_key(&mut std::io::Cursor::new(&bytes), &key)
        .expect("independent decrypt route also permits long salts");
    assert_eq!(opened, upstream);
    assert!(super::import_kdbx(&fixture.0, "wrong synthetic password").is_err());
    assert_eq!(fs::read(&fixture.0).unwrap(), bytes);
}

fn legacy_header(id: u8, width: usize) -> Vec<u8> {
    let mut bytes = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 3, 0];
    bytes.push(id);
    bytes.extend_from_slice(&(width as u16).to_le_bytes());
    bytes.resize(bytes.len() + width, 0);
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes
}

#[test]
fn authenticated_inner_stream_id_width_is_a_structured_error() {
    let valid = keepass::credential_valid_kdbx4_with_inner_stream_id_width(PASSWORD, 4)
        .expect("valid four-byte stream ID");
    let key = keepass::DatabaseKey::new().with_password(PASSWORD);
    let opened = keepass::Database::parse(&valid, key.clone()).expect("four-byte stream ID opens");
    assert_eq!(opened.iter_all_entries().count(), 1);
    assert_eq!(
        opened.iter_all_entries().next().unwrap().get_title(),
        Some("synthetic inner stream")
    );
    let valid_fixture = Fixture::new(&valid);
    let imported = super::import_kdbx(&valid_fixture.0, PASSWORD).expect("valid import");
    assert_eq!(imported[0].name, "synthetic inner stream");

    for width in 0..4 {
        let bytes = keepass::credential_valid_kdbx4_with_inner_stream_id_width(PASSWORD, width)
            .unwrap_or_else(|err| panic!("fixture width {width}: {err}"));
        let wrong = keepass::DatabaseKey::new().with_password("wrong synthetic password");
        let wrong_open = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            keepass::Database::parse(&bytes, wrong)
        }));
        let wrong_open = wrong_open.expect("wrong password must not panic");
        let wrong_err =
            wrong_open.expect_err("wrong password is rejected at header authentication");
        assert!(
            !wrong_err.to_string().contains("stream ID"),
            "wrong password reached the inner header: {wrong_err}"
        );
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered_open = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            keepass::Database::parse(&tampered, key.clone())
        }));
        assert!(
            tampered_open
                .expect("unauthenticated byte must not panic")
                .is_err()
        );

        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            keepass::Database::parse(&bytes, key.clone())
        }));
        let parsed = parsed.expect("short stream ID must not panic");
        let err = parsed.expect_err("short stream ID must fail");
        assert!(
            err.to_string()
                .contains("Invalid inner header stream ID length"),
            "{err}"
        );
        let fixture = Fixture::new(&bytes);
        let imported = std::panic::catch_unwind(|| super::import_kdbx(&fixture.0, PASSWORD));
        let imported = imported.expect("import must not panic");
        match imported {
            Ok(_) => panic!("import must fail for width {width}"),
            Err(import_err) => assert!(
                import_err
                    .to_string()
                    .contains("Invalid inner header stream ID length"),
                "{import_err:#}"
            ),
        }
        let direct = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::db::open_with_key(&mut std::io::Cursor::new(bytes), &key)
        }));
        let direct = direct.expect("decrypt route must not panic");
        assert!(
            direct.is_err(),
            "independent decrypt must reject width {width}"
        );
    }
}

#[test]
fn malformed_legacy_scalars_return_import_error_without_unwinding() {
    // All fixed-width scalar reads in keepass 0.13.20's KDBX3 outer header.
    for (id, expected_width) in [(3, 4), (6, 8), (10, 4)] {
        for width in (0..expected_width).chain([expected_width + 1]) {
            let bytes = legacy_header(id, width);
            let fixture = Fixture::new(&bytes);
            let result = std::panic::catch_unwind(|| super::import_kdbx(&fixture.0, "synthetic"));
            let key = keepass::DatabaseKey::new().with_password(PASSWORD);
            let direct = crate::db::open_with_key(&mut std::io::Cursor::new(bytes), &key);
            assert!(
                direct.is_err(),
                "independent decrypts must also reject malformed legacy headers"
            );
            assert!(
                result.is_ok(),
                "KDBX3 field {id} width {width} must not panic"
            );
            let error = result.unwrap().err().expect("malformed import must fail");
            assert!(error.to_string().contains("KDBX3"), "{error:#}");
        }
    }
}
