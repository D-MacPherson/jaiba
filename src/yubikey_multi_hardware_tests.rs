//! Safe opt-in interchangeability acceptance: one create-new ciphertext, two read-only runs.
use super::{Fixture, db};
use crate::config::YubikeyConfig;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const A: u32 = 39269826;
const B: u32 = 39269828;
const PASSWORD: &str = "synthetic shared ciphertext master";
const DB: &str = "shared-interchangeable.kdbx";
const KEYFILE: &str = "shared-interchangeable.key";

fn private_directory(path: &Path) {
    assert!(path.is_absolute());
    assert_eq!(
        fs::canonicalize(path).unwrap(),
        path,
        "no symlink directories"
    );
    let m = fs::symlink_metadata(path).unwrap();
    assert!(m.is_dir() && m.uid() == crate::private_fs::uid() && m.mode() & 0o077 == 0);
}
fn opt_in() -> PathBuf {
    assert_eq!(
        std::env::var("JAIBA_YUBIKEY_MULTI_TEST").as_deref(),
        Ok("39269826,39269828:2"),
        "separate explicit physical authorization required"
    );
    let root = PathBuf::from(std::env::var_os("TMPDIR").expect("private TMPDIR required"));
    private_directory(&root);
    let home = PathBuf::from(std::env::var_os("HOME").expect("private HOME required"));
    private_directory(&home);
    assert!(
        home.starts_with(&root) && home != root,
        "HOME must be private beneath TMPDIR"
    );
    root
}
fn read_private(path: &Path) -> Vec<u8> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    let m = file.metadata().unwrap();
    assert!(
        m.is_file()
            && m.uid() == crate::private_fs::uid()
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && m.len() < 8 * 1024 * 1024
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}
fn create_shared(root: &Path) -> anyhow::Result<String> {
    private_directory(root);
    // Never overwrite, rename or modify any existing file. A failed creation
    // leaves its incomplete new artifact for inspection; use a new private root.
    let mut keyfile = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(KEYFILE))?;
    keyfile.write_all(b"synthetic shared interchangeability keyfile")?;
    keyfile.sync_all()?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(DB))?;
    let _operation = challenge_response::operation::Operation::standard();
    let key = db::build_database_key_with_yubikey(
        PASSWORD,
        Some(&root.join(KEYFILE)),
        Some(YubikeyConfig { serial: A, slot: 2 }),
    )?;
    db::save_with_key(&keepass::Database::new(), &mut output, &key)?;
    output.sync_all()?;
    Ok(format!(
        "{:x}",
        Sha256::digest(read_private(&root.join(DB)))
    ))
}
fn read_shared(root: &Path, serial: u32) -> String {
    private_directory(root);
    assert!([A, B].contains(&serial));
    let bytes = read_private(&root.join(DB));
    let keyfile_bytes = read_private(&root.join(KEYFILE));
    let _operation = challenge_response::operation::Operation::standard();
    let key = db::build_database_key_with_yubikey(
        PASSWORD,
        Some(&root.join(KEYFILE)),
        Some(YubikeyConfig { serial, slot: 2 }),
    )
    .unwrap();
    let database = db::open_with_key(&mut std::io::Cursor::new(&bytes), &key).unwrap();
    assert_eq!(database.iter_all_entries().count(), 0);
    assert!(
        read_private(&root.join(DB)) == bytes,
        "common ciphertext must remain unchanged"
    );
    assert!(
        read_private(&root.join(KEYFILE)) == keyfile_bytes,
        "synthetic keyfile must remain unchanged"
    );
    format!("{:x}", Sha256::digest(&bytes))
}

#[test]
fn shared_ciphertext_harness_with_simulated_native_sessions() {
    use challenge_response::test_support::{SerialRead, Sessions};
    let f = Fixture::new();
    let digest = {
        let _io = Sessions::new(vec![SerialRead::Serial(A)]);
        create_shared(&f.0).unwrap()
    };
    for serial in [A, B] {
        let _io = Sessions::new(vec![SerialRead::Serial(serial)]);
        assert_eq!(read_shared(&f.0, serial), digest);
    }
    let before = read_private(&f.0.join(DB));
    assert!(create_shared(&f.0).is_err(), "refuse reuse of fixture root");
    assert_eq!(read_private(&f.0.join(DB)), before);
}

#[test]
#[ignore = "REAL USB: explicit multi-key opt-in, create-new shared synthetic ciphertext using serial39269826 slot2"]
fn disposable_shared_ciphertext_create_on_a() {
    let root = opt_in();
    eprintln!(
        "CREATE NEW synthetic ciphertext: provide touch on serial39269826 slot2; no programming, no overwrite."
    );
    let digest = create_shared(&root).unwrap();
    eprintln!("shared synthetic ciphertext created; SHA256={digest}");
}
#[test]
#[ignore = "REAL USB: explicit multi-key opt-in, READ ONLY shared synthetic ciphertext using serial39269826 slot2"]
fn disposable_shared_ciphertext_read_on_a() {
    let root = opt_in();
    eprintln!("READ ONLY same synthetic ciphertext: provide touch on serial39269826 slot2.");
    let digest = read_shared(&root, A);
    eprintln!("native full-factor read succeeded; serial={A} slot=2 ciphertext_SHA256={digest}");
}
#[test]
#[ignore = "REAL USB: explicit multi-key opt-in, READ ONLY shared synthetic ciphertext using serial39269828 slot2"]
fn disposable_shared_ciphertext_read_on_b() {
    let root = opt_in();
    eprintln!("READ ONLY same synthetic ciphertext: provide touch on serial39269828 slot2.");
    let digest = read_shared(&root, B);
    eprintln!("native full-factor read succeeded; serial={B} slot=2 ciphertext_SHA256={digest}");
}
