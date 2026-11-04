use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use chrono::Utc;
use keepass::db::{EntryId, EntryMut, EntryRef, Times, fields};
use keepass::{Database, DatabaseKey};

fn resolve_totp(e: &EntryRef) -> String {
    if let Some(otp) = e.get_raw_otp_value() {
        if !otp.trim().is_empty() {
            return otp.to_string();
        }
    }

    let Some(seed) = e.get("TOTP Seed") else {
        return String::new();
    };
    let seed = seed.trim();
    if seed.is_empty() {
        return String::new();
    }

    let (period, digits) = e
        .get("TOTP Settings")
        .and_then(|settings| settings.split_once(';'))
        .and_then(|(p, d)| Some((p.trim().parse::<u32>().ok()?, d.trim().parse::<u32>().ok()?)))
        .unwrap_or((30, 6));

    let label = e.get_title().unwrap_or("");
    let user = e.get_username().unwrap_or("");
    let encoded_label = urlencoding_encode(&format!("{label}:{user}"));
    let encoded_issuer = urlencoding_encode(label);

    format!(
        "otpauth://totp/{encoded_label}?secret={seed}&period={period}&digits={digits}&issuer={encoded_issuer}"
    )
}

pub struct TotpCode {
    pub code: String,
    pub valid_for: std::time::Duration,
}

pub fn current_totp_code(raw: &str) -> Option<TotpCode> {
    if raw.trim().is_empty() {
        return None;
    }

    let totp: keepass::db::TOTP = raw.parse().ok()?;
    let otp_code = totp.value_now().ok()?;

    Some(TotpCode {
        code: otp_code.code,
        valid_for: otp_code.valid_for,
    })
}

fn urlencoding_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[derive(Clone, Default)]
pub struct Entry {
    pub id: Option<EntryId>,
    pub name: String,
    pub user: String,
    pub password: String,
    pub url: String,
    pub totp: String,
    pub notes: String,
    pub date_last_modify: String,
    pub password_reuse_count: u32,
    pub duplicate_user_count: u32,
}

fn format_days_ago(dt: chrono::NaiveDateTime) -> String {
    let days = (Utc::now().naive_utc() - dt).num_days();

    match days {
        d if d <= 0 => "today".to_string(),
        1 => "1 day ago".to_string(),
        d => format!("{d} days ago"),
    }
}

pub fn unlock_database(
    path: &Path,
    password: &str,
    keyfile_path: Option<&Path>,
) -> anyhow::Result<(Database, DatabaseKey, Vec<Entry>)> {
    let mut file =
        fs::File::open(path).with_context(|| format!("couldn't open {}", path.display()))?;

    let key = build_database_key(password, keyfile_path)?;
    let db = Database::open(&mut file, key.clone()).map_err(|err| match keyfile_path {
        Some(_) => anyhow::anyhow!("unlock failed with password + keyfile: {err}"),
        None => anyhow::anyhow!("unlock failed with password: {err}"),
    })?;

    let entries = db
        .iter_all_entries()
        .map(|e| {
            let date_last_modify = e
                .times
                .last_modification
                .map(format_days_ago)
                .unwrap_or_default();

            Entry {
                id: Some(e.id()),
                name: e.get_title().unwrap_or("(no title)").to_string(),
                user: e.get_username().unwrap_or_default().to_string(),
                password: e.get_password().unwrap_or_default().to_string(),
                url: e.get_url().unwrap_or_default().to_string(),
                totp: resolve_totp(&e),
                notes: e.get(fields::NOTES).unwrap_or_default().to_string(),
                date_last_modify,
                password_reuse_count: 0,
                duplicate_user_count: 0,
            }
        })
        .collect();

    Ok((db, key, entries))
}

pub fn create_database(
    path: &Path,
    password: &str,
    keyfile_path: Option<&Path>,
) -> anyhow::Result<(Database, DatabaseKey, Vec<Entry>)> {
    if path.exists() {
        anyhow::bail!("a file already exists at {}", path.display());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("couldn't create {}", parent.display()))?;
    }

    let db = Database::new();
    let key = build_database_key(password, keyfile_path)?;

    write_to_disk(path, &key, &db)?;

    Ok((db, key, Vec::new()))
}

pub fn build_database_key(
    password: &str,
    keyfile_path: Option<&Path>,
) -> anyhow::Result<DatabaseKey> {
    let mut key = DatabaseKey::new().with_password(password);

    if let Some(path) = keyfile_path {
        let mut keyfile = fs::File::open(path)
            .with_context(|| format!("couldn't open keyfile {}", path.display()))?;

        if keyfile
            .metadata()
            .with_context(|| format!("couldn't inspect keyfile {}", path.display()))?
            .len()
            == 0
        {
            anyhow::bail!("keyfile {} is empty", path.display());
        }

        key = key
            .with_keyfile(&mut keyfile)
            .with_context(|| format!("couldn't read keyfile {}", path.display()))?;
    }

    Ok(key)
}

pub fn save_database(
    path: &Path,
    key: &DatabaseKey,
    db: &mut Database,
    entries: &mut [Entry],
) -> Result<(), SaveError> {
    // Stage changes separately: a failed write must not leak into a later save.
    let mut candidate = db.clone();
    let mut pending = entries.to_vec();
    for entry in &mut pending {
        write_entry(&mut candidate, entry).map_err(SaveError::Write)?;
    }

    let result = write_checked(path, key, &candidate, &pending);
    if !matches!(result, Err(SaveError::Write(_))) {
        // A verification/durability error happens after replacement. Retain the
        // assigned IDs so retrying updates that entry instead of adding another.
        *db = candidate;
        entries.clone_from_slice(&pending);
    }
    result
}

/// Individually reopen the vault from disk and confirm every entry we just
/// wrote is present with the fields we asked for.
///
/// This is deliberately an independent read: it re-decrypts the file the user
/// will actually keep, instead of trusting the in-memory `Database`.
fn verify_saved_entries(path: &Path, key: &DatabaseKey, entries: &[Entry]) -> anyhow::Result<()> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("couldn't reopen {} to verify the save", path.display()))?;

    let reopened = Database::open(&mut file, key.clone())
        .map_err(|err| anyhow::anyhow!("couldn't decrypt the saved database: {err}"))?;

    for entry in entries {
        let id = entry.id.context("saved entry has no ID")?;

        let saved = reopened.entry(id).ok_or_else(|| {
            anyhow::anyhow!("the saved database doesn't contain the entry that was written")
        })?;

        for (field, expected_value) in persisted_fields(entry) {
            let actual = saved.get(field).unwrap_or_default();

            // Unprotected whitespace-only values are normalized to empty by
            // keepass's XML reader. Passwords are protected and compared exactly.
            let expected_value = if field != fields::PASSWORD && expected_value.trim().is_empty() {
                ""
            } else {
                expected_value
            };
            if actual != expected_value {
                anyhow::bail!(
                    "the saved entry doesn't match what was written: field \"{field}\" differs"
                );
            }
        }
    }

    Ok(())
}

/// The field/value pairs that must survive a save, paired with their
/// user-facing names for the mismatch message.
fn persisted_fields(entry: &Entry) -> [(&'static str, &str); 6] {
    [
        (fields::TITLE, entry.name.as_str()),
        (fields::USERNAME, entry.user.as_str()),
        (fields::PASSWORD, entry.password.as_str()),
        (fields::URL, entry.url.as_str()),
        (fields::OTP, entry.totp.as_str()),
        (fields::NOTES, entry.notes.as_str()),
    ]
}

fn write_to_disk(path: &Path, key: &DatabaseKey, db: &Database) -> anyhow::Result<()> {
    write_checked(path, key, db, &[]).map_err(anyhow::Error::new)
}

fn write_checked(
    path: &Path,
    key: &DatabaseKey,
    db: &Database,
    entries: &[Entry],
) -> Result<(), SaveError> {
    write_checked_with(path, key, db, |candidate| {
        verify_saved_entries(candidate, key, entries)
    })
}

fn write_checked_with(
    path: &Path,
    key: &DatabaseKey,
    db: &Database,
    verify: impl Fn(&Path) -> anyhow::Result<()>,
) -> Result<(), SaveError> {
    let (tmp_path, mut file) = create_staging_file(path).map_err(SaveError::Write)?;
    let result = (|| -> Result<(), SaveError> {
        db.save(&mut file, key.clone())
            .map_err(|err| SaveError::Write(anyhow::anyhow!("failed to write database: {err}")))?;
        file.sync_all()
            .context("couldn't flush staged database")
            .map_err(SaveError::Write)?;
        // Reject unreadable or mismatched data before replacing the good file.
        verify(&tmp_path)
            .context("staged save could not be verified")
            .map_err(SaveError::Write)?;
        fs::rename(&tmp_path, path)
            .context("couldn't replace database")
            .map_err(SaveError::Write)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .context("database replaced, but directory flush failed")
            .map_err(SaveError::Verification)?;
        verify(path).map_err(SaveError::Verification)
    })();
    // Remove only the unique file that this operation created.
    drop(file);
    let _ = fs::remove_file(&tmp_path);
    result
}

fn create_staging_file(path: &Path) -> anyhow::Result<(PathBuf, fs::File)> {
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    for _ in 0..100 {
        let mut name: OsString = path.as_os_str().to_owned();
        name.push(format!(
            ".jaiba-{}-{}.tmp",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let candidate = PathBuf::from(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err).context("couldn't create staged database"),
        }
    }
    anyhow::bail!("couldn't allocate a unique staged database")
}

fn write_entry(db: &mut Database, entry: &mut Entry) -> anyhow::Result<()> {
    match entry.id {
        Some(id) => {
            let mut e = db
                .entry_mut(id)
                .context("entry no longer exists in the database")?;
            apply_fields(&mut e, entry);
        }
        None => {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            apply_fields(&mut e, entry);
            entry.id = Some(e.id());
        }
    }

    Ok(())
}

pub fn delete_entry(
    path: &Path,
    key: &DatabaseKey,
    db: &mut Database,
    id: EntryId,
) -> anyhow::Result<()> {
    let mut candidate = db.clone();
    if let Some(entry) = candidate.entry_mut(id) {
        entry.remove();
    }
    let result = write_checked_with(path, key, &candidate, |saved| {
        verify_entry_absent(saved, key, id)
    });
    if !matches!(result, Err(SaveError::Write(_))) {
        *db = candidate;
    }
    result.map_err(anyhow::Error::new)
}

fn verify_entry_absent(path: &Path, key: &DatabaseKey, id: EntryId) -> anyhow::Result<()> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("couldn't reopen {} to verify the delete", path.display()))?;

    let reopened = Database::open(&mut file, key.clone())
        .map_err(|err| anyhow::anyhow!("couldn't decrypt the saved database: {err}"))?;

    if reopened.entry(id).is_some() {
        anyhow::bail!("the deleted entry is still present in the saved database");
    }

    Ok(())
}

fn apply_fields(e: &mut EntryMut<'_>, entry: &Entry) {
    e.set_unprotected(fields::TITLE, entry.name.clone());
    e.set_unprotected(fields::USERNAME, entry.user.clone());
    e.set_protected(fields::PASSWORD, entry.password.clone());
    e.set_unprotected(fields::URL, entry.url.clone());
    e.set_unprotected(fields::OTP, entry.totp.clone());
    e.set_unprotected(fields::NOTES, entry.notes.clone());
    e.times.last_modification = Some(Times::now());
}

pub fn calculate_warnings(entries: &mut Vec<Entry>) {
    let mut password_counts: HashMap<String, u32> = HashMap::new();
    let mut user_counts: HashMap<String, u32> = HashMap::new();

    for entry in entries.iter() {
        if !entry.password.trim().is_empty() {
            *password_counts.entry(entry.password.clone()).or_insert(0) += 1;
        }

        if !entry.user.trim().is_empty() {
            *user_counts.entry(entry.user.clone()).or_insert(0) += 1;
        }
    }

    for entry in entries.iter_mut() {
        entry.password_reuse_count = if entry.password.trim().is_empty() {
            0
        } else {
            password_counts.get(&entry.password).copied().unwrap_or(0)
        };

        entry.duplicate_user_count = if entry.user.trim().is_empty() {
            0
        } else {
            user_counts.get(&entry.user).copied().unwrap_or(0)
        };
    }
}

/// A write that reached disk but could not be confirmed by re-reading it.
///
/// Kept distinct from a write failure so the UI can tell the user whether the
/// vault was not written at all, or was written but could not be verified.
#[derive(Debug)]
pub enum SaveError {
    /// The vault was not written. The on-disk file is unchanged.
    Write(anyhow::Error),

    /// The vault was written, but reopening it from disk did not reproduce the
    /// saved entry's fields.
    Verification(anyhow::Error),
}

impl std::error::Error for SaveError {}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Write(err) => write!(f, "{err:#}"),
            SaveError::Verification(err) => write!(f, "{err:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Entry, SaveError, build_database_key, create_database, save_database, unlock_database,
    };
    use keepass::db::fields;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    const XML_V1_KEYFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<KeyFile>
    <Meta>
        <Version>1.00</Version>
    </Meta>
    <Key>
        <Data>NXyYiJMHg3ls+eBmjbAjWec9lcOToJiofbhNiFMTJMw=</Data>
    </Key>
</KeyFile>"#;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("jaiba-test-{}-{id}", std::process::id()));
            fs::create_dir_all(&path).expect("test directory should be created");
            Self(path)
        }

        fn join(&self, path: impl AsRef<Path>) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn password_only_databases_still_unlock() {
        let dir = TestDir::new();
        let database_path = dir.join("password-only.kdbx");

        create_database(&database_path, "correct horse", None)
            .expect("password-only database should be created");
        unlock_database(&database_path, "correct horse", None)
            .expect("password-only database should unlock");
    }

    #[test]
    fn unlock_database_reads_entry_notes() {
        let dir = TestDir::new();
        let database_path = dir.join("notes.kdbx");
        let (mut database, key, mut entries) =
            create_database(&database_path, "correct horse", None)
                .expect("database should be created");

        {
            let mut root = database.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Entry with notes");
            entry.set_unprotected(fields::NOTES, "first line\nsecond line");
        }

        save_database(&database_path, &key, &mut database, &mut entries)
            .expect("database should be saved");

        let (_, _, entries) =
            unlock_database(&database_path, "correct horse", None).expect("database should unlock");
        let entry = entries
            .iter()
            .find(|entry| entry.name == "Entry with notes")
            .expect("entry should be loaded");

        assert_eq!(entry.notes, "first line\nsecond line");
    }

    #[test]
    fn unlock_database_defaults_missing_notes_to_empty() {
        let dir = TestDir::new();
        let database_path = dir.join("no-notes.kdbx");
        let (mut database, key, mut entries) =
            create_database(&database_path, "correct horse", None)
                .expect("database should be created");

        {
            let mut root = database.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Entry without notes");
        }

        save_database(&database_path, &key, &mut database, &mut entries)
            .expect("database should be saved");

        let (_, _, entries) =
            unlock_database(&database_path, "correct horse", None).expect("database should unlock");
        let entry = entries
            .iter()
            .find(|entry| entry.name == "Entry without notes")
            .expect("entry should be loaded");

        assert!(entry.notes.is_empty());
    }

    #[test]
    fn password_and_keyfile_databases_require_both_factors() {
        let dir = TestDir::new();
        let database_path = dir.join("composite.kdbx");
        let keyfile_path = dir.join("database.keyx");
        fs::write(&keyfile_path, XML_V1_KEYFILE).expect("XML v1 keyfile should be written");

        create_database(&database_path, "correct horse", Some(&keyfile_path))
            .expect("composite-key database should be created");
        unlock_database(&database_path, "correct horse", Some(&keyfile_path))
            .expect("database should unlock with password and keyfile");

        assert!(unlock_database(&database_path, "correct horse", None).is_err());
        assert!(unlock_database(&database_path, "wrong password", Some(&keyfile_path)).is_err());
    }

    #[test]
    fn password_change_keeps_keyfile_requirement() {
        let dir = TestDir::new();
        let database_path = dir.join("composite.kdbx");
        let keyfile_path = dir.join("database.keyx");
        fs::write(&keyfile_path, [42_u8; 32]).expect("keyfile should be written");

        let (mut database, _, mut entries) =
            create_database(&database_path, "old password", Some(&keyfile_path))
                .expect("composite-key database should be created");
        let new_key = build_database_key("new password", Some(&keyfile_path))
            .expect("new composite key should be built");

        save_database(&database_path, &new_key, &mut database, &mut entries)
            .expect("database should be re-encrypted");

        unlock_database(&database_path, "new password", Some(&keyfile_path))
            .expect("new password and keyfile should unlock");
        assert!(unlock_database(&database_path, "new password", None).is_err());
        assert!(unlock_database(&database_path, "old password", Some(&keyfile_path)).is_err());
    }

    #[test]
    fn missing_and_empty_keyfiles_have_clear_errors() {
        let dir = TestDir::new();
        let database_path = dir.join("placeholder.kdbx");
        let missing_keyfile = dir.join("missing.keyx");
        let empty_keyfile = dir.join("empty.keyx");
        fs::write(&database_path, []).expect("placeholder database should be written");
        fs::write(&empty_keyfile, []).expect("empty keyfile should be written");

        let missing_error = unlock_database(&database_path, "secret", Some(&missing_keyfile))
            .err()
            .expect("missing keyfile should fail")
            .to_string();
        assert!(missing_error.contains("couldn't open keyfile"));
        assert!(missing_error.contains(&missing_keyfile.display().to_string()));

        let empty_error = unlock_database(&database_path, "secret", Some(&empty_keyfile))
            .err()
            .expect("empty keyfile should fail")
            .to_string();
        assert!(empty_error.contains("keyfile"));
        assert!(empty_error.contains("is empty"));
    }

    #[test]
    fn wrong_keyfile_error_preserves_the_root_cause() {
        let dir = TestDir::new();
        let database_path = dir.join("composite.kdbx");
        let correct_keyfile = dir.join("correct.keyx");
        let wrong_keyfile = dir.join("wrong.keyx");
        fs::write(&correct_keyfile, [7_u8; 32]).expect("correct keyfile should be written");
        fs::write(&wrong_keyfile, [9_u8; 32]).expect("wrong keyfile should be written");

        create_database(&database_path, "secret", Some(&correct_keyfile))
            .expect("composite-key database should be created");

        let error = unlock_database(&database_path, "secret", Some(&wrong_keyfile))
            .err()
            .expect("wrong keyfile should fail")
            .to_string();
        assert!(error.contains("password + keyfile"));
        assert!(error.contains("Incorrect key"));
    }

    fn saved_entry(name: &str) -> Entry {
        Entry {
            id: None,
            name: name.to_string(),
            user: "tester".to_string(),
            password: "entry-password".to_string(),
            url: "https://example.test".to_string(),
            totp: String::new(),
            notes: "notes".to_string(),
            date_last_modify: String::new(),
            password_reuse_count: 0,
            duplicate_user_count: 0,
        }
    }

    #[test]
    fn save_database_persists_an_entry_with_a_blank_title() {
        // Whitespace-only titles must not cause the entry to disappear.
        let dir = TestDir::new();
        let database_path = dir.join("blank-title.kdbx");
        let (mut database, key, mut entries) =
            create_database(&database_path, "correct horse", None)
                .expect("database should be created");

        let mut entry = saved_entry("   ");
        entries.push(std::mem::take(&mut entry));

        save_database(&database_path, &key, &mut database, &mut entries)
            .expect("an untitled entry should still be written");

        assert!(
            entries[0].id.is_some(),
            "the entry should have been assigned an id"
        );

        let (_, _, reopened) =
            unlock_database(&database_path, "correct horse", None).expect("database should unlock");
        assert_eq!(
            reopened.len(),
            1,
            "the untitled entry must be persisted, not silently discarded"
        );
        // `keepass` normalizes a blank title to an empty string; the point is
        // that the entry itself survives rather than vanishing.
        assert_eq!(reopened[0].name, "");
    }

    #[test]
    fn save_database_verifies_the_entry_after_reopening_from_disk() {
        let dir = TestDir::new();
        let database_path = dir.join("verified.kdbx");
        let (mut database, key, mut entries) =
            create_database(&database_path, "correct horse", None)
                .expect("database should be created");

        let mut entry = saved_entry("Verified entry");
        entries.push(std::mem::take(&mut entry));

        save_database(&database_path, &key, &mut database, &mut entries)
            .expect("database should be saved and verified");

        let id = entries[0].id.expect("saved entry should keep its id");
        let (_, _, reopened) =
            unlock_database(&database_path, "correct horse", None).expect("database should unlock");
        let persisted = reopened
            .iter()
            .find(|candidate| candidate.id == Some(id))
            .expect("the saved entry should be findable by id");
        assert_eq!(persisted.name, "Verified entry");
        assert_eq!(persisted.user, "tester");
        assert_eq!(persisted.url, "https://example.test");
    }

    #[test]
    fn save_database_reports_write_failures_separately_from_verification_failures() {
        let dir = TestDir::new();
        let database_path = dir.join("write-fails.kdbx");
        let (mut database, key, mut entries) =
            create_database(&database_path, "correct horse", None)
                .expect("database should be created");

        // A directory where the vault file should be makes the final rename
        // fail: the write phase cannot complete.
        let blocking_path = dir.join("blocked.kdbx");
        fs::create_dir(&blocking_path).expect("blocking directory should be created");

        let entry = saved_entry("Blocked entry");
        entries.push(entry);

        let error = save_database(&blocking_path, &key, &mut database, &mut entries)
            .expect_err("writing over a directory must fail");
        assert!(
            matches!(error, SaveError::Write(_)),
            "a failed write should be reported as a write failure, got {error:?}"
        );

        // No temp file should be left behind next to the real vault.
        let mut leftover = PathBuf::from(&blocking_path);
        leftover.set_extension("kdbx.tmp");
        assert!(
            !leftover.exists(),
            "a failed write must not leave a temp file"
        );
    }

    #[test]
    fn save_database_reports_verification_failures_when_the_written_file_cannot_be_reopened() {
        let dir = TestDir::new();
        let database_path = dir.join("verify-fails.kdbx");
        let (mut database, key, mut entries) =
            create_database(&database_path, "correct horse", None)
                .expect("database should be created");

        let mut entry = saved_entry("Ghost entry");
        entries.push(std::mem::take(&mut entry));

        // Write and verify in two steps so the second one can be pointed at a
        // file that no longer opens: this is the "written, but unconfirmed"
        // case that must not be reported as success.
        super::write_entry(&mut database, &mut entries[0]).expect("entry should be staged");
        super::write_to_disk(&database_path, &key, &database).expect("database should be written");

        fs::write(&database_path, b"not a kdbx file").expect("corrupt file should be written");

        let error = super::verify_saved_entries(&database_path, &key, &entries)
            .expect_err("an unreadable vault must fail verification");
        assert!(
            error.to_string().contains("couldn't decrypt"),
            "verification should explain why it failed, got: {error}"
        );

        let mapped: SaveError = SaveError::Verification(error);
        assert!(
            !matches!(mapped, SaveError::Write(_)),
            "an unreadable written file is a verification failure"
        );
    }

    #[test]
    fn verification_detects_a_field_that_did_not_persist() {
        let dir = TestDir::new();
        let database_path = dir.join("mismatch.kdbx");
        let (mut database, key, mut entries) =
            create_database(&database_path, "correct horse", None)
                .expect("database should be created");

        let mut entry = saved_entry("Persisted name");
        entries.push(std::mem::take(&mut entry));

        super::write_entry(&mut database, &mut entries[0]).expect("entry should be staged");
        super::write_to_disk(&database_path, &key, &database).expect("database should be written");

        // The caller now believes a different value was saved. Verification
        // must compare against what is actually on disk.
        entries[0].notes = "a value that never reached disk".to_string();

        let error = super::verify_saved_entries(&database_path, &key, &entries)
            .expect_err("a field mismatch must fail verification");
        assert!(
            error.to_string().contains("Notes"),
            "the mismatch should name the field, got: {error}"
        );
    }

    #[test]
    fn rejected_staging_preserves_original_and_removes_only_its_own_file() {
        let dir = TestDir::new();
        let path = dir.join("original.kdbx");
        let (db, key, _) = create_database(&path, "test password", None).unwrap();
        let original = fs::read(&path).unwrap();
        let sentinel = dir.join("original.kdbx.tmp");
        fs::write(&sentinel, b"unrelated file").unwrap();
        let err = super::write_checked_with(&path, &key, &db, |_| {
            anyhow::bail!("injected verification failure")
        })
        .unwrap_err();
        assert!(matches!(err, SaveError::Write(_)));
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read(&sentinel).unwrap(), b"unrelated file");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn final_verification_failure_reports_that_replacement_already_happened() {
        let dir = TestDir::new();
        let path = dir.join("replaced.kdbx");
        let (mut db, key, _) = create_database(&path, "test password", None).unwrap();
        let mut entry = saved_entry("replacement");
        super::write_entry(&mut db, &mut entry).unwrap();
        let err = super::write_checked_with(&path, &key, &db, |candidate| {
            if candidate == path {
                anyhow::bail!("injected final verification failure");
            }
            super::verify_saved_entries(candidate, &key, std::slice::from_ref(&entry))
        })
        .unwrap_err();
        assert!(matches!(err, SaveError::Verification(_)));
        let (_, _, entries) = unlock_database(&path, "test password", None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "replacement");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn saved_database_has_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let path = dir.join("private.kdbx");
        let (mut db, key, mut entries) = create_database(&path, "test password", None).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        entries.push(saved_entry("private entry"));
        save_database(&path, &key, &mut db, &mut entries).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn failed_rename_does_not_mutate_database_or_assign_entry_id() {
        let dir = TestDir::new();
        let path = dir.join("source.kdbx");
        let (mut db, key, mut entries) = create_database(&path, "test password", None).unwrap();
        let original = db.clone();
        let blocked = dir.join("blocked.kdbx");
        fs::create_dir(&blocked).unwrap();
        entries.push(saved_entry("should not leak"));
        assert!(save_database(&blocked, &key, &mut db, &mut entries).is_err());
        assert_eq!(db, original);
        assert!(entries[0].id.is_none());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn deletion_can_be_retried_after_a_failed_write() {
        let dir = TestDir::new();
        let path = dir.join("delete.kdbx");
        let (mut db, key, mut entries) = create_database(&path, "test password", None).unwrap();
        entries.push(saved_entry("delete me"));
        save_database(&path, &key, &mut db, &mut entries).unwrap();
        let id = entries[0].id.unwrap();
        let blocked = dir.join("missing/delete.kdbx");
        assert!(super::delete_entry(&blocked, &key, &mut db, id).is_err());
        assert!(db.entry(id).is_some());
        super::delete_entry(&path, &key, &mut db, id).unwrap();
        super::delete_entry(&path, &key, &mut db, id).unwrap();
        assert!(
            unlock_database(&path, "test password", None)
                .unwrap()
                .2
                .is_empty()
        );
    }
}
