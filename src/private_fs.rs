//! Small Linux descriptor-relative private-file boundary shared by locks and drafts.
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Dir {
    fd: File,
    uid: u32,
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    if name.is_empty() || name.as_bytes().contains(&b'/') || name == "." || name == ".." {
        return Err(io::Error::other("invalid private-file name"));
    }
    CString::new(name.as_bytes()).map_err(io::Error::other)
}
fn opened(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful openat returns a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn open_at(parent: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: parent is live, name is NUL-terminated, flags/mode are supplied by this module.
    opened(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode,
        )
    })
}
fn private(meta: &Metadata, uid: u32, directory: bool, max: u64) -> io::Result<()> {
    if meta.uid() != uid
        || meta.mode() & 0o077 != 0
        || (if directory {
            !meta.is_dir()
        } else {
            !meta.is_file() || meta.nlink() != 1 || meta.len() > max
        })
    {
        return Err(io::Error::other("unsafe private file or directory"));
    }
    Ok(())
}
pub fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

impl Dir {
    /// Walk every component without symlink traversal; the resulting directory is pinned.
    pub fn open(path: &Path, uid: u32) -> io::Result<Self> {
        let mut fd = File::open(if path.is_absolute() { "/" } else { "." })?;
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => (),
                Component::Normal(name) => {
                    fd = open_at(&fd, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
                }
                _ => return Err(io::Error::other("unsafe directory path")),
            }
        }
        private(&fd.metadata()?, uid, true, 0)?;
        Ok(Self { fd, uid })
    }
    pub fn child(&self, name: &OsStr, create: bool) -> io::Result<Self> {
        if create {
            let c = c_name(name)?;
            // SAFETY: live directory descriptor and valid name.
            let result = unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), 0o700) };
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error());
            }
            self.fd.sync_all()?;
        }
        let fd = open_at(&self.fd, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        private(&fd.metadata()?, self.uid, true, 0)?;
        Ok(Self { fd, uid: self.uid })
    }
    /// Open a private child of a parent which need not itself have mode 0700.
    pub fn beside(path: &Path, uid: u32, create: bool) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Walk and pin ancestors, but only the final data directory must be private.
        let mut fd = File::open(if parent.is_absolute() { "/" } else { "." })?;
        for c in parent.components() {
            match c {
                Component::RootDir | Component::CurDir => (),
                Component::Normal(n) => {
                    fd = open_at(&fd, n, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
                }
                _ => return Err(io::Error::other("unsafe directory path")),
            }
        }
        let meta = fd.metadata()?;
        if meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "recovery parent must be owned by this user and not writable by others",
            ));
        }
        Self { fd, uid }.child(
            path.file_name()
                .ok_or_else(|| io::Error::other("missing directory name"))?,
            create,
        )
    }
    pub fn open_file(&self, name: &OsStr, max: u64) -> io::Result<File> {
        // O_PATH pins an inode without invoking a FIFO/device endpoint. Validate
        // type and ownership before reopening this exact regular inode for I/O.
        let pinned = open_at(&self.fd, name, libc::O_PATH, 0)?;
        let meta = pinned.metadata()?;
        private(&meta, self.uid, false, max)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
        let actual = file.metadata()?;
        private(&actual, self.uid, false, max)?;
        if !same(&meta, &actual) {
            return Err(io::Error::other("private file identity changed"));
        }
        Ok(file)
    }
    pub fn create(&self, name: &OsStr) -> io::Result<File> {
        let file = open_at(
            &self.fd,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private(&file.metadata()?, self.uid, false, u64::MAX)?;
        Ok(file)
    }
    pub fn read(&self, name: &OsStr, max: u64) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.open_file(name, max)?
            .take(max + 1)
            .read_to_end(&mut data)?;
        if data.len() as u64 > max {
            return Err(io::Error::other("private file too large"));
        }
        Ok(data)
    }
    pub fn names(&self) -> io::Result<Vec<OsString>> {
        // This path references this live descriptor, not a caller-controlled symlink.
        fs::read_dir(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect()
    }
    pub fn sync(&self) -> io::Result<()> {
        self.fd.sync_all()
    }
    pub fn remove_owned(&self, name: &OsStr, meta: &Metadata) -> io::Result<()> {
        let file = self.open_file(name, u64::MAX)?;
        if !same(&file.metadata()?, meta) {
            return Err(io::Error::other("private file identity changed"));
        }
        let name = c_name(name)?;
        // SAFETY: pinned directory descriptor, validated single-component name.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.sync()
    }
    pub fn atomic(
        &self,
        name: &OsStr,
        write: impl FnOnce(&mut File) -> anyhow::Result<()>,
        verify: impl Fn(&mut File) -> anyhow::Result<()>,
        published: &mut Option<File>,
    ) -> anyhow::Result<()> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let (staging, mut file) = (0..100)
            .find_map(|_| {
                let n = OsString::from(format!(
                    ".jaiba-stage-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match self.create(&n) {
                    Ok(f) => Some(Ok((n, f))),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => None,
                    Err(e) => Some(Err(e)),
                }
            })
            .ok_or_else(|| io::Error::other("cannot allocate private staging file"))??;
        let meta = file.metadata()?;
        let result = (|| {
            write(&mut file)?;
            file.sync_all()?;
            let mut staged = self.open_file(&staging, u64::MAX)?;
            anyhow::ensure!(same(&meta, &staged.metadata()?), "Staging identity changed");
            verify(&mut staged)?;
            match self.open_file(name, u64::MAX) {
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
            let src = c_name(&staging)?;
            let dest = c_name(name)?;
            let pinned = file.try_clone()?;
            anyhow::ensure!(
                same(&meta, &self.open_file(&staging, u64::MAX)?.metadata()?),
                "Staging identity changed"
            );
            // SAFETY: live pinned directory and valid names; rename never follows target links.
            if unsafe {
                libc::renameat(
                    self.fd.as_raw_fd(),
                    src.as_ptr(),
                    self.fd.as_raw_fd(),
                    dest.as_ptr(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            *published = Some(pinned);
            self.sync()?;
            let mut actual = self.open_file(name, u64::MAX)?;
            anyhow::ensure!(
                same(&meta, &actual.metadata()?),
                "Published identity changed"
            );
            verify(&mut actual)?;
            Ok(())
        })();
        let _ = self.remove_owned(&staging, &meta);
        result
    }
}

pub fn uid() -> u32 {
    // SAFETY: getuid has no arguments or memory safety preconditions.
    unsafe { libc::getuid() }
}
pub fn claim(file: &File) -> io::Result<bool> {
    // SAFETY: live descriptor; nonblocking exclusive advisory lock, never affects other services.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "jaiba-private-fs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn recovery_directory_refuses_mutable_parent() {
        let root = Root::new();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            Dir::beside(&root.0.join("sidecars"), uid(), true).is_err(),
            "durability cannot depend on an attacker-replaceable directory"
        );
    }

    #[test]
    fn unsafe_directories_owners_links_and_fifo_are_rejected_without_blocking() {
        let root = Root::new();
        assert!(Dir::open(&root.0, uid().wrapping_add(1)).is_err());
        let dir = Dir::open(&root.0, uid()).unwrap();
        let file = dir.create(OsStr::new("data")).unwrap();
        assert!(
            private(
                &file.metadata().unwrap(),
                uid().wrapping_add(1),
                false,
                4096
            )
            .is_err()
        );
        fs::set_permissions(root.0.join("data"), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(dir.open_file(OsStr::new("data"), 4096).is_err());
        fs::set_permissions(root.0.join("data"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(root.0.join("data"), root.0.join("hard")).unwrap();
        assert!(dir.open_file(OsStr::new("hard"), 4096).is_err());
        symlink(root.0.join("data"), root.0.join("link")).unwrap();
        assert!(dir.open_file(OsStr::new("link"), 4096).is_err());
        symlink(&root.0, root.0.join("dirlink")).unwrap();
        assert!(Dir::open(&root.0.join("dirlink"), uid()).is_err());
        let fifo = CString::new(root.0.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: create only a disposable scratch FIFO, never open a device.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(dir.open_file(OsStr::new("fifo"), 4096).is_err());
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Dir::open(&root.0, uid()).is_err());
    }

    #[test]
    fn unsafe_file_type_is_rejected_before_opening_its_io_endpoint() {
        let root = Root::new();
        let dir = Dir::open(&root.0, uid()).unwrap();
        let path = CString::new(root.0.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: only disposable scratch objects and a fresh observation fd.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let mut watcher =
            opened(unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) }).unwrap();
        assert!(
            unsafe { libc::inotify_add_watch(watcher.as_raw_fd(), path.as_ptr(), libc::IN_OPEN) }
                >= 0
        );
        assert!(dir.open_file(OsStr::new("fifo"), 4096).is_err());
        let mut event = [0u8; 128];
        let observed = watcher.read(&mut event);
        assert!(
            matches!(observed, Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "reject special files before opening their FIFO/device endpoint"
        );
    }

    #[test]
    fn atomic_rejects_replaced_staging_inode_without_publishing_or_removing_replacement() {
        let root = Root::new();
        let dir = Dir::open(&root.0, uid()).unwrap();
        let mut published = None;
        let result = dir.atomic(
            OsStr::new("data"),
            |file| {
                file.write_all(b"synthetic original staging")?;
                let staging = dir
                    .names()?
                    .into_iter()
                    .find(|n| n.to_string_lossy().starts_with(".jaiba-stage-"))
                    .unwrap();
                fs::remove_file(root.0.join(&staging))?;
                dir.create(&staging)?
                    .write_all(b"synthetic replacement staging")?;
                Ok(())
            },
            |_| Ok(()),
            &mut published,
        );
        assert!(result.is_err(), "writer must verify its own staged inode");
        assert!(published.is_none());
        assert!(!root.0.join("data").exists());
        let names = dir.names().unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(
            dir.read(&names[0], 4096).unwrap(),
            b"synthetic replacement staging"
        );
    }

    #[test]
    fn rejected_atomic_write_preserves_source_and_unrelated_files() {
        let root = Root::new();
        let dir = Dir::open(&root.0, uid()).unwrap();
        dir.create(OsStr::new("data"))
            .unwrap()
            .write_all(b"original")
            .unwrap();
        dir.create(OsStr::new("unrelated"))
            .unwrap()
            .write_all(b"keep")
            .unwrap();
        let mut published = None;
        let result = dir.atomic(
            OsStr::new("data"),
            |f| Ok(f.write_all(b"replacement")?),
            |_| anyhow::bail!("synthetic staging rejection"),
            &mut published,
        );
        assert!(result.is_err());
        assert!(published.is_none());
        assert_eq!(dir.read(OsStr::new("data"), 4096).unwrap(), b"original");
        assert_eq!(dir.read(OsStr::new("unrelated"), 4096).unwrap(), b"keep");
        assert_eq!(dir.names().unwrap().len(), 2);
    }

    #[test]
    fn final_verification_failure_keeps_own_published_inode_pinned() {
        let root = Root::new();
        let dir = Dir::open(&root.0, uid()).unwrap();
        let calls = std::cell::Cell::new(0);
        let mut published = None;
        let result = dir.atomic(
            OsStr::new("data"),
            |f| Ok(f.write_all(b"replacement")?),
            |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    anyhow::bail!("synthetic final verification rejection");
                }
                Ok(())
            },
            &mut published,
        );
        assert!(result.is_err());
        let pinned = published.unwrap();
        assert!(same(
            &pinned.metadata().unwrap(),
            &fs::metadata(root.0.join("data")).unwrap()
        ));
        assert_eq!(dir.read(OsStr::new("data"), 4096).unwrap(), b"replacement");
        assert_eq!(dir.names().unwrap().len(), 1);
    }
}
