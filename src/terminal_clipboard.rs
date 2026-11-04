//! Opt-in, write-only integration with the administrator-installed sensitive adapter.
use std::{ffi::OsStr, io};

pub fn enabled(setting: Option<&OsStr>) -> io::Result<bool> {
    match setting {
        None => Ok(false),
        Some(value) if value == "native" => Ok(false),
        Some(value) if value == "terminal-sensitive" => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "JAIBA_CLIPBOARD_BACKEND must be native or terminal-sensitive",
        )),
    }
}

pub fn copy(text: &str) -> io::Result<()> {
    write_to(
        &mut std::process::Command::new(
            "/usr/local/libexec/vault-terminal-clipboard-sensitive/xsel",
        ),
        text,
    )
}

fn write_to(command: &mut std::process::Command, text: &str) -> io::Result<()> {
    use std::io::Write;
    use std::process::Stdio;
    // Match the root-owned adapter's memory-only bound; never truncate a value.
    if text.len() > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "clipboard value exceeds the 65535-byte limit",
        ));
    }
    let mut child = command
        .args(["--clipboard", "--input"])
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("XAUTHORITY")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| io::Error::other("cannot start sensitive clipboard adapter"))?;
    let written = child.stdin.take().unwrap().write_all(text.as_bytes());
    // Always close stdin and reap the child, including on a broken pipe.
    let status = child.wait();
    match (written, status) {
        (Ok(()), Ok(status)) if status.success() => Ok(()),
        _ => Err(io::Error::other(
            "sensitive clipboard write failed or timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_exact_stdin_and_only_fixed_arguments() {
        let output =
            std::env::temp_dir().join(format!("jaiba-synthetic-{}.txt", std::process::id()));
        let mut command = std::process::Command::new("/bin/sh");
        command.args([
            "-c",
            "test \"$#\" = 3 && test \"$2\" = --clipboard && test \"$3\" = --input && cat > \"$1\"",
            "test-adapter",
        ]);
        command.arg(&output);
        let text = "  synthetic λ\tvalue\nwith trailing newlines\n\n";
        write_to(&mut command, text).unwrap();
        let actual = std::fs::read(&output).unwrap();
        std::fs::remove_file(output).unwrap();
        assert_eq!(actual, text.as_bytes());
    }

    #[test]
    fn rejects_oversized_input_before_starting_adapter() {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "cat >/dev/null"]);
        assert!(write_to(&mut command, &"x".repeat(65536)).is_err());
    }

    #[test]
    fn adapter_failure_is_reported_without_child_output() {
        let mut command = std::process::Command::new("/bin/sh");
        command.args([
            "-c",
            "cat >/dev/null; echo synthetic-child-error >&2; exit 17",
        ]);
        let error = write_to(&mut command, "synthetic-secret")
            .unwrap_err()
            .to_string();
        assert_eq!(error, "sensitive clipboard write failed or timed out");
    }

    #[test]
    fn backend_selection_is_explicit_and_fail_closed() {
        assert!(!enabled(None).unwrap());
        assert!(!enabled(Some(OsStr::new("native"))).unwrap());
        assert!(enabled(Some(OsStr::new("terminal-sensitive"))).unwrap());
        assert!(enabled(Some(OsStr::new("typo"))).is_err());
        assert!(enabled(Some(OsStr::new(""))).is_err());
    }
}
