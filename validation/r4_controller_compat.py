#!/usr/bin/env python3
"""Offline compatibility with the hash-pinned Vagabond R4 controller functions.

Never execute the controller's main(), provider or service-management paths.
Only the Rust cfg(test) protocol child is launched. UID, registry/proc discovery,
executable admission and provider shutdown are explicit controlled substitutes;
request generation, pidfd signal delivery, polling and ack interpretation use
unchanged functions extracted from the inspected installed helper.
"""
import argparse
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import tempfile
import time

HELPER_SHA256 = "8c35c03a71c48d4bfcc29568a1b5e14796fd114c45da42c8703a460ef567ef5a"


def wait_for(check, child):
    deadline = time.monotonic() + 15
    while not check():
        if child.poll() is not None:
            raise RuntimeError("synthetic protocol child exited early")
        if time.monotonic() >= deadline:
            raise TimeoutError("synthetic protocol child readiness was inconclusive")
        time.sleep(0.02)


def extracted(source):
    names = {"private_json", "atomic", "lock", "identity"}
    tree = ast.parse(source)
    nodes: list[ast.stmt] = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in nodes if isinstance(node, ast.FunctionDef)} != names:
        raise ValueError("missing pinned controller functions")
    return compile(ast.Module(body=nodes, type_ignores=[]), "<pinned-r4-controller-functions>", "exec")


def run_case(code, binary, root, mode):
    case = root / (mode or "no-database")
    case.mkdir(mode=0o700)
    if mode:
        (case / "mode").write_text(mode)
    child = subprocess.Popen(
        [str(binary), "--exact", "locking::tests::protocol_child", "--nocapture"],
        env={"JAIBA_TEST_LOCK_ROOT": str(case), "TMPDIR": str(root)},
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    try:
        wait_for(lambda: (case / "ready").exists(), child)
        pid = child.pid
        fake_proc = case / "process-discovery"
        fake_proc.mkdir(mode=0o700)
        (fake_proc / str(pid)).mkdir(mode=0o700)
        actual = Path("/proc") / str(pid)
        start = (actual / "stat").read_text().rpartition(")")[2].split()[19]
        executable = os.readlink(actual / "exe")
        if Path(executable) != binary:
            raise RuntimeError("unexpected synthetic executable")

        def identity(candidate, manager=None):
            if candidate != pid or child.poll() is not None:
                raise ProcessLookupError()
            status = (actual / "status").read_text().splitlines()
            uids = [line.split()[1:] for line in status if line.startswith("Uid:")]
            if uids != [[str(os.getuid())] * 4]:
                raise ValueError("synthetic kernel credential drift")
            observed = (actual / "stat").read_text().rpartition(")")[2].split()[19]
            if observed != start or os.readlink(actual / "exe") != executable:
                raise ValueError("synthetic identity drift")
            return start, "jaiba"

        class NoServices:
            DEVNULL = subprocess.DEVNULL
            PIPE = subprocess.PIPE
            TimeoutExpired = subprocess.TimeoutExpired

            @staticmethod
            def run(argv, **kwargs):
                # These exact two calls are simulated; never launch systemctl.
                if len(argv) >= 4 and argv[-3:] == ["--user", "stop", "manual-secret-service.service"]:
                    return subprocess.CompletedProcess(argv, 0, "")
                if len(argv) >= 4 and argv[-3:] == ["--user", "is-active", "manual-secret-service.service"]:
                    return subprocess.CompletedProcess(argv, 3, "inactive\n")
                raise AssertionError("unexpected controller subprocess")

        def mapped_path(value):
            return fake_proc if value == "/proc" else Path(value)

        namespace = {
            "Path": mapped_path, "UID": os.getuid(), "REGISTRY": case / "vault-tui-lock",
            "os": os, "json": json, "stat": stat, "tempfile": tempfile,
            "secrets": secrets, "signal": signal, "time": time,
            "subprocess": NoServices, "ENV": {}, "ExeUnavailable": PermissionError,
            "kernel_uids": lambda path: (os.getuid(),) * 4,
            "provider_absent": lambda: True,
        }
        exec(code, namespace)
        # Verify the unchanged production identity predicate does NOT admit this
        # development executable, even if kernel credentials were appropriate.
        namespace["process_identity"] = lambda path, manager=None: (start, executable, [b"synthetic"])
        if namespace["identity"](pid)[1] is not None:
            raise AssertionError("production executable pin unexpectedly admitted test binary")
        namespace["identity"] = identity
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = namespace["lock"]()
        report = json.loads(output.getvalue())
        durable = mode != "failed-draft"
        expected = {
            "locked": durable, "apps_notified": 1, "apps_acknowledged": 1,
            "drafts_durable": int(durable), "wallet_stopped": True,
            "errors": [] if durable else ["draft_in_memory_keep_window_open"],
        }
        if report != expected or result != (0 if durable else 1):
            raise AssertionError((report, result, expected))
        wait_for(lambda: read_state(case).get("locked") is True, child)
        if mode:
            (case / "authenticate").touch()
            wait_for(lambda: read_state(case).get("recovered") is True, child)
        (case / "stop").touch()
        if child.wait(timeout=10) != 0:
            raise AssertionError("synthetic child failed")
        if list((case / "vault-tui-lock").glob("*.json")):
            raise AssertionError("normal exit did not clean registration")
        return {"case": mode or "no-database", "controller": report, "passed": True}
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()


def read_state(case):
    try:
        return json.loads((case / "state").read_text())
    except (OSError, ValueError):
        return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--test-binary", type=Path, required=True)
    args = parser.parse_args()
    source = args.helper.read_bytes()
    if hashlib.sha256(source).hexdigest() != HELPER_SHA256:
        raise ValueError("controller differs from inspected installed Vagabond R4 bytes")
    binary = args.test_binary.resolve(strict=True)
    code = extracted(source)
    scratch = Path(os.environ["TMPDIR"]).resolve(strict=True)
    # Refuse the unconfined invocation before launching any child. These are
    # concrete runner prerequisites, not a hostile-native-code sandbox proof.
    if not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise RuntimeError("run in a read-only-host sandbox; see R4-LOCKING.md")
    if os.statvfs(scratch).f_flag & os.ST_RDONLY:
        raise RuntimeError("sandbox scratch must be writable")
    info = scratch.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("TMPDIR must be private and owned by the test user")
    interfaces = {
        line.split(":", 1)[0].strip()
        for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line
    }
    if interfaces != {"lo"}:
        raise RuntimeError("run with networking unshared; see R4-LOCKING.md")
    repository = Path(__file__).resolve().parent.parent
    source_paths = [repository / "Cargo.toml", repository / "Cargo.lock"]
    source_paths.extend(sorted((repository / "src").rglob("*.rs")))
    fingerprints = {
        str(path.relative_to(repository)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source_paths
    }
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="jaiba-controller-compat-", dir=scratch) as directory:
        results = [run_case(code, binary, Path(directory), mode) for mode in ["", "draft", "failed-draft"]]
    print(json.dumps({
        "helper_sha256": HELPER_SHA256, "test_binary": str(binary),
        "test_binary_sha256": binary_hash, "source_snapshot_sha256": fingerprints,
        "source_binding": "caller builds the test binary from this snapshot; hashes record provenance, not build equivalence",
        "sandbox_checks": ["read-only root", "private writable scratch", "loopback-only interfaces"],
        "cases": results, "passed": len(results),
        "substitutes": ["test UID", "scratch runtime/proc discovery", "test-only executable admission", "provider and systemctl stubs"],
        "not_claimed": ["production UID1503 acceptance", "real wallet shutdown", "deployed-binary equivalence"],
    }, indent=2))


if __name__ == "__main__":
    main()
