# Jaiba R4 cooperative-lock reconstruction

## Scope and provenance

Development baseline: `1ccac19bfc823e06e03a09765a0268b7ef3dcf6a` on
`feature/vault-lock-recovery`, equal to `feature/vault-r4` at inspection.
The pre-existing untracked `contrib/`, `examples/`, and `tests/` directories
are not inputs to this reconstruction and must not be added wholesale or run as
an offline regression suite: some contain live deployment/acceptance operations.

This work builds a separate executable. It does not replace deployed Jaiba,
BiTTY, lock helpers, NixOS configuration, services, authorization rules, device
configuration, or keyring data. Tests use newly generated synthetic databases.
YubiKey HMAC-SHA1 authentication is out of scope.

## Authoritative protocol inspected over SSH

Source files on Vagabond, captured read-only for this task:

| File under `~/nixos-config` | SHA-256 |
| --- | --- |
| `modules/nixos/vault-files/vault-lock` | `c24592714042bcee1b6c8b5b2156eab1d36f6b19508445075f62553b45d70a04` |
| `modules/nixos/vault-files/vault-lock-events` | `bbc285e9d91bd08bca903a97cd81fafa92f2f062a0734077fc4dfb6a5096d41d` |
| `modules/nixos/vault.nix` | `fd24cf298aa9ded68f669d2e942ef475ab7a09b1b9b8922425a2044a98248a54` |
| `home/vagabond.nix` | `c77625d59726cd52502582e74bf92f9d06fefac85b35fabffabfee2089e622cd` |

The installed, Nix-substituted helper was also read, not executed:

- Path: `/nix/store/gbxic6r0rn9dw7y3354i0jmcabzyi86z-vault-lock-r4/bin/vault-lock`.
- SHA-256: `8c35c03a71c48d4bfcc29568a1b5e14796fd114c45da42c8703a460ef567ef5a`.
- Its Jaiba identity is exactly
  `/nix/store/mx51xcik4f6yjrycpna9fg7c26mga296-jaiba-vault-r4-2026.7.0/bin/jaiba`.
- Installed Jaiba SHA-256 at initial inspection:
  `4dd8ee2ed16d454b08a843a3c2dcea74fa3d40e1dae926d7847e458dae09b213`.
  This differs from the source-input binary hash in `vault.nix`. The derivation
  applies `autoPatchelfHook`, which can change bytes; the cause of this specific
  hash difference and byte equivalence have not been independently established.

### Registration and identity

The isolated `vault` account is UID/GID 1503. The launcher supplies
`HOME=/home/vault`, `USER=LOGNAME=vault`, `XDG_RUNTIME_DIR=/run/user/1503`,
and `JAIBA_CLIPBOARD_BACKEND=terminal-sensitive`, with no desktop display
variables. The registry is `/run/user/1503/vault-tui-lock`.

Registration filename: `jaiba.<PID>.json`. JSON fields consumed by the helper:

```json
{"version":1,"frontend":"jaiba","pid":12345,"start":"123456789"}
```

The illustrative PID/start above are not measured process identities.
`start` is Linux `/proc/<PID>/stat` field 22 (clock ticks since boot), not a
wall-clock timestamp. The helper opens a pidfd before identity validation,
checks all four kernel UIDs, verifies start time and exact executable identity,
and sends through the pinned pidfd. Registration is not authorization to
substitute an arbitrary development executable. The helper also scans for
unregistered recognized frontend processes and fails closed on unverifiable
vault process identity.

The runtime/registry must be real UID-1503 directories with no group/other
permission bits. The helper requires registration and acknowledgment files to
be regular UID-1503 files, no group/other bits, and at most 4096 bytes.
Application-created private files should use 0600 and private directories 0700.
The application may impose stronger checks than the helper; the helper's own
validation must remain unchanged.

### Request and acknowledgment

For each registration, the helper generates `secrets.token_hex(16)`: exactly
32 lowercase hexadecimal characters, no newline. It writes this raw nonce to
`jaiba.<PID>.request` using a private temporary file, flushes and fsyncs it,
atomically replaces the request filename, then sends `SIGUSR2`.

The acknowledgment is `jaiba.<PID>.ack`, private JSON containing:

```json
{"nonce":"0123456789abcdef0123456789abcdef","locked":true,"draft_persisted":true}
```

The nonce must exactly match the current request. `locked` and
`draft_persisted` must be actual JSON booleans, not strings or integers.
The helper does not require version/PID fields in the acknowledgment.
A successful acknowledgment must follow actual locking and successful durable
preservation of any draft; neither signal receipt nor queued work is enough.

The helper serializes its invocations using `vault-lock-relay.lock` and waits
up to 18 seconds, polling every 50 ms. Wrong nonces and `locked != true` do
not count as acknowledgments. `locked=true, draft_persisted=false` counts the
application as locked but reports `draft_in_memory_keep_window_open` and fails
the overall lock. Missing acknowledgment reports
`app_did_not_acknowledge_lock`. Invalid/unreachable registrations and
unregistered/unverifiable frontends also fail closed. Dead/stale identities are
handled conservatively by the helper; the application must not remove another
process's registration to obtain a pass.

The helper attempts to stop only the isolated account's secret provider even
when application locking fails, then independently verifies unit, broker/name,
and process absence. This application must neither call that service-management
path itself nor change those checks. There is no credential-broker replacement.

### Removal-trigger path and deadlines

`vault-lock-events --monitor` polls USB descriptors every 250 ms. It tracks
physical Yubico device instances, starts the lock service if no key is initially
present, and triggers on removal even if another key remains attached. This is
an external lock trigger, not Jaiba hardware-key authentication.

`--once` invokes the fixed doas lock route with a 30-second timeout, publishes
its JSON result to the desktop user's private status directory, and returns
failure unless `locked` is true. The oneshot service has a 35-second startup
timeout and a critical failure notification. No monitor, service, doas, udev, or
YubiKey configuration is changed by this reconstruction.

## Reconstructed application design

`src/locking.rs` owns a lifetime registration and an async-signal-safe
`signal-hook` atomic flag. The event loop checks the flag before rendering each
frame; requests never perform filesystem work or mutate application state in the
signal handler. The ordinary input poll tick is 200 ms, not a guarantee that a
slow filesystem or KDF can finish before the controller's 18-second deadline.
Malformed/unsafe requests do not produce success acknowledgments. Inherited
request/ack nonces and consumed nonces are rejected; coalesced signals process
the latest published request. The external controller serializes ordinary lock
invocations; overlapping nonces cannot all receive simultaneous acknowledgments
through its single per-process acknowledgment filename.

`src/recovery.rs` stores the editor entry, original entry, stable entry ID,
selected field, field-edit flag, and exact partial buffer in a protected JSON
field (`JaibaR4Draft`) inside an encrypted KDBX4 container. It does not commit
unsaved changes to the primary database. Recovery files live beside that database
in `<database>.jaiba-drafts/`, with private `draft.<pid>.<counter>.kdbx` and
companion `.lock` files. A held advisory lock prevents another cooperative live
session from claiming the same draft. After exit/crash, an authenticated session
can claim an abandoned draft; it restores one per authentication and leaves other
records intact. Save/discard explicitly retires the claimed recovery record.

The primary database must authenticate before any draft is restored. Both
password and existing keyfile requirements are retained. Sidecars inherit the
revalidated primary database's KDF parameters, outer/inner cipher policy, and
compression policy, with fresh library-generated seeds/IVs; default sidecar
settings must not create a cheaper password-guessing oracle. The sidecar format
remains KDBX4 without converting or writing the primary database. Recovery binds the
payload to the database's canonical path and root UUID; a deleted existing-entry
target is an error, not a new-entry insertion. Database/keyfile preference edits
apply after restart rather than redirecting an already-open database. In-app
password changes refuse to orphan pending encrypted recovery files. A stable,
nonblocking `transaction.lock` serializes cooperating Jaiba primary writes and
draft publication transactions; the lock file is never unlinked. Edit, delete,
import, and rekey compare the current primary ciphertext to the exact bytes
previously authenticated before replacement. Successful or uncertain replacements
advance that revision from the staged descriptor, not from a potentially
unrelated pathname readback. Stale-key and same-key stale-state saves fail closed
without forgetting the editor. Exports use cloned application state and refuse
to overwrite the open primary or its symlink/hardlink aliases.
Canonical paths put symlink aliases in the same transaction/sidecar domain.
Hardlinked primary files fail closed for recovery/rekey. Noncooperating external
writers remain outside mutex exclusion; this is not general cross-application
multiwriter database support.

Repeated lock acknowledgments revalidate the pinned recovery inode, lock-file
identity, safe metadata, and ciphertext SHA-256 without retaining an
authentication key. Deleted, changed, truncated, replayed, or unsafe artifacts
invalidate durability. Failed restoration of a missing target retains memory
and false durability instead of publishing a knowingly unusable snapshot.
Committed deletion with failed recovery cleanup has an explicit pending-cleanup
state; saving cannot resurrect it, and unrelated replacement files are retained.

`src/private_fs.rs` pins directories and files, refuses symlink traversal,
nonregular files, wrong ownership, group/other permissions, multiple hard links,
and unsafe recovery parents. It stages private encrypted containers, fsyncs and
independently decrypts/verifies them before publication, flushes the directory,
and verifies again after publication. Cleanup checks the retained inode identity
and does not intentionally remove unrelated replacement files. These checks are
not a security boundary against another malicious process with the same UID.

Failed draft persistence transitions to Login while retaining the draft only in
process memory, hidden from ordinary application access until reauthentication.
Its acknowledgment says `draft_persisted:false`, and the controller fails the
overall lock. Repeated requests cannot change that to true after credentials
have been dropped; successful authenticated persistence is required. The Login
Escape key refuses to silently quit with such an undurable memory draft. Closing
the terminal, killing the process, or a machine crash can still lose a draft
whose persistence failed: keep that process/window open and recover it first.

The recovered object is the entry editor draft. Transient settings,
master-password-change, import-password, and export-path prompts are canceled and
their owned buffers erased rather than resumed as drafts. Native clipboard
expiry keeps its original deadline and compare-before-clear behavior after lock:
only a SHA-256 fingerprint of the expected value remains in its timer, not the
plaintext. Locking itself performs no clipboard I/O. The terminal-sensitive
write-only adapter and its no-read/no-fallback behavior remain unchanged.

Recovery payloads are limited to 8 MiB and encrypted containers to 16 MiB;
oversized/unsafe/corrupt/mismatched artifacts fail conservatively. This is a new
sidecar format; recovery compatibility with historical deployed-R4 sidecars is
not claimed. No historical production draft or database was inspected.

## Local build and validation

Linux and `/proc` are required. The manifest declares Rust 1.85, but this task
uses rustc 1.99.0 and Cargo 1.99.0; the minimum compiler version has not been
validated against the complete dependency lockfile. Existing dependencies remain
locked. `libc` 0.2.189, `signal-hook` 0.3.18, `zeroize` 1.9.0, and `sha2`
0.10.9 were promoted from transitive lockfile dependencies to direct
dependencies; no dependency upgrades were needed.
The application uses the existing `keepass` 0.13.20 save/decrypt implementation,
not new cryptographic primitives or a secret-service broker.

From this repository root, with `TMPDIR` pointing to private disposable storage:

    cargo fmt --check
    cargo test --locked
    cargo clippy --locked --all-targets
    cargo build --locked --release
    ./target/release/jaiba --version

The resulting desktop executable is `target/release/jaiba`. It is not a
NixOS-native release/deployment artifact merely because it builds on Linux.
For eventual declarative integration, use `pkgs.rustPlatform.buildRustPackage`
with the reviewed source and `cargoLock.lockFile = ./Cargo.lock`, preserving
the existing dependencies and write-only clipboard adapter routing. Update the
helper's exact executable reference through the derivation relationship, never
through a broad identity exception. No Nix derivation has been activated here.

`validation/r4_controller_compat.py` provides a separate offline compatibility
check against hash-pinned functions extracted from the inspected installed R4
helper. It launches only `locking::tests::protocol_child` in the Rust test binary;
there is no release-runtime admission override. Supply `--helper` with a read-only
copy of the installed helper and `--test-binary` with the executable reported by
`cargo test --locked --no-run`. The helper hash must match the provenance above.
Run this fixture with a private scratch `TMPDIR`, no network, and a read-only host
filesystem, for example with Bubblewrap: `--unshare-net --cap-drop ALL --ro-bind /
/ --dev /dev --bind "$TMPDIR" "$TMPDIR"`. The script refuses to launch a test
child unless root is read-only, scratch is private/writable, and `/proc/net/dev`
contains only loopback. Those concrete checks are runner prerequisites, not a
general hostile-native-code sandbox proof. The Python interpreter also needs
access to its normal read-only installation. Results record the test-binary hash
and source snapshot hashes; the caller must build that binary from those sources.

This harness uses unchanged controller registration parsing, nonce generation,
atomic request publication, pidfd SIGUSR2 delivery, acknowledgment polling and
success/failure interpretation. UID, runtime/proc discovery, test-executable
admission and provider/systemctl calls are explicit controlled substitutes.
Its `wallet_stopped:true` is a stub result, never evidence of real wallet
shutdown. It separately checks that the unchanged production executable
predicate rejects the development test executable. Neither this fixture nor
unit tests prove production-UID or deployed-binary equivalence.

## Validation record and limits

The untouched baseline passed 37 Rust tests. The first reconstruction passed 72
Rust tests but failed independent adversarial review: a weaker sidecar KDF,
cached durability after artifact damage, failed-restoration false success,
incomplete deletion cleanup, and a publication/rekey race were identified. The
review also confirmed plaintext native clipboard-timer retention. Passing those
original tests was explicitly not accepted as readiness. The first repair passed
87 tests but independent review then found canceled native clipboard expiry and
a stale-session write route that could revert rekey and strand a recovery draft.
Those cases were repaired across sibling paths, with additional regressions.
The next review reproduced an uncertain-deletion/lock transition that the
100-test suite's immediate-retry check missed. The user authorized one further
focused repair: pre-replacement failure leaves editor state unchanged;
committed-but-unconfirmed deletion retains an accurate memory-only deletion
marker across lock/reauthentication; explicit retry confirms the idempotent
primary deletion before retiring recovery. The new regression also covers
repeated uncertainty, unrelated later saves, and restart without resurrection.

The final source candidate has passed:

- `cargo fmt --check`.
- `cargo test --locked`: 101 passed, 0 failed, 0 ignored; includes genuine
  SIGUSR2 subprocess cases and deterministic rekey/publication interleavings.
- `cargo clippy --locked --all-targets`: exit 0, with existing warnings for
  `theme_picker_help_items`, password-step variant naming, `calculate_warnings`
  accepting a Vec, and theme sorting/test-module placement. Warning-free lint
  was not claimed; unrelated code was not refactored.
- `cargo build --locked --release`, and `jaiba --version` returned
  `jaiba 2026.7.0`.
  Tested desktop release SHA-256:
  `6280973587b05269191a07aa9a82b2ddcebbcd728a0fd41bc7129fefb9b822e5`.
  Tested Rust test-executable SHA-256:
  `448201605d813842ae6de0183f181300950df34495049fb30928cf06258b8958`.
  These identify this build, not every future compiler/environment's output.
- Three isolated installed-controller-function compatibility cases: no database,
  durable draft, and failed persistence. The failed-persistence case correctly
  returned overall `locked:false`, one application acknowledged, zero durable
  drafts, and `draft_in_memory_keep_window_open`.
- A release-executable PTY smoke test with private HOME/config and a newly
  created synthetic database: incomplete Notes editing, inactivity lock,
  reauthentication, exact buffer recovery, verified save, and normal exit.
  A separate KDBX reader confirmed one entry and the exact recovered notes.
  This did not exercise production UID registration or a real clipboard adapter.
- Independent bounded re-review accepted the final uncertain-deletion repair:
  8 focused tests passed, 0 failed, with frozen-source hashes unchanged before
  and after. Earlier broad reviews accepted the remaining repaired paths; their
  failed candidates and the discovered blockers remain documented above. This
  source-review result is distinct from full live deployment acceptance.
- Read-only final SSH checks matched the initial installed Jaiba/lock-helper
  hashes and all four inspected configuration-source hashes. No installed
  executable, production configuration, service, keyring, device, or credential
  was changed by this development task.

Initial compatibility-runner failures were setup defects (`/dev/null` missing
from the sandbox, then missing constants on the service stub); both were
corrected before the passing runs. The first PTY smoke attempt was inconclusive
because concatenating differential terminal output omitted unchanged letters.
After rendering cursor-positioned output correctly, the full smoke workflow
passed. Neither an initial timeout nor simulated provider shutdown was counted
as application acceptance.

Not yet performed: production UID-1503/NixOS acceptance; the actual external
key-removal trigger; real clipboard adapter/desktop paste and expiration checks;
real secret-provider shutdown/restart; complete two-frontend compatibility;
historical R4 recovery-file compatibility; slow/full/read-only filesystem fault
campaigns; power-cut durability; 18-second deadline qualification with
production-strength KDF configurations; minimum-supported Rust validation;
independent clean-machine or byte-for-byte historical binary reproducibility.
Existing save paths were not expanded to add older-format saving or automatic
primary-database format conversion.

Owned lock-time strings/editor copies and draft/JSON temporaries are zeroized
to the supported extent. Decrypted database internals, allocator/compiler/library
copies, terminal buffers, swap, core dumps, and hostile same-UID access are not
proven erased or contained by this source change. The intentionally retained
memory-only failed draft is not zeroized until it is safely resolved. A memory
preservation acknowledgment is a failure, not a durability guarantee.

## Required deployment acceptance (not yet performed)

Passing local tests is not complete equivalence with the deployed executable.
Before replacing production R4:

1. Review the final source, dependency lockfile, security limitations, and all
   failure-path evidence. Build with `cargo build --locked --release` in an
   isolated declarative Nix derivation, retaining the working production output
   and rollback route. Pin the reviewed source revision and Cargo dependency
   closure. Do not merely copy an unreviewed desktop binary over R4.
2. In a disposable NixOS environment with a synthetic UID/GID-1503 account,
   install the candidate and the actual lock helper through the same derivation
   relationships as `vault.nix`. The helper must pin the candidate's exact
   Nix-store path without broadening its identity policy. A desktop build is
   expected to fail production identity validation.
3. Verify clean startup/exit registration, restart/PID-reuse rejection, private
   modes/ownership, malformed and symlink/hardlink/FIFO refusal, and abrupt
   termination behavior. Probe wrong executable identity as a negative control.
4. Exercise the real SIGUSR2/request/ack path with no database, an unlocked
   synthetic database, and new/existing/untitled drafts, including edits still
   inside each field buffer. Confirm actual login state before crediting ack,
   wrong-password refusal, correct reauthentication and exact draft recovery,
   save once, and independent database readback with no duplicate entries.
5. Exercise inactivity locking, repeated requests, coalesced signals, nonce
   replay, overlapping requests, slow/full/read-only storage, fsync/rename
   failures, and service timeout. Failure must never become a success merely
   because an application already shows Login. Keep failed-durability processes
   running until recovery. Do not credit a timed-out test as a pass.
6. Exercise two frontends together with the unchanged BiTTY artifact. Check
   helper `apps_notified`, `apps_acknowledged`, `drafts_durable`, and failures
   against independently observed application state. Confirm secret-provider
   shutdown and its separately authenticated restart without desktop-provider
   access or activation side effects.
7. Test the external key-removal trigger only in that controlled environment,
   including sequential physical swaps when needed; do not alter keys, slots,
   PINs, or enrollment. Preserve synthetic drafts and verify reauthentication.
8. Exercise `terminal-sensitive` application copy through the real approved
   write-only adapter. Verify exact bytes, no direct X11/Wayland access, no
   clipboard read path or fallback, and the adapter's actual expiration policy.
   Unit adapter tests alone are not a desktop clipboard acceptance claim.
9. Only after independent review and all authorized compatibility tests pass,
   obtain separate production replacement authorization. Retain existing R4 as
   fallback; do not infer deployment permission from this development task.
