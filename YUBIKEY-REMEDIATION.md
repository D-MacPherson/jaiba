# YubiKey independent-review remediation — uncommitted review candidate

## Status and authority

The amended independent review supersedes the first report's conditional approval.
This is a development-source repair, not independent acceptance or deployment.
No commit, push, PR, SSH/production access, hardware challenge, key programming,
service/configuration change, or production credential/keyring operation was
performed in this remediation phase. Production state was not remotely remeasured.
A separate fresh independent review is required before any local commit.

Repository: `/home/david/src/jaiba-vault`, branch
`feature/yubikey-challenge-response`, HEAD/baseline
`397c79f14630b16e5ffb1a38798993fedc70a5d3`.
At start: 12 modified tracked files and 11 untracked top-level status entries.
The existing uncommitted YubiKey implementation was preserved. Both supplied
`/mnt/data` report paths were unavailable; the supplied amended findings governed.

Verified pre-edit recovery snapshot (outside the repository):
`/home/david/.hermes/cache/scratch/jaiba-remediation-20261105-145300/`.
`candidate.tar.gz` contains all 103 initial tracked/untracked nonignored files,
with `manifest.json`, binary `baseline.diff`, and `status.txt`.
Archive SHA-256:
`aebf82d3b5c8a10fe37378950f98de2ab4f51b54ea0d18aaf20f3f529796cc21`.
All archived file hashes were checked against the manifest before editing.
Ignored build outputs are rebuildable and are not part of that source snapshot.

## Findings and corrections

### A — Late credential installation: repaired

Creation checks cancellation after configuration persistence; ordinary unlock
checks after warning calculation, immediately before installing returned state.
Both recheck after installation/filter work before exposing Index, and unlock
checks immediately before dispatching recovery. Observed cancellation revokes
partial authenticated state, leaves Login and the pending signal intact, drops
returned credentials, preserves hidden drafts and existing durability receipts,
and does not start recovery/persistence. Newly created ciphertext is retained.

Six deterministic tests inject after the helper's final check, during installation,
and before recovery. These are cooperative checkpoints, not atomic signal masking,
preemption, or proof that a signal arriving after the last check cannot occur.

### B — Duplicate signal suppresses acknowledgment: repaired

`Dir::atomic_key_free` uses the same staging, private-file metadata/type/ownership,
inode identity, sync, publication and content verification as `Dir::atomic`, but
omits credential-operation cancellation. Only the post-revocation acknowledgment
uses it. Credential-bearing sidecar publication retains cancellation checks.
No nonce is unburned or replay-authorized, and the duplicate flag stays pending
for normal coordinator consumption.

Three tests inject exactly the signal handler's atomic action after locking,
after staged verification/before rename, and after published verification. Each
originally failed with cancellation; each now checks acknowledgment readback,
credential absence, duplicate consumption, and no replay relocking/ack rewriting.
The injection avoids signaling other unit-test registrations. Genuine SIGUSR2
subprocess coverage also passes, but no real double-signal hardware trial is claimed.

### C — Memory-only draft crosses database identity: repaired

Each captured draft retains the canonical path from the authenticated `Revision`
and the decrypted database root UUID. It never binds to a fresh lock-time symlink
resolution or a later login. Restore and publication require matching authenticated
revision path, currently resolved path and root. A transaction-path recheck prevents
rebinding between initial validation and publication. Durable envelopes retain
version/serialization compatibility and supply the identity after authentication.

Six tests cover new and existing drafts, replacement roots with colliding entry IDs,
retargeted canonical paths even with identical ciphertext/root, missing-primary
capture, and symlink retargeting between authentication and recovery. They check
repeated-lock failure, hidden memory retention, credential dropping, original-file
restoration/reauthentication, durable retry, explicit save, no duplicates and no
writes to the replacement/copy.

Recovery procedure on mismatch: KEEP THE PROCESS/WINDOW OPEN. Preserve both files;
restore the original vault from a known backup to its original canonical location
and restore the configured alias/path, then authenticate with all original factors.
The error identifies that origin path. Wrong credentials remain rejected. No
cross-vault rescue/export or discard bypass was added. If no matching original
vault is available, the draft remains hidden in this process; this repair does not
provide a general standalone rescue UI or make a memory-only draft crash-safe.
Missing authenticated provenance also fails closed rather than inventing identity.

### Follow-up QA-1 — Missing-primary creation bypass: repaired, reinspection required

Fresh-context internal QA rejected the first repaired freeze after reproducing an
inherited preservation defect on its release executable: with a hidden memory-only
draft and missing primary, `n` could create a replacement vault, expose Index, and
permit ordinary exit while the original draft remained unresolved. That freeze
and its rejection report remain preserved; the earlier passing suite did not cover
this workflow and is not approval of it.

`App::protect_memory_draft` now clears exposed credentials/editor state without
consuming the hidden draft or doing filesystem/clipboard I/O. Login refuses
creation (including already-started creation) while recovery is pending and the
primary is missing, and refuses ordinary exit. Index defensively gates all actions
while a hidden draft remains. The main-loop exit boundary independently refuses
termination with unresolved memory recovery. Guidance requires keeping the window
open and restoring/authenticating the original vault and configured path.

Four regression definitions failed before the guards and now pass. New/existing
draft cases each cover a missing primary and dangling/retargeted alias, repeated
lock, rejected creation/exit, wrong-password rejection, original reauthentication,
exact editor recovery, explicit save and no duplicate entries. Two defensive cases
cover already-started creation and Index exit/new-editor actions with hidden memory.

A no-USB PTY test of the hash-pinned final release also passed: remove the synthetic
primary during editing, inactivity-lock to memory, attempt replacement creation and
exit, restore the original, reauthenticate, explicitly save, and exit normally.
A separate reader using the locked keepass library verified the original entries
and exactly one recovered synthetic title. ANSI-stripped terminal deltas are not
rendered-screen proof; process/file state and independent decrypted readback are
the decisive oracles. The first reader incorrectly assumed the starting fixture had
zero entries; its failed assertion and transcript are retained. The corrected
reader compares the original backup and the fresh PTY rerun passed.

### D — Malformed KDBX3 import panic: repaired

Every Jaiba decrypt wrapper now bounds-checks legacy outer-header framing and the
exact widths of all three unchecked KDBX3 scalar reads in keepass 0.13.20:
compression (u32), transform rounds (u64), and inner-stream ID (u32). Malformed input
returns an error before decoder reads. No blanket legacy rejection, dependency
fork, or implicit conversion was introduced.

The regression covers each undersized width and an oversized width through import
and direct decrypt. Real encrypted uncompressed/gzip KDBX3 fixtures successfully
import, reject a wrong password, and retain original bytes. The implementing worker
also opened both with a sandboxed KeePassXC CLI; that supplemental result is not
hardware interoperability evidence. Test ciphertext and its synthetic password are
explicitly labeled in `src/kdbx_test_fixtures.rs`.

### E — Hardware seed limit on password-only databases: repaired

KDBX4 framing/dictionary scalar validation remains universal. Only configured
hardware unlock applies the 1–64-byte seed restriction before discovery. Because
keepass exposes no public factor accessor on DatabaseKey, independent decrypts
rely on the existing vendored native challenge-length guard, not inferred metadata.
A real native-key variant admitted by synthetic discovery returns exact typed
`InvalidChallenge` for invalid seed lengths; unavailable USB is not accepted as
proof of length validation.

A genuinely authenticated password-only KDBX4 fixture with a 128-byte Argon2id salt
now opens/imports, matching raw locked keepass behavior. KeePassXC rejected that
fixture's KDF parameters: no KeePassXC long-salt interoperability claim is made.
Seven D/E tests also cover pre-discovery rejection, independent native-key rejection,
universal malformed dictionary rejection and safe small invalid KDF parameters.

### F — Wrong-slot test accepts infrastructure errors: repaired

The ignored physical test constructs the explicit slot-1 native key and calls the
typed decrypt wrapper. Only `DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey)`
counts: KDBX4 emits it at header-HMAC rejection after the configured challenge
completed. Selection/access failure, unsupported slot response, timeout,
cancellation, disconnect, malformed input and successful authentication all fail
the test; infrastructure outcomes are labeled inconclusive/failure, never passes.
The stale "may wait forever" annotation and guide were corrected.

An ordinary offline regression checks direct/nested typed infrastructure failures,
text-only spoofed errors, and real software-challenge success/wrong-secret/invalid
secret results. This validates the oracle, not actual physical slot behavior.

### Additional — Native clipboard false-clear report: repaired

Failed native readback or clearing retains a zeroized expected-value fingerprint
and original expiration deadline for retry, reporting clearing as unverified.
A different clipboard value resolves the timer without erasing it or claiming
that it was cleared. Two regression definitions cover failed readback/missing
handle and retry to a changed value without opening a live clipboard/display.
The terminal-sensitive write-only backend is unchanged; its routing/stdin tests
and lock-time no-I/O/fingerprint tests still pass. No live desktop acceptance ran.

## Additional findings retained as explicit limitations

- **nusb initialization cleanup panic — deferred upstream/dependency work.** Exact
  locked nusb 0.2.9 Linux source still has `EPOLL_FD.get().unwrap()` in unregister,
  reachable from LinuxDevice Drop after failed epoll initialization; thread spawn
  also unwraps. Source-confirmed here, not resource-exhaustion reproduced. A Jaiba
  error wrapper cannot safely repair destructor assumptions; catching/ignoring
  unwinds is not a fix. A separately scoped dependency lifecycle patch with
  subprocess resource-fault tests is preferable to adding another native fork to
  these repairs. A panic can still lose undurable memory drafts.
- **nusb enumeration omissions — deferred upstream diagnostics.** Linux sysfs
  enumeration discards failed directory/canonicalization/required-attribute probes.
  Vendor-level strict selection/error isolation is preserved but cannot recover
  omitted errors. `DeviceNotFound` is not proof of physical absence. Fixing this
  requires checked lower-level enumeration; no first-token/factor fallback was
  added. Source-confirmed, no live permission-denial test performed.
- **Cooperative timing only.** Native waits, cleanup, filesystem calls and KDFs can
  block between checks. No hard execution/credential-drop bound is established and
  no persistent/abandoned credential-bearing worker was introduced.
- **Hostile KDF CPU/memory — unresolved.** keepass passes potentially expensive
  parameters and narrows some u64 fields to u32; AES rounds are synchronous and
  Argon2 memory allocation is not an application resource policy. Zero/minimum
  invalid cases return typed errors, but that is not a resource-exhaustion defense.
  No arbitrary memory/iteration caps or hostile expensive workload was introduced.
  Resource admission/isolation and broader parser/fuzzing hardening remain separate
  design work before treating untrusted files as safely bounded.

## Lock responsiveness versus persistence latency

The 18-second controller acknowledgment wait is configurable operational policy,
not an intrinsic security requirement or a proven execution bound. It was not
increased. Cancellation is signaled immediately, but credential revocation awaits
return to a checkpoint/coordinator if a synchronous dependency blocks.

For hardware-session valid signal locking, the existing policy deliberately
cancels new draft persistence before filesystem transactions/KDFs: capture memory,
revoke credentials, then publish truthful `locked:true,draft_persisted:false`.
That is controller failure requiring recovery, not successful durable locking.
Already durable ciphertext is revalidated without retaining a key after revocation.
Password-only signal locks retain verified encrypted persistence before credential
drop; strong KDF/storage latency is consequently distinct from native cancellation
responsiveness. Direct/inactivity full-factor persistence can also be slow. A
larger controller wait would not solve blocked credential revocation. No alternate
retained credential authority, weaker sidecar, skipped verification or format
conversion was introduced.

## Parent validation of the corrected source

Environment: rustc 1.99.0, Cargo 1.99.0. Cargo.lock/manifests and all existing vendor
files remain unchanged from the start of this remediation phase.

- `cargo test --locked --offline --no-run --message-format=json`, then the exact
  reported test executable copied/hash-verified to immutable-by-convention scratch
  and run in Bubblewrap: **175 passed, 0 failed, 9 ignored, 184 definitions**, 50.48s.
  All tests selected, none filtered. This is the complete root Rust unit suite;
  test builds use the locked graph, not execution on the unrestricted desktop.
- **29 new regression definitions** relative to the starting candidate: A6, B3,
  C6, D/E7, F1, clipboard2, follow-up preservation4. Focused runs overlap the full
  suite, not extra unique
  tests. The original failure/RED logs remain in the evidence directories below.
- Ignored accounting: **7 physical-hardware tests unexecuted**; **2 ignored
  subprocess-only helpers actually exercised by ordinary parents**:
  `config::tests::startup_config_child` and `yubikey_tests::native_signal_child`.
  Ignored is not credited as a pass. Ordinary protocol_child is a no-op without
  its test environment, and its real path is exercised by subprocess parents and
  the separate controller harness.
- `cargo fmt --check`: exit 0. Scoped changed/new vendor-source rustfmt check with
  `skip_children=true`: exit 0. An initial recursive vendor check reached untouched
  configure/OTP/rusb files and failed on upstream formatting; preserved in
  `vendor-fmt-final.log`, not concealed or fixed by unrelated reformatting.
- `cargo clippy --locked --offline --all-targets`: exit 0, with five existing
  warning categories (dead theme helper, password-step names, Vec argument,
  theme sorting and test-module placement). Warning-free lint is not claimed.
- `cargo build --locked --offline --release`: exit 0. Sandboxed development
  executable `--version`: `jaiba 2026.7.0`. `git diff --check`: exit 0.
- Hash-pinned installed-controller-function harness: **3/3 passed** (no database,
  durable draft, failed persistence). Failed persistence correctly has one app
  acknowledgment, zero durable drafts, overall failure and
  `draft_in_memory_keep_window_open`. It uses real private requests, pidfd signals,
  nonce/ack polling, but controlled UID/runtime/executable/provider substitutions.
  Its `wallet_stopped:true` is a stub, not live provider shutdown evidence.
- Existing recovery, keyfile/hardware-factor, stale-write, atomicity,
  committed-but-unconfirmed deletion, filesystem/UID, genuine-SIGUSR2 and
  terminal-sensitive regressions pass in the full suite.

Initial shared broad runs had a genuine fixture incompatibility: direct manual
key/database installation omitted the now-required authenticated revision. The
protocol child and password+keyfile sidecar fixture now use real authentication
and retain its revision; no production check was weakened. Concurrent Cargo
replacement also caused an earlier self-spawn ENOENT; final runners freeze the
actual reported binary. Neither setup failure was counted as a passing run.

Round-two full validation initially had **174 passed, 1 failed, 9 ignored** in
`review_logic4_draft_wins_denies_rekey_before_publication_including_aliases` at its
"published draft also blocks rekey" status assertion. The isolated test passed.
Only failure diagnostics were expanded; the next complete run passed 175/0/9.
The failure's cause was not established and is an unresolved intermittent-test
evidence limitation, not a repaired defect or proven environment failure. Both
full logs are retained for the next reviewer. No ignored test or assertion was
removed to obtain the passing result.

Development executable (not installed or NixOS-qualified):
`/home/david/src/jaiba-vault/target/release/jaiba`
SHA-256: `917a5247177d47c684e504c98fd6b046cda9d4dde2a1a59813f42e4ea89ce73d`.
Frozen tested executable:
`/home/david/.hermes/cache/scratch/jaiba-remediation-20261105-145300/round2/final-full-diagnostic-test-executable`
SHA-256: `112bf2f98fbcd8ee206f49a5dc453efde9ac3ece1bd43c26723d22c95f1a638b`.

## Changed files in this remediation phase

Production changes: `src/app.rs`, `src/clipboard.rs`, `src/db.rs`,
`src/input/index.rs`, `src/input/login.rs`,
`src/locking.rs`, `src/private_fs.rs`, `src/recovery.rs`.
Test-only changes/references: `src/import.rs`,
`src/r4_review_tests.rs`, `src/yubikey_hardware_tests.rs`.
New test files: `src/input/login_cancellation_tests.rs`,
`src/kdbx_header_tests.rs`, `src/kdbx_import_tests.rs`, `src/kdbx_test_fixtures.rs`.
Documentation: this file, `YUBIKEY.md`, `YUBIKEY-BOUNDED.md`,
`YUBIKEY-VALIDATION.md`. Historical evidence remains labeled historical.
All 25 pre-existing files under contrib/examples/tests and all 22 existing vendor
files are byte/mode-identical to the initial manifest; none of the old acceptance
or deployment scripts were executed. No unrelated work was reset, cleaned or staged.

## Evidence and review handoff

Parent logs, snapshot, remediation-only diff, final artifacts, controller JSON,
source manifests and preservation checks:
`/home/david/.hermes/cache/scratch/jaiba-remediation-20261105-145300/`.
The original first-round freeze remains there unchanged. Final follow-up source,
logs, corrected PTY evidence, artifact copies and new review freeze are under
`round2/`. First-round internal QA rejection:
`/home/david/.hermes/cache/scratch/jaiba-fresh-qa-67z5dmu8/QA-REPORT.md`.
User-requested workstation FIDO investigation paused this work; its passive
findings and no-reset/no-driver-change record are in `round2/FIDO-INTERFERENCE.md`.
No FIDO2 SSH restoration is claimed by this remediation report.
A/F worker RED/GREEN evidence: `/home/david/.hermes/cache/scratch/jaiba-af-38eky8n7/`.
D/E worker RED/GREEN, fixture generator and supplementary XC evidence:
`/home/david/.hermes/cache/scratch/jaiba-de-fixes-ca4i0uef/`.
C worker RED/GREEN: `/home/david/.hermes/cache/scratch/jaiba-memory-origin-ixauq_5u/`.
Parent has inspected the remediation diff and test additions. Any subsequent
fresh-context internal QA report is evidence, not final independent approval.
Read-only QA/source-freeze evidence is kept externally so the review does not
silently amend reviewed source. Leave the candidate uncommitted for the distinct
reviewer; a build/test pass is not permission to publish or deploy.

## Remaining gates before disposable NixOS integration

1. Separate fresh review of frozen source, dependencies, A–F regressions, recovery
   procedure and explicitly deferred nusb/KDF/timing risks. Resolve blockers or
   obtain an explicit bounded acceptance decision; then authorize any commit.
2. Build reviewed source/locked closure in an isolated Nix derivation; preserve the
   existing production fallback and exact executable-identity relationship. Desktop
   release bytes alone are not an integration artifact. No silent 4.0→4.1 conversion.
3. Separately authorize/coordinate real-key testing with synthetic databases only:
   bidirectional XC interoperability including actual format/padding edge cases,
   full-factor create/save/rekey/export/recovery, real wrong-slot/denial/removal,
   no-touch/cancellation, explicit serial with unreadable neighbors, interface and
   descriptor cleanup. Neither historical evidence nor software tokens qualifies
   the current executable. No user touches were requested in this phase.
4. Qualify native responsiveness and encrypted persistence separately with
   representative/strong KDFs and slow/error storage; retain truthful durability
   failure and controller fail-closed behavior. Do not credit timeout as acceptance.
5. In the disposable environment, test UID1503/runtime/private-file admission,
   actual controller/exact Nix-store identity, provider lifecycle, terminal-sensitive
   clipboard routing/expiry, key-removal trigger, two frontends and uncertain
   deletion/recovery on the final artifact. Live production remains separately
   authorized and NO-GO here.
