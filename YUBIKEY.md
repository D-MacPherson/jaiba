# Native YubiKey challenge-response candidate for Jaiba R4

## Status: development candidate, not production R4 acceptance

The amended independent review withdrew the earlier conditional approval. See
`YUBIKEY-REMEDIATION.md` for the subsequent A–F repairs, current validation and
remaining upstream/deployment limitations. Historical test results below are not
approval of the corrected candidate; a separate fresh review is still required.

This enables the native `keepass` 0.13.20 `challenge_response` implementation for
an explicitly authorized set of existing YubiKey HMAC-SHA1 devices in one slot. It is not device enrollment, key programming,
a secret-service replacement, a deployed executable, or a migration tool.
Historical `R4-LOCKING.md` describes the baseline R4 work; this document adds the
hardware-factor scope and limitations without changing that protocol.

**Current multi-device/pinned-handle amendment:** see `YUBIKEY-MULTI.md`. It supersedes
the old serial-rediscovery implementation; hardware interchangeability still needs
separate acceptance against the same disposable ciphertext on both physical keys.

**Bounded-operation background:** see `YUBIKEY-BOUNDED.md` for the vendored native
30-second shared operation budget, 100ms transfer/cancellation policy, scoped
interface-zero cleanup, unchanged nonce/replay protocol, and fail-closed
memory-only hardware signal-lock policy. A waiting touch can no longer keep the
userspace status loop running indefinitely. This does not bound arbitrary KDF,
filesystem or kernel stalls; nusb timeout completion still depends on the kernel.
Independent review and real hardware cleanup/timing acceptance are still required.
No worker abandonment, key-response cache, weaker sidecar, skipped verification
or relaxed 18-second controller threshold is used. Prior hardware evidence in
`YUBIKEY-VALIDATION.md` belongs to the old unbounded implementation.

**Removal-time limitation:** a new recovery sidecar requires fresh hardware
operations. If the key is removed before an edited draft is persisted, the only
safe existing R4 outcome is Login with credentials dropped, the hidden draft
retained in memory, and `draft_persisted:false`. KEEP THAT WINDOW OPEN. Closing
it, killing it, or losing power can lose that undurable draft. Repeated locks
cannot turn memory-only preservation into durable success. Already durable
sidecars can be revalidated by pinned inode/metadata/ciphertext without retaining
an authentication key.

## Build and explicit configuration

The manifest pins `keepass = "=0.13.20"` with `save_kdbx4`, `totp`, and
`challenge_response`. The application lockfile resolves `challenge_response`
0.5.46 and `nusb` 0.2.9. On Linux the selected backend does not require a libusb
development package; platform-specific inactive dependencies may still appear in
the lockfile. The upstream nusb backend is experimental; this candidate patches the native
protocol and claims only descriptor-validated OTP interface zero. Do not broaden device
permissions or change key slots to make a test pass.

```sh
cargo fmt --check
cargo test --locked --bin jaiba --no-run
cargo clippy --locked --all-targets
cargo build --locked --release
./target/release/jaiba --version
```

Configure the normal `~/.config/rama/jaiba_config.toml` (a disposable HOME for
validation). Put all top-level settings before the hardware table:

```toml
default_database = "~/.local/share/rama/default.kdbx"
# keyfile = "~/.local/share/rama/default.keyx"
auto_lock = 300
clipboard_timeout = 15

[yubikey]
slot = 2
serials = [39269826, 39269828]
```

Both fields are mandatory: slot must be integer 1 or 2; serials must be a nonempty
list of distinct nonzero u32 values. Legacy `serial = 39269826` authorizes only that
singleton, never both devices; `serial` and `serials` cannot be mixed. Accessible
authorized devices are selected by ascending serial, independent of enumeration
or configuration order. No unrestricted first-device selection, environment
override, enrollment, or silent fallback is provided. Omit the entire table to retain
existing password-only/password+keyfile behavior. Unknown/misspelled settings,
partial tables, wrong types, out-of-range values and malformed TOML fail startup
rather than replacing the config with defaults. Saving settings retains the
complete hardware table. Changing config does not enroll/change a vault's factors.

A successful open/create pins database path, keyfile preference and hardware
authorization policy for that session, including subsequent lock/reauthentication
and master-password changes. The retained complete key holds only the concrete
selected serial/slot; a fresh full-factor reauthentication may use another device
from the frozen policy. A write using a retained key never substitutes another
serial if its selected key is unavailable. Preferences apply to a new session, not an already
opened vault. A password change preserves keyfile+hardware; no in-app hardware
removal/rotation or hardware-only authentication is implemented. Jaiba continues
to add its password contribution even when the entered password is empty.

## Actual library integration and supported formats

The builder calls the vendored `ChallengeResponseKey::get_authorized_yubikey(serials)`,
constructs `ChallengeResponseKey::YubikeyChallenge(device, slot.to_string())`, and
attaches it with `DatabaseKey::with_challenge_response_key`. Enumeration itself
performs USB I/O. Authorization reads the serial on the exact opened handle whose
OTP interface-zero claim is retained until the outer operation ends. Nested
challenges reuse that handle, not a reopened bus/address or serial match. Reported
transfer failure poisons the operation; no retry or substitution follows. Serial
is a public selection hint, not cryptographic attestation of a physical device.

Both native discovery entrypoints isolate ordinary per-device serial access,
busy, disconnection and unsupported-layout errors, so an unreadable neighbor
cannot hide the configured accessible token. All-list retains unreadable devices
with `serial: None`; explicit selection continues to a matching serial and
retains the first unreadable diagnostic if none matches. A wholly readable
nonmatching enumeration establishes absence only among adapter-visible candidates:
nusb's Linux sysfs iterator can silently omit failed probes. `DeviceNotFound`
therefore does not prove physical absence or exclude OS access/probe uncertainty.
Cancellation, deadlines and reported global enumeration failures (even inside a
candidate's serial-read/open) stay fatal;
checks occur after actual I/O before classifying an error. nusb open detail and
unsupported-layout errors remain distinguishable.

The app no longer uses KeePass's filtering constructor or a diagnostic rescan.
A single native pass retains the first unreadable diagnostic when no authorized
device is accessible; global list/cancellation/deadline errors remain fatal even
after a candidate matches. An accessible authorized neighbor tolerates ordinary
per-device probe failure. The library adapter returns its concrete descriptor
without exporting its type or retaining claims in `DatabaseKey`. A completed
hardware exchange with wrong password, keyfile or slot secret normally becomes
`Incorrect key`: it cannot reliably say which factor was wrong. Jaiba does not
retry with a factor omitted. Matching serial authorization/slot numbers do not
make differently programmed keys interchangeable: their existing factor material
must already match. No programming, secret export or migration is performed.

The app retains the **unperformed** complete `DatabaseKey`. KDBX4 open/save use
consumed clones; the library performs the challenge using that container's KDF
seed. Reopening identical bytes executes another challenge with the same seed;
a save generates fresh seeds/IVs and executes another challenge. There is no
application response/composite/transformed-key cache, manual `perform_challenge`,
or production `LocalChallenge` path. Full keys flow through primary saves,
deletes/import destination writes, independent staged and published verification,
rekey, encrypted KDBX exports and R4 draft encryption/decryption. A normal save
requires three challenges; new draft publication requires primary authentication,
sidecar encryption, and two independent sidecar decryptions (four). A touch-enabled
key can require a separate touch for each operation. The UI remains synchronous;
SIGUSR2 cancellation is polled by the native backend and processed before further
input/clipboard I/O. A valid hardware signal lock does not attempt fresh durable
publication: it promptly drops credentials and truthfully reports memory-only
retention of an edited draft. See the bounded handoff for exact policy.

Hardware-enabled open explicitly rejects KDB, prerelease KDB2 and KDBX3 **before
device discovery**. KDBX3 does not execute the upstream hardware challenge and
must never be treated as hardware-authenticated. KDBX4 can be read; upstream saves
support only KDBX4.1. Older writable-format conversion is not added. Convert a
new disposable copy using XC if needed, never silently rewrite a primary.

A bounds-only scan of KDBX4 outer KDF/public-custom dictionaries runs before
native decrypts (including sidecars), validating framing and scalar widths for
all factors. Configured hardware unlock additionally rejects empty or over-64-byte
challenge seeds before device discovery. Independent decrypts of an already-built
native key retain the vendored backend's typed `InvalidChallenge` length guard;
keepass does not expose key-factor metadata for a separate caller-side preflight.
Password-only opens do not inherit the hardware seed ceiling: a genuinely
authenticated synthetic database with a 128-byte Argon2id salt is tested. This is
not KeePassXC long-salt interoperability evidence. KDBX3 imports/decrypts now
validate the legacy compression, transform-rounds and inner-stream scalar widths
before library decoding, without rejecting legitimate KDBX3 reads. None of these
checks authenticate the header, replace keepass crypto parsing, establish hostile
KDF CPU/memory limits, or constitute a comprehensive parser/fuzzing audit.

The operator's genuine XC 2.7.10 fixture was reported as KDBX4.0. This common
XC format can authenticate, but cannot be saved by this keepass version; full
read/write interoperability with that fixture is therefore a known limitation,
not a passed gate. The open-only test explicitly checks unchanged ciphertext and
retained editor after the unsupported save. Jaiba-created 4.1 -> XC readback is
a separate gate. No automatic upgrade is performed.

The existing R4 transaction guard, exact authenticated ciphertext revision,
stale-write refusal, assigned-entry-ID retry behavior and post-replacement
uncertainty remain. Hardware loss before verified staging leaves the old primary
untouched. Loss after replacement retains the advanced revision and reports
uncertainty, never success; rekey retains the new complete credentials when
replacement has occurred. KDBX export preserves factors; explicit CSV/JSON export
is still plaintext and does not become hardware-encrypted. KDBX import source
credentials are separate and the old password-only source import UI is not
expanded to select hardware/keyfile factors. Clipboard implementation and release
lock protocol are unchanged.

Keys and consumed clones use upstream zeroize-on-drop, not proof of exhaustive
allocator/compiler/library/swap/core/terminal erasure. Never log DatabaseKey Debug
or response/local-secret material.

## KeePassXC compatibility still requires real bidirectional evidence

KDBX4 factor composition matches the inspected XC implementation for one challenge
factor, including password+optional keyfile. This is not blanket interoperability
acceptance. The Rust backend uses zero/ff variable padding, whereas XC pads with
PKCS7-style length bytes. Existing variable-input HMAC-LT64 configuration is the
intended mode; fixed-64-input slots are not generally interchangeable. Trailing
padding-byte seed cases, especially a 32-byte seed ending in `0x20`, need separate
hardware acceptance. No slot is reprogrammed by these tests. Multi-hardware-factor
XC databases, KDBX3 legacy challenge composition, and historical production files
are not covered. Software-secret tests cannot establish USB/touch/permissions or
XC compatibility.

## Offline regressions and containment

Only tracked application tests and newly added `src/yubikey*_tests.rs` are inputs.
Pre-existing untracked `contrib/`, `examples/`, and `tests/` are not run or added.
Build outside the test sandbox if necessary, then invoke the executable reported
by `cargo test --locked --bin jaiba --no-run` directly (not an older artifact).
Use a new private scratch directory and the required read-only-host/no-network
runner; do not grant USB to ordinary tests:

```sh
bwrap --unshare-net --cap-drop ALL --ro-bind / / --dev /dev \
  --bind "$TMPDIR" "$TMPDIR" --setenv TMPDIR "$TMPDIR" \
  "$TEST_BINARY" --nocapture
```

`src/yubikey_test_backend.rs` is compiled only under `cfg(test)`. Its thread-local
software-token model uses the real keepass LocalChallenge HMAC/KDBX code, with
operation-boundary faults. This is not hardware evidence and cannot be selected
in a release build. `faults_only()` does not replace native hardware selection or
key material and is used by the actual-hardware lifecycle test. Its injected
failure means simulated unavailable-at-boundary, not physical unplug/permission
qualification. The lifecycle harness is also exercised offline with the software
token so its handler/assertion sequence is not entirely unexecuted scaffolding.

Regression coverage includes failclosed configuration/startup, hardware-required
unlock, unsupported formats/oversized seed, pinned reauthentication/rekey with
keyfile, production create/edit-save handlers, staged/published failure retention,
repeated operation counts/fresh ciphertext, encrypted export, missing-at-lock
memory preservation/credential drop and full-factor sidecar restart recovery.
All original R4 regressions remain in the suite.

## Opt-in disposable real-hardware tests (operator only)

Do not run these unattended. Coordinate multiple touches and allow only the
already-authorized serial39269826 slot2. Use a new private absolute canonical
TMPDIR and a private HOME directory beneath it. Tests reject missing opt-in or
non-isolated HOME, create only new synthetic inputs, never program hardware, and
never read a supplied production vault. Keep an external process timeout: upstream
can still stall in the kernel despite its userspace budget. A killed/timed-out
run is INCONCLUSIVE/FAILURE, not acceptance.
Only the operator may choose how to expose the authorized device to a no-network,
read-only-host sandbox. Ordinary `--dev /dev` deliberately has no USB device.
Do not replace that with broad unreviewed device access.

Set `JAIBA_YUBIKEY_TEST=39269826:2`, then run **one exact ignored name**, e.g.:

```sh
"$TEST_BINARY" --ignored --exact \
  yubikey_tests::hardware::disposable_hardware_lifecycle \
  --nocapture --test-threads=1
```

Available exact names:

- `yubikey_tests::hardware::disposable_hardware_lifecycle`: production create,
  factor omissions/wrong password/serial, real full-factor save with injected
  pre-staging/staged/post-replacement failures, unavailable-at-lock with memory
  recovery, durable sidecar restart, pinned rekey and KDBX export. It leaves
  `TMPDIR/jaiba-hardware-output.kdbx` and `.key` for independent XC readback,
  password **new synthetic master**, two entries with notes **synthetic partial
  notes**. Existing outputs are refused. Other generated fixtures are removed.
- `yubikey_tests::hardware::disposable_xc_fixture_open`: additionally set
  `JAIBA_XC_FIXTURE` to the canonical path `TMPDIR/synthetic-xc.kdbx`, a NEW copy
  of the operator-created disposable XC vault. Set `JAIBA_XC_FIXTURE_PASSWORD`
  to its synthetic password (default **synthetic master**). It verifies that
  password alone fails, full native authentication succeeds, and KDBX4.0 save
  fails with retained editor/unchanged copy. It never converts the primary.
- `yubikey_tests::hardware::disposable_xc_fixture_roundtrip`: for **KDBX4.1 only**, additionally set
  `JAIBA_XC_FIXTURE` to a NEW XC-created password+hardware-only synthetic vault
  beneath TMPDIR, canonically named `synthetic-xc.kdbx`, password **synthetic
  master** (or the explicit synthetic `JAIBA_XC_FIXTURE_PASSWORD`). Only a fresh copy is edited. It adds an entry, rekeys, exports the
  result to the same new output filename (no keyfile), password **new synthetic
  master**. Open that export in XC to verify the added entry/notes and all factors.
  Use a different new TMPDIR per test, since exports never overwrite.
- `yubikey_tests::hardware::disposable_hardware_wrong_slot`: separate hazardous
  negative test; requires `JAIBA_TEST_WRONG_SLOT=1`. Creates a fresh slot2 vault
  and attempts slot1 without programming either. Wrong/unconfigured/touch slot
  can hit the cooperative operation deadline. The test accepts only a completed
  challenge followed by typed KDBX4 `IncorrectKey` header-HMAC rejection. Timeout,
  cancellation, disconnection, permission/discovery failures and unsupported slot
  responses fail as infrastructure/inconclusive, never clean wrong-key rejection.
- `yubikey_tests::hardware::disposable_hardware_timing`: actual private request
  nonce, SIGUSR2, `Registration::process`, ack readback, then independent
  assertions of Login/key drop/false-durability memory retention for edited drafts. `Registration::for_test` is exposed
  only under cfg(test); release registration/UID/path admission is unchanged.
  Default `JAIBA_YUBIKEY_KDF=representative` is the actual keepass default
  Argon2d, 50 iterations, 1 MiB, parallelism4. `JAIBA_YUBIKEY_KDF=strong` selects
  Argon2id, 64 MiB, parallelism4, 3 iterations; override only its iteration count
  with `JAIBA_YUBIKEY_ITERATIONS` (1..10000) for an explicit expensive profile.
  It prints the actual KDF label and save/lock durations and creates a private
  `jaiba-hardware-timing-<pid>.json`. The unchanged threshold is 18 seconds: a
  completed lock over that threshold fails the test even if it eventually emits
  a durable ack. Touch time is part of the measurement. It does not run the real
  installed controller/provider or establish production qualification.

## Historical earlier-candidate local verification (before independent review)

These counts/hashes do not validate the current patch. Current policy, exact
ignored-test accounting and new hardware commands are in `YUBIKEY-BOUNDED.md`;
current build/test evidence is retained separately in the bounded handoff scratch.

- `cargo fmt --check` and `git diff --check` passed.
- Current `cargo test --locked --bin jaiba --no-run` artifact, run with the
  read-only-host/no-network/no-USB Bubblewrap command above: **118 passed,
  0 failed, 6 ignored** (five hardware tests and one subprocess-only startup
  helper, which is exercised by its ordinary parent regression).
- Focused `yubikey_tests::`: **14 passed, 0 failed, 5 ignored**; includes the
  software-token execution of the complete native-lifecycle harness sequence.
- `cargo clippy --locked --all-targets` passed with only the existing R4 warning
  categories (theme helper, password-step names, Vec argument, theme sort and
  test-module placement). `cargo build --locked --release` passed;
  `target/release/jaiba --version` returned `jaiba 2026.7.0`.
- TDD behavioral RED and focused GREEN logs are retained under
  `/home/david/.hermes/cache/scratch/jaiba-yubi-implementation/`: `red-config`,
  `red-startup`, `red-selection`, `red-format`, `red-pin`, `red-rekey`,
  `red-create`, `red-verification`, `red-seed` and corresponding GREEN `.log`
  files. Final runs: `focused-final.log`, `full-final.log`, `clippy-final.log`,
  `release-final.log`. Builds ran separately; tests ran in the sandbox.
- No real device challenge was performed by the implementation worker.
  The operator's fixture report is not counted as Jaiba hardware acceptance.

Required remaining gates: independent frozen-source review; parent gate reruns of
full fmt/test/Clippy/release checks; real XC-created fixture and XC readback of
Jaiba writes; actual USB errors/removal/touch behavior and padding edge cases;
representative/strong KDF request/ack timings; resolution of the unbounded USB wait
before production R4 acceptance; isolated NixOS/UID/helper/clipboard/service
integration. No commit, push, deployment, service/permission changes or key
programming are authorized by this implementation. The parent operator appends
actual acceptance evidence here.
