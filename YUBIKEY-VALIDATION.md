# Historical unbounded YubiKey candidate — NOT ACCEPTED / NOT DEPLOYED

Current remediation evidence is in `YUBIKEY-REMEDIATION.md`. The amended
independent review superseded the earlier conditional approval. This historical
record is retained, not a current acceptance verdict.

**Superseded implementation:** the hashes, hardware timings and counts below
belong to the earlier unbounded candidate, not the current vendored patch.
See `YUBIKEY-BOUNDED.md` for current policy and handoff. Historical failures and
unperformed gates below remain audit evidence, not erased acceptance history.

## Candidate provenance

- Branch: `feature/yubikey-challenge-response`.
- Baseline and current HEAD: `397c79f14630b16e5ffb1a38798993fedc70a5d3`.
- Implementation remains uncommitted. No push or deployment occurred.
- Implementation source freeze: `/home/david/.hermes/cache/scratch/jaiba-yubikey-parent/review-freeze.json`. All 38 recorded source/document/build-input files matched after testing. This validation document is a subsequent evidence-only addition, not an implementation change.
- All 25 pre-existing untracked files under `contrib/`, `examples/`, and `tests/` remain byte/mode-identical to the initial inventory. They were not run as acceptance scripts or added to Git.
- `src/clipboard.rs`, `src/terminal_clipboard.rs`, `src/private_fs.rs`, `src/input/edit.rs`, `src/r4_review_tests.rs`, and `validation/r4_controller_compat.py` remain byte-identical to baseline. The only `locking.rs` change exposes a helper under `cfg(test)`; release admission and wire protocol are unchanged.

Development executable:

`/home/david/src/jaiba-vault/target/release/jaiba`

SHA-256: `c2a5b9c7b6f255d6962d7e7eef1c867eb4f03ff7d74c86c03d9b95dd3b977d17`

Test executable: `target/debug/deps/jaiba-8bddac0a4cf60af0`.
SHA-256: `246f05eb9232527ca4b9a7be30f2ebf2a3f7032253022322d85c4d7b28455c12`.

## Implemented scope

See `YUBIKEY.md` for configuration and API details. Native keepass 0.13.20 challenge-response preserves complete password/keyfile/YubiKey factors through creation, unlock, pinned reauthentication, rekey, primary writes, staged/published verification, encrypted exports and recovery sidecars. The application does not manually perform or cache hardware responses. Invalid hardware configuration fails startup rather than falling back. Legacy hardware-authentication formats and oversized challenge seeds fail closed. Existing write revisions, transactions, uncertainty receipts and recovery states are retained.

## Verified offline checks

The implementation worker executed formatting, test build, contained unit tests, Clippy and release compilation. Logs were read and build/source hashes independently matched by the parent:

- `cargo fmt --check`: passed; parent additionally reran formatting.
- `cargo test --locked --bin jaiba --no-run`, then current test executable in a no-network/read-only-host/no-USB Bubblewrap sandbox: 118 passed, 0 failed, 6 ignored. The ignored set comprises five hardware tests and one subprocess-only helper exercised by its ordinary parent test. This includes the complete existing R4 regression suite.
- Focused hardware-factor suite: 14 passed, 0 failed, 5 ignored. This overlaps the full suite; it is not 14 additional unique tests.
- `cargo clippy --locked --all-targets`: passed with existing warning categories only; warning-free lint is not claimed.
- `cargo build --locked --release`: passed. Release `--version`: `jaiba 2026.7.0`.
- `git diff --check`: passed.
- Hash-pinned installed-controller-function compatibility harness: all three cases passed (no database, durable draft, failed persistence). Failed persistence produced `draft_in_memory_keep_window_open`, zero durable drafts and overall failure. UID/discovery/executable admission/provider shutdown are controlled substitutes, not production acceptance.

Logs: `/home/david/.hermes/cache/scratch/jaiba-yubi-implementation/`.

## Actual hardware and interoperability

Only newly generated disposable synthetic databases were used. Serial 39269826, existing HMAC-SHA1 slot 2, requires physical touch. No slots, secrets, device programming, permissions or services were changed.

1. Genuine KeePassXC 2.7.10 GUI created a password+YubiKey fixture in a private Xvfb/HOME/D-Bus/network-isolated sandbox. Independent `keepassxc-cli db-info` accepted password+slot2/serial and rejected password alone. Fixture SHA-256: `28a34fdd0db2f9c924efc8337de0abe3466e7a545260eccffda73e011614d371`. Actual format KDBX4.0, Argon2d169 iterations/65536 KiB.
2. Jaiba's native fixture-open test passed. KDBX4.0 save was explicitly unsupported, with unchanged ciphertext and retained editor. This is read compatibility, not full 4.0 read/write support.
3. Actual-hardware lifecycle test passed: password+keyfile+YubiKey creation, omitted-factor/wrong-password/wrong-serial negatives, repeated hardware operations, pre-staging/staged/published verification failures, memory-only failed-lock recovery, durable encrypted sidecar restart/restoration, pinned rekey and encrypted export. Unavailability during these scenarios was injected at operation boundaries while retaining the real native key. It was NOT physical unplug/USB-permission qualification.
4. KeePassXC independently decrypted Jaiba's KDBX4.1 export with all three factors and confirmed two entries with exact expected synthetic notes. Omitting hardware failed HMAC validation. Saved-output SHA-256: `49494714111519440f12bc626b56eec11a6324c7b365e6985ca7d3b66964d482`.
5. Actual release executable, isolated HOME and a new synthetic copy: full-factor unlock; unfinished Notes editing; inactivity lock; full-factor reauthentication; exact partial-buffer restoration; verified save; normal exit. All five milestones passed. No clipboard copy/read or production registration was exercised.

There were four completed passing hardware harness invocations (fixture open, lifecycle, and two timing profiles), covering three distinct ignored test names. These are separate from the ordinary offline suite. Evidence:

`/home/david/.hermes/cache/scratch/jaiba-yubikey-parent/`

In particular: `hardware-open-retry2/`, `hardware-lifecycle/xc-independent-readback.json`, `hardware-representative/`, `hardware-strong/`, and `release-ui/result.json`.

## Controller deadline measurements

Measured request/ack tests used actual hardware, private nonce/request, real SIGUSR2, production `Registration::process`, exact emitted ack readback and subsequent Login/key-drop/durability assertions. Touch time is included. They do not run the installed controller/provider or production UID.

| Profile | Save | Lock through durable ack | 18-second result |
| --- | ---: | ---: | --- |
| Argon2d, 50 iterations, 1 MiB, parallelism4 | 4.272811820 s | 4.316118881 s | passed this run |
| Argon2id, 3 iterations, 64 MiB, parallelism4 | 4.867546152 s | 12.091348483 s | passed this run |

The largest observed completed lock among these two cases was 12.091348483 seconds. Neither is a worst-case bound or production KDF measurement. The native USB status loop has no overall timeout/cancellation, and human touch can be delayed indefinitely. Therefore the existing 18-second deadline is NOT qualified as sufficient in general. It was not changed. The synchronous event loop can remain unable to lock/drop credentials/ack during a stalled operation. This remains a source-acceptance blocker.

## Failed attempts and runner defect

Initial genuine XC saves/readback attempts timed out without coordinated physical touch; later properly coordinated attempts passed. Jaiba's first fixture-open attempt exceeded an external 240-second test timeout; it was not counted as acceptance. The original scratch runner killed its Bubblewrap wrapper but left a test child holding USB. Parent verified and terminated that exact owned child, corrected whole-process-group termination, and operator reconnected the key. The intervening discovery-error retry is not evidence of a missing physical key or a clean hardware error classification.

The native backend detaches multiple device interfaces. Forced termination skipped normal restoration; after the operator replug and completed tests, OTP/FIDO interfaces again bound to `usbhid` and `ykman list` saw serial39269826. Final inspection found no remaining owned Jaiba/Xvfb test processes. The isolated fixture GUI was stopped; no production processes were stopped/restarted. This exposes an interface-coexistence/abrupt-termination acceptance concern, not permission to modify udev or drivers.

## Independent review gate: NOT PASSED

A fresh reviewer independently read the frozen source and ran the full offline suite and four additional synthetic probes. Its provider blocked its final response; no completed verdict was delivered. Its recorded probe output confirms:

- Failure at each of four draft hardware boundaries retained memory, dropped unlocked credentials, returned false durability and allowed later recovery.
- Creation/export post-replacement failures can be displayed as generic failures despite a created/replaced target. These routes predate this delta and need explicit uncertainty-message review.
- A separate upstream malformed non-KDF scalar header still panics during reauthentication with a memory-only draft; the challenge-seed guard does not cover all parser panics. This is an inherited limitation, not a demonstrated seed-guard bypass. A production unwind can lose an undurable draft.

These probes are evidence of behaviors, not four passing acceptance cases or a completed review. Files: `/home/david/.hermes/cache/scratch/jaiba-independent-review-w28yhwvz/`.

A separate read-only Claude review was attempted twice; both failed before inference due OAuth refresh/expired-session errors. No credential files, authentication settings or unrelated processes were changed. Consequently independent review remains incomplete and the local-commit gate is closed.

## Remaining work / NO-GO

- Complete independent review and resolve the unbounded hardware-wait/lock cancellation problem without response caching, weakened factors, dropped drafts, skipped verification or controller changes.
- Resolve/review inherited parser-panic and post-replacement reporting limitations; add durable in-repository regressions for any repairs.
- Decide explicit support/migration for common XC KDBX4.0; no silent format conversion was added.
- Physical removal during save/lock, true permission denial, actual wrong-slot behavior, two-token selection/coexistence, trailing-padding-seed interoperability, and genuine XC-created4.1 roundtrip remain unqualified. Wrong-slot is covered by the offline software-token model, not actual slot1 hardware acceptance.
- Repeat timing across expensive KDFs, delayed/absent touches, slow storage and hardware errors; observed fast passes do not establish a worst case.
- Complete fault/power-cut durability and disposable NixOS/UID1503/exact-store-identity/helper/clipboard/provider/two-frontend acceptance.

No production database was accessed/copied/decrypted/modified. No SSH connection to production, replacement of Jaiba/BiTTY, NixOS activation, service/controller/udev change, push, or deployment was performed. Installed R4 remains the fallback. Production remains NO-GO until separately authorized.
