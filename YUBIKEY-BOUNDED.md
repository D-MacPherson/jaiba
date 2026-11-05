# Bounded YubiKey candidate — implementation handoff, NOT deployment acceptance

The amended independent review withdrew conditional approval of this candidate.
See `YUBIKEY-REMEDIATION.md` for subsequent A–F repairs and current validation.
The implementation/build counts below are historical, not approval of the repaired
source. Native timeouts remain cooperative; nusb initialization/probe limitations
remain explicit, unresolved upstream issues.

This supersedes the unbounded-wait implementation described in the historical
`YUBIKEY-VALIDATION.md`. That document's hardware results and binary hashes belong
to the **old** candidate. None qualify this vendored backend. No USB operations
were performed by the bounded-operation implementation worker.

## Serial-selection repair: current uncommitted candidate

The independent review found that propagating every serial-read failure made an
accessible configured token unusable when another token was unreadable. Both
native discovery entrypoints now share the same production disposition logic:
ordinary candidate access/busy/disconnection/layout failures leave `serial: None`
in all-list results; explicit serial discovery continues until the requested
serial matches. If no serial matches, an unreadable candidate may be the target:
its first error is retained instead of reporting absence. A completely readable
nonmatching enumeration still reports `DeviceNotFound`. No first-token fallback
is used by the app. Explicit discovery stops at its matching serial; all-list
continues and can still fail after seeing that match.

Cancellation and deadline errors remain fatal, with checks after actual I/O and
before classification. Global list failures are fatal too, including enumeration
nested inside serial-read/open. They carry a typed wrapper preserving the cause;
nusb open errors retain their detail, and unsupported OTP layouts have a distinct
error. The 30-second shared deadline and separate 100ms best-effort reset allowance
are unchanged; no crypto, padding, CRC, factor, cache, worker or protocol change
was made by this repair.

KeePass's descriptor type has public fields but is not publicly nameable through
its crate exports. The app therefore retains its established explicit-serial
`get_yubikey(Some(serial))` constructor. Only on its `NoKeys`/`KeyNotFound` result,
a native explicit-serial diagnostic rescan recovers access versus true-absence
information, under the same budget. If the device appears during that rescan,
authentication still fails with availability-changed/retry guidance; it does not
install credentials from a failed initial selection or omit any factor.

Fresh worker-only validation of these source bytes:

- Full offline suite: **146 passed, 0 failed, 9 ignored** (95.10s).
- Focused `yubikey_tests::`: **41 passed, 0 failed, 8 ignored** (52.80s), overlapping
  the full suite. Sixteen new discovery regression definitions use fake enumeration
  and serial I/O through the real native/app selection code, including KeePass's
  per-challenge rediscovery. No software selection algorithm replaces production.
- Two ignored subprocess helpers were actually executed by ordinary parent
  regressions; seven hardware tests remain unexecuted. No USB was accessed.
- Root fmt, changed vendored-source fmt, `git diff --check`, locked/offline
  all-targets Clippy (compile-only), and release build passed. Clippy retains
  only the five previously recorded warning categories. Release version is
  `jaiba 2026.7.0`; this is not a deployment artifact or acceptance verdict.
- Release SHA-256:
  `764f3ada1a2518069d51152d8b1c655778cb381897c8cb6feed5d0f02fa29950`.
- Test SHA-256:
  `c49e5bfc6daa11d06f184a63d0639f76631ae99fb4bd3b6b9327b3d6f1c1456c`.

Exact freeze, copied artifacts, source snapshot, RED/GREEN logs, fresh
`frozen-candidate-{full,focused}.log`, and handoff:
`/home/david/.hermes/cache/scratch/jaiba-yubi-serial-repair/`.
Independent review must be repeated against this new freeze. Earlier hardware
results belong to earlier artifact hashes and are not fresh acceptance of this
repair; no historical acceptance record is rewritten here. The XC/Wine-busy
readback blocker remains untouched, and no genuine XC-created 4.1 roundtrip has
been established. No commit, deployment, production access or USB operation was
performed by this worker.

## Previous bounded freeze validation (before serial-selection repair)

- `cargo fmt --check`, targeted vendored-source rustfmt check, and
  `git diff --check`: passed.
- `cargo test --locked --bin jaiba --no-run` built
  `target/debug/deps/jaiba-a0a34717bdd36a50`; the exact artifact ran in the
  required no-network/read-only-host/no-USB sandbox: **130 passed, 0 failed,
  9 ignored**, 48.50 seconds. The two ignored subprocess helpers were also
  actually executed by their ordinary parent regressions; the seven hardware
  tests were not executed. Focused reruns overlap these definitions.
- `cargo clippy --locked --all-targets`: passed with only the five existing
  categories (unused theme helper, password enum naming, Vec parameter, theme
  sort and test-module placement). Warning-free lint is not claimed.
- `cargo build --locked --release`: passed; `target/release/jaiba --version`
  returned `jaiba 2026.7.0`.

Regression-first RED/GREEN and final logs:
`/home/david/.hermes/cache/scratch/jaiba-yubi-bounded/implementation/`.
Behavioral REDs reproduced the header unwind, creation/export receipt flattening,
unbounded native polling, response-slice panic, unresponsive real-signal native
poll fixture, late auth installation, late private publication and lock-time
filesystem transaction before cancellation. A final regression also caught an
unused USB deadline incorrectly failing password-only draft persistence; deadline
activation is now native-only, while cancellation remains unconditional. Each corresponding focused GREEN
passed before the final broad suite. This is implementation-worker evidence,
not a completed independent review or real-hardware acceptance.

## Native policy and limits

`Cargo.toml` patches `challenge_response = 0.5.46` to
`vendor/challenge_response`; keepass remains 0.13.20 and nusb remains 0.2.9.
The direct dependency explicitly disables default features and selects `nusb`:
enabling the upstream default would instead select rusb. No crypto implementation,
HMAC padding, CRC calculation, factor composition or key-cache behavior is changed.
The original unperformed complete DatabaseKey is still retained. Every native
keepass clone independently challenges the hardware.

The patched native protocol uses an absolute **30-second** operation deadline.
This is a policy allowance for ordinary multi-touch interaction, not a measured
SLA. The application input handler and save/open/create/lock transaction scopes
share this budget with nested enumeration, serial reads, frame writes, status
polling, response reads and reset. Nested scopes use the earlier deadline, never
a fresh 30 seconds for each poll. Public native operations also establish a finite
fallback when no application scope exists. The budget includes elapsed KDF time
but does not preempt a KDF. Deadline enforcement activates only if a native
operation is actually used in that scope (shared by nested scopes); an unused
USB budget must not change password-only verified-draft success behavior. Signal
cancellation always applies. Expiry produces an error, not an authentication bypass.

Native control transfers request at most **100ms**, clipped to remaining budget;
checks occur before and after transfers and every protocol poll. Cancellation is
an `Arc<AtomicBool>` installed on the calling thread and loaded, never consumed,
by I/O helpers. A successful transfer cannot turn cancellation into success.
Cancellation/deadline errors are propagated through enumeration, rather than
silently classified as a missing device. Adjacent oversized challenge, short HID
report and overlong response-buffer panic paths fail closed.

On error, a device session attempts **one** best-effort write-state reset with a
100ms transfer timeout, preserving the original error even if cleanup fails.
All paths then drop normal owned nusb interfaces/device handles. Only interface
zero with HID/boot-keyboard descriptors (class3/subclass1/protocol1) is claimed;
unrecognized layouts fail rather than guessing. FIDO/CCID interfaces are not
claimed or detached. Linux nusb Interface Drop releases the claim and attempts
kernel-driver reattachment. Device Drop unregisters its descriptors. Physical
reattachment success still needs operator verification.

**This is not a hard wall-clock bound on the kernel.** nusb 0.2.9's synchronous
control-transfer wait parks until completion; its timeout requests cancellation,
but return still depends on kernel completion. Enumeration/open/claim/release
and reattachment use synchronous filesystem/syscall paths. Arbitrary kernel,
filesystem or KDF stalls cannot be preempted by this userspace USB budget. No
background worker is abandoned to manufacture a deadline. No application worker
is added. nusb's existing process-lifetime event thread is distinct from a new
credential-bearing worker and is not removed by this patch.

## Cooperative signal locking and truthful recovery

Release registration admission, nonce syntax/replay guards and the **18-second**
controller wire protocol are unchanged. The admitted Registration owns the atomic
SIGUSR2 handler and its thread-local cancellation guard for its whole lifetime.
There is no new desktop/non-vault registration bypass or signal admission mode.
A raw signal interrupts an in-flight library operation; **only a valid fresh
request nonce authorizes locking and acknowledgment**. Invalid, missing or
replayed requests produce no new ack/lock and consume the cancellation flag on
the normal coordinator path so later authentication is not permanently poisoned.

After a synchronous handler returns, the event loop checks pending lock work
before clipboard expiration I/O or accepting another input event. Authentication
results and primary/private-file publication boundaries check cancellation again.
All synchronous credential clones have returned/dropped before an ack is written.

For a valid hardware-session SIGUSR2 lock, new draft persistence is deliberately
cancelled **before beginning filesystem transactions or KDFs**. The exact editor
is captured in memory, unlocked credentials are dropped, and ack says
`locked:true,draft_persisted:false`. This is a controller **failure**, not durable
success. Keep the window/process open and authenticate with every factor to
recover. The protocol is not extended to buy time for additional touches. An
already durable sidecar is still independently revalidated with no retained key;
credential drop precedes that key-free metadata/ciphertext validation.

Password-only/password+keyfile lock persistence retains its prior verified-draft
success behavior. Direct/inactivity locks can still attempt full-factor verified
persistence within the shared normal budget; a later coordinator signal cancels
that attempt. Lost hardware, expired deadlines and failed verification never
weaken the sidecar factors or cause a durable ack. Expensive KDF/storage and
actual device behavior still require separate qualification against 18 seconds.

## Parser and transaction-reporting repairs

A regression first reproduced malformed zero-width KDBX4 compression-header
reauthentication panicking with an undurable memory draft. The bounds-only header
preflight now rejects the compression scalar width and also checks scalar widths
in public custom-data variant dictionaries, not only the KDF dictionary. It is
not an authenticated parser replacement or comprehensive hostile-resource defense.
Login remains usable, the memory editor survives, and retrying the repaired
synthetic file restores the exact buffer.

Creation and encrypted export preserve `SaveError::Write` versus
`SaveError::Verification` through anyhow rather than flattening the receipt.
Pre-replacement failure says creation/export failed and leaves the target
uncommitted. Post-replacement failure explicitly says **created/replaced, but not
verified**, retains the file, and asks for independent all-factor authentication.
Creation's additional failed reopen is also classified as committed-unverified;
it returns to ordinary authentication, not a misleading create retry. No success
is reported from a merely completed rename.

## KDBX4.0: explicit limitation and safe migration policy

KDBX4.0 remains readable, not writable by keepass 0.13.20. Jaiba refuses an
unsupported save and keeps the editor/primary unchanged. There is **no automatic
4.0 -> 4.1 conversion**. An XC GUI switch producing 4.1 has not been verified;
do not assume or invent one.

For any separately authorized migration: retain the untouched original and
backups; use a new disposable copy in an independently verified tool that really
supports explicit 4.1 output **without removing password, keyfile or hardware**;
inspect the output version independently; reopen with all factors; verify that
omitting any required factor fails; compare entries/notes/attachments and policy;
then prove a Jaiba edit/save/export and independent XC readback on that copy.
If explicit 4.1 output is unavailable, stop and use XC for writes; do not use
plaintext export/import or factor removal as a migration workaround. Do not
redirect a primary or retire the original until separate review and authorization.

## Offline and operator test accounting

Ordinary validation builds only `cargo test --locked --bin jaiba --no-run`, then
runs the exact reported binary under read-only-host/no-network/no-USB Bubblewrap
with only private scratch writable. Pre-existing untracked `contrib/`, `examples/`
and `tests/` are neither executed nor added. Clippy all-targets is compile-only.

The six **old** ignored names remain accounted for:

- `config::tests::startup_config_child`: ignored helper, executed by ordinary
  `config::tests::malformed_config_aborts_startup_before_clipboard_or_runtime_services`.
- `yubikey_tests::hardware::disposable_hardware_lifecycle`
- `yubikey_tests::hardware::disposable_xc_fixture_open`
- `yubikey_tests::hardware::disposable_xc_fixture_roundtrip`
- `yubikey_tests::hardware::disposable_hardware_wrong_slot`
- `yubikey_tests::hardware::disposable_hardware_timing`

The five hardware names are not executed by ordinary tests. The historical timing
name now measures save plus **memory-only false-durability** signal-lock ack, not
fresh durable sidecar publication; old 4.316/12.091 second runs do not apply.

Three newly ignored names:

- `yubikey_tests::native_signal_child`: subprocess-only no-USB fixture, executed by
  ordinary `yubikey_tests::native_signal_cancellation_and_lock_run_in_private_subprocess`.
  A true SIGUSR2 interrupts the vendored Backend polling loop, then production
  Registration processes the fresh request and exact ack is read back. It checks
  no early ack, Login/key drop/false durability, exact editor reauthentication,
  missing/malformed/replayed cancellation reset, and repeated deadline fd/thread
  counts. Synthetic claim leases also test cleanup and no success after a
  successful transfer races with cancellation. This is not software HMAC standing
  in for the native polling loop, but it is still not USB evidence.
- `yubikey_tests::hardware::disposable_hardware_no_touch_deadline`: parent/operator
  only; after native fixture setup, withhold touch for three 30-second native
  opens. Each must return deadline error within 29..33 seconds, retain the editor
  and return fd/thread counts to baseline. No SIGUSR2 is sent. Allow a separately
  supervised whole-group timeout exceeding all three attempts plus setup touches.
- `yubikey_tests::hardware::disposable_hardware_stalled_signal`: parent/operator
  only; native all-factor fixture creation/unlock followed by withheld-touch
  native decrypt, true SIGUSR2, cancellation, key-drop/false ack and reauth.

Hardware command/API handoff (never run ordinary tests with USB exposed):

```sh
# Parent prepares a NEW canonical private TMPDIR, HOME below it, restricted USB
# exposure, and whole-process-group external timeout; coordinates touches first.
export JAIBA_YUBIKEY_TEST=39269826:2
"$TEST_BINARY" --ignored --exact \
  yubikey_tests::hardware::disposable_hardware_stalled_signal \
  --nocapture --test-threads=1
```

Creation/unlock needs multiple separate touches. At `STALLED PHASE` release the
key and withhold touch; a test thread sends SIGUSR2 after 500ms. Native decrypt
must return cancellation and lock+ack must complete below the test's 2-second
target. Only after `STALLED CANCEL COMPLETE` resume touches for full-factor
reauthentication. An early device error/completion, unexpected touch, external
kill or timeout is failure/inconclusive, never acceptance. Inspect interface-zero
reattachment and FIDO/CCID coexistence after each attempt; verify no owned child
or USB descriptor remains. Never change permissions, drivers, services or slots.
The test creates only new synthetic files and a create-new private JSON report.

Require separate native no-signal withheld-touch deadline, repeated cancellation
resource counts with the real device, physical removal, permission-denial,
wrong-slot, serial selection/two-token coexistence, padding-edge interoperability,
new XC-created 4.1 roundtrip, expensive-KDF and storage qualification. A process
external timeout must terminate the entire owned group and verify no survivor;
forced termination may require operator replug and is not evidence of normal
cleanup. Independent frozen-source review, broad parent gates and all deployment
acceptance remain open. No commit, push, deployment or production access occurred.
