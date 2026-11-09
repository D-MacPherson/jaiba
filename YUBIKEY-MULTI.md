# Explicit multi-device authorization and physical-session pinning

Implementation amendment to `YUBIKEY.md`; not hardware acceptance or deployment.
The older serial-only constructor/rescan descriptions in historical validation
and bounded-candidate receipts are superseded, not retroactively revalidated.

## Configuration

```toml
[yubikey]
slot = 2
serials = [39269826, 39269828]
```

This explicitly authorizes either already-configured physical device. The native
algorithm has no built-in authorized serials. The two serials above appear only
in examples and synthetic/opt-in acceptance tests. `serial = 39269826` remains a
legacy singleton and is never expanded. Saving preferences serializes the policy
as `serials`, retaining the same authorization set. Reject mixed `serial` and
`serials`, empty lists, duplicates, zero, wrong types, unknown fields, missing
slot, slots other than 1/2, and values outside u32.

Neither this config nor matching slot numbers establishes interchangeability:
the existing challenge-response factor material must already match. Jaiba does
not program devices, extract secrets, rekey a vault, remove factors, or fall back.
The serial is public metadata, not device attestation. Successful complete-factor
KDBX authentication remains necessary.

## Operation contract

- Native selection enumerates supported adapter-visible candidates once, opens
  and claims descriptor-validated OTP interface zero, and reads each serial on
  that same opened handle. Among accessible authorized candidates, the smallest
  serial wins, independent of list/enumeration order. Nonselected claims drop.
- Ordinary unreadable/busy/disconnected/unsupported candidates do not hide an
  accessible authorized device. If none is accessible, retain the first such
  diagnostic instead of falsely claiming absence. Reported global enumeration,
  cancellation and deadline failures stay fatal even after a candidate matches.
  nusb's preexisting sysfs iterator may omit failed probes; absence is not proof
  that no physical device exists.
- The chosen **nusb Device and claimed Interface** live in thread-local shared
  outer `Operation` state. All nested operations, library clients and cloned
  complete keys reuse this physical session. Serial reads, HMAC, staged and
  published verification do not reopen a bus/address or serial descriptor.
- A failed selected exchange poisons that operation. No rediscovery, retry,
  another allowed key, same-address replacement, or even a replacement advertising
  the same serial can resume it. Protocol failure/cancellation gets one bounded
  best-effort reset before normal claim/device release. A fresh outer operation
  is required to retry. Removal is observed by native I/O, not an atomic guarantee
  against unplugging immediately after the last completed exchange.
- At outer-scope drop the claim and handle release. `DatabaseKey` never holds
  live USB resources indefinitely: it retains only its concrete serial/slot plus
  the original unperformed complete credential. Each KDBX open/save still runs a
  fresh challenge on a clone; no responses, transformed keys or completed-key
  caches are retained.
- The opened vault separately freezes its authorization policy and keyfile/path
  policy. Saving with a retained concrete key cannot substitute another serial.
  After locking, a fresh all-factor authentication can choose the other allowed
  key, even if current preferences were subsequently edited.
- Login direct handlers encompass create/save/independent unlock/install and
  primary unlock/recovery/install. Settings direct handlers encompass complete
  new-key construction/save/verification. Draft persistence encompasses primary
  verification and sidecar write/reads. Existing event-loop and save scopes nest
  into the same session rather than extending its deadline.
- The current-password verification and later password-change confirmation are
  separate UI operations, as before. No interface claim is held while a person
  edits password fields. Confirmation constructs a fresh complete key under the
  frozen policy and pins its concrete choice through commit/verification. This
  implementation does not exercise real rekeying as part of multi-key acceptance.
- The qualified backend is nusb; the new authorization/pinned-HMAC APIs fail closed
  for rusb/Windows rather than leaving an unpinned fallback. No UID confinement,
  Nix isolation, public-serial ACL, FIDO/CCID permissions or lock protocol changes
  are part of this source amendment.

The shared 30-second native deadline, cancellation checks, KDBX4 guards, complete
password/keyfile factors and recovery durability semantics remain in force. The
budget is cooperative and does not preempt KDF/filesystem/kernel stalls.

## Offline evidence and seams

`src/yubikey_multi_tests.rs` uses production policy and real full-factor KDBX
crypto, with a test-only native boundary replacing enumeration/open/serial/HMAC
I/O. `vendor/challenge_response/src/test_sessions.rs` gives each simulated
physical handle a distinct identity and traces open, serial, HMAC, abort and
close. Replacing the same address does not revive an old handle. This is distinct
from the existing `LocalChallenge` software model, and is **not physical USB
acceptance**. New regressions cover either/neither/both authorized keys,
unauthorized neighbors, deterministic choice, unreadable/global diagnostics,
scoped claim lifetime, same-address/same-serial replacement, no in-operation
retry, separate full-factor reauthentication on the other key, creation/install,
password-change commit, staged/published failure receipts and recovery.

Build without running Cargo's tests directly:

```sh
cargo test --locked --offline --bin jaiba --no-run --message-format=json > "$TMPDIR/build.json"
```

Use the test executable from that invocation's compiler-artifact JSON, freeze its
bytes and SHA-256, then run it in the existing read-only-host, private HOME/TMPDIR,
no-network/no-USB Bubblewrap runner. Do not run pre-existing untracked `tests/`,
`examples/` or `contrib/` artifacts. Broad suite, formatting/lint, packaging and
independent review gates must pass before a commit; this document is not such a
receipt.

## Later authorized hardware acceptance: one shared ciphertext

Three ignored, explicit-opt-in tests use only fixed synthetic filenames under a
canonical, owned, private absolute `TMPDIR`, with a separately private `HOME`
beneath it. They never read production paths, print database/keyfile contents or
HMAC responses, program a device, or overwrite an existing artifact. Initial
creation uses create-new 0600 files only; both subsequent invocations are read
only. Failed creation leaves its new incomplete fixture for inspection; never
reuse that root for creation.

After independent review and explicit physical authorization, prepare a new
private root and private HOME there, use a frozen compiler-reported test binary,
and set:

```sh
export JAIBA_YUBIKEY_MULTI_TEST='39269826,39269828:2'
```

Run **one exact test per process** under an external whole-process-group timeout:

```sh
"$TEST_BIN" --exact --ignored --nocapture \
  yubikey_tests::multi_hardware::disposable_shared_ciphertext_create_on_a
"$TEST_BIN" --exact --ignored --nocapture \
  yubikey_tests::multi_hardware::disposable_shared_ciphertext_read_on_a
"$TEST_BIN" --exact --ignored --nocapture \
  yubikey_tests::multi_hardware::disposable_shared_ciphertext_read_on_b
```

Keep the identical TMPDIR/HOME and files across these three invocations. Touch
serial39269826 for creation/read-on-A and serial39269828 for read-on-B. Sequential
physical swaps are permitted **between** invocations; both plugged in is also
valid because each test authorizes its exact serial. Preserve the emitted common
ciphertext SHA-256 plus each native full-factor success. A timeout, permission
error, disappearance or cancellation is failure/inconclusive, never successful
interchangeability evidence. No negative credential or rekey attempt is needed
for these read-only interchangeability tests. Preserve normal USB/driver/FD
pre/post acceptance checks; do not reset/rebind devices or alter ACLs to force a
pass.

The ordinary `shared_ciphertext_harness_with_simulated_native_sessions` test
exercises this exact create/read procedure using the native I/O seam and checks
that reuse cannot overwrite a fixture. It does not establish that the two real
keys have matching factor material. These ignored real tests have not been run
by the implementation worker.
