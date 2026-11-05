# Jaiba downstream patch provenance

Source: crates.io challenge_response 0.5.46, copied byte-for-byte from the local
Cargo registry before targeted edits. Registry archive checksum:
`951c671a3cd201dd2ce911801b82631a9524fd6485ba5c10b08279e72c23a741`.

The archive's `.cargo_vcs_info.json` records git
`099597f94aa871b30b8ebe7c87925561615be0e4`, **dirty:true**. Do not claim that clean
Git commit alone reproduces the published archive. `UPSTREAM-FILES.sha256`
records every original copied file before patching (it is not a checksum file
for the patched tree). Original licenses remain alongside the source.

Changed upstream files: Cargo.toml (test-only support feature), src/lib.rs
(scoped public operations, bounds and cleanup), src/error.rs (typed failures),
src/usb.rs (bounded protocol loops, checked response slicing and cleanup),
src/usb/nusb.rs (native transfer timeout/checks, per-device discovery error isolation
with fatal cancellation/deadline/global-enumeration propagation, retained access
diagnostics and distinct unsupported layouts,
descriptor-validated OTP-interface-only claims and one best-effort abort reset).
New source: src/operation.rs (thread-local absolute budget/cancellation),
src/test_support.rs (dev-only fake backend using the real protocol methods).

No cryptographic primitive, padding, CRC or factor composition is replaced.
Unchanged original src/sec.rs, src/hmacmode.rs, src/otpmode.rs and configuration
implementations remain upstream bytes. The rusb backend is not qualified by this
patch; Jaiba explicitly uses nusb on Linux. See ../../YUBIKEY-BOUNDED.md for
policy, syscall/KDF limitations, test accounting and operator-only acceptance.
