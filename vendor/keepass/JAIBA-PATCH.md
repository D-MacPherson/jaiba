# Jaiba downstream patch — KDBX4 inner stream-ID length

Source: crates.io `keepass` 0.13.20, copied from the local Cargo registry before
the edits below. Registry checksum:
`e8014931bc1d5d427563b2c75e7b240a92353463e89cb2b4e21c98fb776c1c28`.

`UPSTREAM-FILES.sha256` records every original copied file before patching. It is
not a checksum of the patched tree. The published license remains alongside the
source.

## Root cause

`parse_inner_header` in `src/format/kdbx4/parse.rs` reads the inner random-stream
ID with `LittleEndian::read_u32`. byteorder implements that read as a 4-byte
conversion, which panics when the field body is shorter than four bytes. The
length prefix itself is taken from a bounds-checked 4-byte slice. The field is
parsed only after the header HMAC and the authenticated block stream, so a wrong
password or an unauthenticated ciphertext change returns an error and does not
reach the panic.

The adjacent inner-header reads do not have this bug. The stream key is copied
as an opaque byte string. A binary attachment returns `UnexpectedEof` when its
body is empty before the flag byte is read.

## Fix

A stream-ID body whose length is not exactly 4 returns
`Kdbx4InnerHeaderError::InvalidStreamIdLength` instead of panicking. Valid
4-byte IDs, including ChaCha20 and Salsa20 values written by this library, are
unchanged. No cipher, KDF, header HMAC, or challenge-response behavior is
replaced.

`test-support` is a dev-only feature used to build synthetic credential-valid
fixtures. Release builds of Jaiba do not enable it.

## Upstream

The same `read_u32(entry_buffer)` call is still present on
`sseemayer/keepass-rs` master. Pull request 285 fixed other unchecked slices and
the maintainer welcomed further panic hardening; it did not cover this field.
No existing issue was found for the inner stream-ID width. This fix should be
proposed upstream. This commit does not open that request or publish the fork.
