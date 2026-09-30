# Changelog

All notable changes to unmicro, the Dev7 / Micro (`.cryptedmicro`) decryptor.

## 3.5

Recovery, guessing throughput, and file naming.

### Added
- **Extension repair** after decryption. The crew randomises file extensions
  before encrypting (a video named `.jpg`, an archive named `.png`), so unmicro
  now reads each recovered file's true type from its decrypted bytes and, on a
  genuine cross-category mismatch, writes the output under the corrected
  extension and reports the swap. Conservative: container families (docx/zip,
  mov/m4a, wav/webp) and same-category names are left alone. Uses the `filetype`
  library when present, an internal table otherwise. On by default; `--no-fix-ext`
  disables it.
- **`--scavenge FILE`** (repeatable). Pull candidate keys out of an unencrypted
  dump: a memory image, the pagefile or hibernation file, a `strings` listing,
  an implant log. The key is a typed string and often survives there in the
  clear. ASCII and UTF-16LE.
- **`--dumb-brute`**. Classic incremental brute, 3 characters up to the longest
  recovered key, over the alphabet these operators type. `--charset`
  {observed, turkish, full}, default `turkish` (Turkish + English lowercase and
  digits). Pauses and explains before a length that would take too long.
- **`--checkpoint FILE`**. Save sweep progress and resume, skipping finished
  tiers and fast-forwarding the current one. Keyed to the files; matches the
  tier by name so it resumes across flag changes.
- **`--gpu` and `--gpu-info`** (experimental). OpenCL sweep for NVIDIA and AMD.
  Key derivation stays on the CPU; the device runs a startup AES self-test
  against the CPU back end and disables itself on any mismatch; every GPU hit is
  re-validated on the CPU. It can make the search faster or not engage; it
  cannot make it wrong or miss a key. Developed without a GPU in CI, so the
  OpenCL execution is validated by the on-device self-test.
- **Full-auto**: a bare `python3 unmicro.py` searches every drive, tries every
  route, and writes to `./unmicro-recovered`.

### Changed
- **`--workers` defaults to every CPU core** (was 1). Set `--workers 1` for a
  single process.
- **Bounded-memory sweep.** The candidate de-duplication is capped
  (`--seen-cap`, default 1,000,000) and cleared at the cap rather than growing
  without bound, which fixes an out-of-memory kill deep into a `--brute` run.
  De-duplication stays exact, so no candidate is skipped.

### Notes
- No change to the cryptography: AES-256 is not attacked. Recovery still rests on
  the tiny keyspace (no KDF) and known-plaintext verification.
- This tool only decrypts. It cannot produce a `.cryptedmicro` file. Your
  encrypted files are never modified, renamed or deleted.

## 3.2

- Baseline released build: autodiscovery, recovered operator keys, the fitted
  key model (`--brute`/`--deep`), structural verification of every recovery, and
  multi-key handling for interrupted encryption runs.
