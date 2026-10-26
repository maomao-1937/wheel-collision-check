# Observed verification

Executed on 2026-10-26 in Windows with CPython 3.11.15 (AMD64). All tests use the standard library. No third-party wheels were downloaded, installed, imported, or extracted.

## Test-first evidence

Before the implementation existed, the CLI subprocess suite could not run. A minimal reporting stub then established a focused assertion failure: `test_identical_file_is_conflict` expected exit 1 but received exit 0 with an empty conflict list. Implementing validation and comparison made the initial 17 tests pass.

Two later focused regression probes were observed failing before fixes:

- `test_data_container_cannot_be_regular_file`: regular `.data`/`.data/purelib` container files incorrectly returned 0 instead of 2. They are now rejected.
- `test_internal_file_and_explicit_directory_same_path`: a ZIP containing both `occupied` and `occupied/` incorrectly returned 0 instead of 1. File and directory evidence is now retained separately.

## Current local results

```sh
python -m unittest discover -s tests -v
```

The final verification copied only source/text files into a new temporary project, excluding `.git`, environments, caches, generated directories, and all `.whl` archives. From that copy, unittest discovery ran **26 tests: OK, no skips**. The copy then ran all **8 checks.json subprocess probes**, each using the same Python interpreter; all returned the expected code. The first probe generated its own six synthetic fixtures. The probe codes in order were `0, 0, 0, 1, 2, 3, 1, 0`.

The CLI suite covers shared namespace directories, identical payload conflicts, exact/prefix/explicit-directory conflicts within and across wheels, NFC/casefold versus sensitive spelling, purelib/platlib spreading and both layouts, unsupported schemes/wrappers with collision preservation and exit priority, malformed entry-point syntax, unsafe and Windows-special paths, duplicate ZIP entries and RECORD rows, missing records, hash tampering, size mismatch, symlink metadata, encrypted flags, metadata and filename identities, multiple `.dist-info` roots, foreign `.data`, filename/tag mismatch, repeated distributions, malformed ZIPs, entry/metadata/decompressed-file budgets, and signature exclusions. Generator tests verify six deterministic archives, unchanged mtimes on rerun, preservation of unrelated files, refusal of modified targets before partial creation, and refusal of a non-directory output path.

Authored source/text files were scanned for CRLF; all use LF. The supplied `.gitattributes` was preserved. The fresh-copy verification is reproducible with a temporary source copy and Python subprocesses; it does not depend on preexisting example archives.

## Limits of this evidence

These are synthetic local CLI and resource-boundary tests, not a formal parser proof or exhaustive hostile-ZIP fuzzing. The combined-entry and combined-byte guards are implemented; the suite directly exercises per-entry, per-file and parsed-metadata limits rather than every possible threshold combination. No actual encrypted archive was decrypted; an encrypted central-directory flag was rejected. The signed-record sample is intentionally synthetic and no signature is verified. Linux and hosted CI are separate gates, not claimed by this local result. No real installation, import/ABI compatibility, existing-environment ownership, dependency resolution, package adoption, or security certification was tested.
