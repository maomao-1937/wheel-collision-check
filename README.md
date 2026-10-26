# wheel-collision-check

[![tests](https://github.com/maomao-1937/wheel-collision-check/actions/workflows/tests.yml/badge.svg)](https://github.com/maomao-1937/wheel-collision-check/actions/workflows/tests.yml)

Check local wheel payloads for shared files and file/directory conflicts before installation. Two wheels may have different distribution names while writing the same import path. The CLI reports owners, source paths and SHA256 hashes without installing, importing, extracting, or contacting a service.

Python 3.11+; standard library only. No setup, pip dependencies, or credentials are needed.

## Run the synthetic examples

```sh
python examples/generate.py
python wheel_collision_check.py examples/generated/alpha-1.0-py3-none-any.whl examples/generated/beta-1.0-py3-none-any.whl
# exit 0: shared/ is a shared directory; its files differ
python wheel_collision_check.py --format json examples/generated/alpha-1.0-py3-none-any.whl examples/generated/collision-1.0-py3-none-any.whl
# exit 1: shared/module.py has two owners
python wheel_collision_check.py examples/generated/alpha-1.0-py3-none-any.whl examples/generated/wrapper-1.0-py3-none-any.whl
# exit 3: console-script wrapper installation is unverified
python -m unittest discover -s tests -v
```

The generator writes six original synthetic archives into ignored `examples/generated/`. It is deterministic and idempotent: identical existing targets remain untouched; changed targets and symlinks are refused before any target is written. Unrelated files are left alone. Archives are not committed. The synthetic files contain comments and metadata, not usable third-party packages.

## Inputs and options

Pass **2..20 local `.whl` files**. Filenames must follow the supported wheel naming pattern, including optional numeric-leading build tags and dot-compressed compatibility tags. Every filename tag must match the WHEEL `Tag` header set. Names may use underscores; normalized distribution identities must be distinct. Two versions of one distribution are rejected rather than modeled as simultaneous installations.

| Option | Default | Meaning |
| --- | --- | --- |
| `--layout merged` | merged | Both purelib and platlib map to one logical `site-packages`, as in a common venv layout |
| `--layout split` | | Model purelib and platlib as separate logical roots |
| `--case-policy fold` | fold | Compare NFC-normalized, Unicode-casefolded paths conservatively |
| `--case-policy sensitive` | | Compare exact archive path spelling, including Unicode normalization |
| `--format text` | text | Brief status followed by escaped structured evidence |
| `--format json` | | One JSON object on stdout; no file body content |

Root payloads follow `Root-Is-Purelib`. Matching `{distribution}-{version}.data/purelib/` and `/platlib/` paths spread into the selected root. Container directories themselves are not installed. Other `.data` schemes, such as `scripts`, `headers`, and `data`, produce an explicit unverified result. Nonempty `console_scripts` and `gui_scripts` sections produce the same result because generated wrappers are outside the checked payload. Unparseable `entry_points.txt` is also unverified; ordinary plugin groups do not generate wrappers in this model.

## Output and exit codes

| Exit | Meaning |
| --- | --- |
| 0 | No conflict in the supported wheel-payload footprint |
| 1 | Exact shared files, file/directory equality, or file-as-directory-prefix conflicts |
| 2 | Input/setup/validation failure; comparison is incomplete |
| 3 | Unsupported spreading scheme or generated wrapper; includes any known conflicts |

Validation failure has priority over all comparison results. For valid inputs, unverified status 3 takes priority over conflict status 1. Unsupported paths are recorded in `unverified` and excluded from the mapped footprint; their unknown collisions cannot be inferred. Identical file bytes still conflict. Shared directories, including namespace-package directories without `__init__.py`, are permitted. Internal conflicts introduced by spreading paths within a single wheel are also detected.

JSON schema version 1 contains `exit_code`, `layout`, `case_policy`, `conflicts`, `unverified`, and `errors`. Valid comparisons also include `wheel_count` and `checked_bytes`. Conflict entries give a logical `path`, `kind`, and owner evidence (`owner`, original `source`, spelled `target`, file/directory `kind`, and file `sha256`); prefix conflicts also give `descendant`. Error codes are bounded validation reasons or exception class names, without archive bodies or local filesystem paths. Paths and owners come from untrusted metadata: JSON escapes them, but do not render them as raw HTML or execute them. Command-line syntax errors use argparse's usual stderr and exit 2.

## Validation and precise boundaries

The supported subset requires one coherent top-level `.dist-info` with UTF-8 `METADATA`, `WHEEL` and `RECORD`. Required identity headers are single-valued, metadata version is 2.x, wheel version is exactly 1.0, `Root-Is-Purelib` is lowercase `true`/`false`, and filename, metadata name/version and WHEEL tags agree. This is a deliberately strict subset, not complete wheel or Core Metadata conformance checking; it does not implement PEP 440 semantic version equivalence. Unfamiliar filenames or metadata can therefore be rejected with 2.

Every regular file must appear once in RECORD with exact unpadded URL-safe SHA256 and decimal byte size, except RECORD itself, whose hash/size must be empty, and optional `RECORD.jws`/`RECORD.p7s`, which must be absent from RECORD. Those signature files still participate in footprint comparison but their signatures are **not authenticated**. Directory entries are excluded from RECORD. Duplicate ZIP names/RECORD rows, missing/extra entries, tampering, encrypted entries, symlinks/special files, nonportable Windows paths, traversal, NUL/control characters, and mismatched `.data` identities are rejected. No certificate or trust assessment is made.

Fixed budgets: 32 MiB archive size per wheel; 10,000 entries per wheel and 50,000 across inputs; 16 MiB per regular file; 64 MiB actual decompressed bytes across inputs; 1 MiB for each parsed metadata/RECORD/entry-point file; paths at most 512 Unicode characters and 64 components. Reads are streamed and actual byte counts are checked in addition to ZIP declarations. CRC/decompression errors fail validation. No archive entry is written to disk.

The result concerns **wheel-supplied payload paths only**. Installers may generate bytecode, rewrite RECORD, create INSTALLER/REQUESTED/direct_url metadata, choose different installation schemes, or perform other transformations. These generated paths are not modeled. Existing environments and already installed file ownership are not inspected. Layout is a user-selected model, not detected from your interpreter. Casefold is conservative Unicode comparison, not an exact emulation of NTFS, APFS, or every operating system. No dependency resolution, target-tag/ABI/import compatibility testing, script shebang rewriting, installation simulation, vulnerability/malware detection, or security certification is provided. A result of 0 does not prove two packages can be safely installed or used together.

## 中文快速使用

用途：在安装前，比较 **2 到 20 个本地 wheel 自带文件** 是否覆盖同一路径，或出现“文件同时被当作目录”的冲突。要求 Python 3.11+，只用标准库，不联网、不安装、不导入包、不解压落盘。

```sh
python examples/generate.py
python wheel_collision_check.py --format json examples/generated/alpha-1.0-py3-none-any.whl examples/generated/collision-1.0-py3-none-any.whl
python -m unittest discover -s tests -v
```

`--layout merged` 默认将 purelib/platlib 合并；`split` 分开建模。`--case-policy fold` 默认按 NFC 加 Unicode casefold 保守比较；`sensitive` 按原始拼写比较。`--format json` 输出结构化路径、归属者和文件 SHA256，不输出文件内容。

退出码：0 表示支持范围内未发现冲突；1 表示发现冲突；2 表示输入无效、校验失败或超限；3 表示存在无法建模的 `.data` 安装方案或生成的命令行/GUI 包装脚本。2 优先，合法输入中 3 优先于 1，已知冲突仍会保留。共享目录允许，同内容的共享文件也算冲突。

只接受文档所述严格子集，并检查 RECORD 的 SHA256、长度、目录身份和标签。示例生成器拒绝覆盖已修改文件，生成的 wheel 已忽略且不提交。不能把退出 0 理解为可安全安装：本工具不检查已安装环境、依赖解析、ABI、导入可用性、安装器生成的 pyc/元数据、恶意代码或签名可信性。资源上限和更完整边界见上文。

## Evidence and alternatives

See [RESEARCH.md](RESEARCH.md) for primary-source motivation and alternatives, and [TESTING.md](TESTING.md) for observed local verification and its limits. MIT license.
