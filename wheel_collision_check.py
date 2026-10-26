"""Compare a bounded wheel payload footprint without installing or extracting it."""
import argparse
import base64
import configparser
import csv
from email import policy
from email.parser import Parser
import hashlib
import io
import itertools
import json
from pathlib import Path
import re
import stat
import sys
import unicodedata
import zipfile
import zlib

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_ALL_ENTRIES = 50000
MAX_METADATA = 1024 * 1024
RESERVED = re.compile(r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', re.I)
FILENAME = re.compile(r'([A-Za-z0-9_]+)-([A-Za-z0-9_.!+]+)(?:-([0-9][A-Za-z0-9_]*))?-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)\.whl\Z')


class Invalid(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def normalized_name(value):
    return re.sub(r'[-_.]+', '-', value).lower()


def safe_path(value, directory=False):
    require(isinstance(value, str) and 0 < len(value) <= 512, 'invalid_path_length')
    require(not any(unicodedata.category(c).startswith('C') for c in value), 'path_control_character')
    require(not any(c in value for c in '\\:<>"|?*'), 'nonportable_path')
    path = value[:-1] if directory and value.endswith('/') else value
    parts = path.split('/')
    require(len(parts) <= 64 and all(p and p not in ('.', '..') for p in parts), 'unsafe_path')
    require(all(not p.endswith((' ', '.')) and not RESERVED.match(p) for p in parts), 'nonportable_path')
    return path


def headers(body, required):
    require(len(body) <= MAX_METADATA, 'metadata_budget')
    message = Parser(policy=policy.default).parsestr(body.decode('utf-8', errors='strict'))
    require(not message.defects, 'malformed_metadata')
    values = {}
    for key in required:
        rows = message.get_all(key, [])
        require(len(rows) == 1 and str(rows[0]).strip(), 'missing_or_duplicate_' + key.lower())
        values[key] = str(rows[0]).strip()
    return message, values


def inspect_wheel(path, budget):
    match = FILENAME.fullmatch(path.name)
    require(match is not None, 'unsupported_wheel_filename')
    dist, version, _, python_tag, abi_tag, platform_tag = match.groups()
    require(path.is_file() and path.stat().st_size <= MAX_ARCHIVE, 'archive_size_or_missing')
    info_name = dist + '-' + version + '.dist-info'
    data_name = dist + '-' + version + '.data'
    hashes, sizes, bodies, directories = {}, {}, {}, set()
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) <= MAX_ENTRIES, 'entry_budget')
        budget['entries'] += len(entries)
        require(budget['entries'] <= MAX_ALL_ENTRIES, 'combined_entry_budget')
        seen = set()
        for item in entries:
            require(item.orig_filename == item.filename, 'nul_in_zip_name')
            key = safe_path(item.filename, item.is_dir())
            require(item.filename not in seen, 'duplicate_zip_path')
            seen.add(item.filename)
            require(not item.flag_bits & 1, 'encrypted_zip')
            kind = stat.S_IFMT(item.external_attr >> 16)
            require(kind in (0, stat.S_IFREG, stat.S_IFDIR), 'symlink_or_special_file')
            require(not (kind == stat.S_IFDIR and not item.is_dir()), 'directory_mode_mismatch')
            require(item.file_size <= MAX_FILE, 'file_size_budget')
            if item.is_dir():
                require(item.file_size == 0, 'nonempty_directory')
                directories.add(key)
                continue
            digest, length, chunks = hashlib.sha256(), 0, []
            keep = key.startswith(info_name + '/') and key.rsplit('/', 1)[-1] in (
                'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt')
            with archive.open(item) as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    length += len(chunk)
                    budget['bytes'] += len(chunk)
                    require(length <= MAX_FILE and budget['bytes'] <= MAX_TOTAL, 'decompressed_budget')
                    digest.update(chunk)
                    if keep:
                        require(length <= MAX_METADATA, 'metadata_budget')
                        chunks.append(chunk)
            require(length == item.file_size, 'zip_size_mismatch')
            hashes[key], sizes[key] = digest.hexdigest(), length
            if keep:
                bodies[key] = b''.join(chunks)

    all_paths = set(hashes) | directories
    info_roots = {p.split('/')[0] for p in all_paths if p.split('/')[0].endswith('.dist-info')}
    require(info_roots == {info_name}, 'dist_info_identity')
    require(all(p.split('/')[0] == data_name for p in all_paths if p.split('/')[0].endswith('.data')), 'data_identity')
    require(all(len(p.split('/')) >= 3 for p in hashes if p.split('/')[0] == data_name), 'regular_data_container')
    for name in ('METADATA', 'WHEEL', 'RECORD'):
        require(info_name + '/' + name in bodies, 'missing_' + name.lower())
    metadata, values = headers(bodies[info_name + '/METADATA'], ('Metadata-Version', 'Name', 'Version'))
    require(re.fullmatch(r'2\.[0-9]+', values['Metadata-Version']) is not None, 'metadata_version')
    require(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?', values['Name']) is not None, 'metadata_name')
    require(normalized_name(values['Name']) == normalized_name(dist), 'metadata_name_identity')
    require(values['Version'].replace('-', '_') == version, 'metadata_version_identity')
    wheel, wheel_values = headers(bodies[info_name + '/WHEEL'], ('Wheel-Version', 'Root-Is-Purelib'))
    require(wheel_values['Wheel-Version'] == '1.0', 'wheel_version')
    require(wheel_values['Root-Is-Purelib'] in ('true', 'false'), 'root_is_purelib')
    expected_tags = {'-'.join(t) for t in itertools.product(python_tag.split('.'), abi_tag.split('.'), platform_tag.split('.'))}
    tags = [str(t).strip() for t in wheel.get_all('Tag', [])]
    require(tags and len(tags) == len(set(tags)) and set(tags) == expected_tags, 'wheel_tag_identity')

    record_name = info_name + '/RECORD'
    signature_names = {info_name + '/RECORD.jws', info_name + '/RECORD.p7s'}
    record_rows = {}
    reader = csv.reader(io.StringIO(bodies[record_name].decode('utf-8'), newline=''), strict=True)
    for row in reader:
        require(len(row) == 3, 'record_columns')
        key, digest, size = row
        safe_path(key)
        require(key not in record_rows and key in hashes, 'duplicate_or_missing_record_path')
        record_rows[key] = row
        if key == record_name:
            require(digest == size == '', 'record_self_hash')
        else:
            require(key not in signature_names, 'signature_in_record')
            expected = 'sha256=' + base64.urlsafe_b64encode(bytes.fromhex(hashes[key])).rstrip(b'=').decode('ascii')
            require(digest == expected, 'record_sha256_mismatch')
            require(size == str(sizes[key]), 'record_size_mismatch')
    require(set(record_rows) == set(hashes) - signature_names, 'record_coverage')

    owner = normalized_name(values['Name']) + '==' + values['Version']
    unverified = []
    entrypoint = bodies.get(info_name + '/entry_points.txt')
    if entrypoint is not None:
        try:
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(entrypoint.decode('utf-8'))
            wrapper_groups = [group for group in ('console_scripts', 'gui_scripts') if parser.has_section(group) and len(parser[group])]
            if wrapper_groups:
                unverified.append({'owner': owner, 'reason': 'generated_entrypoint_wrappers', 'groups': wrapper_groups})
        except (configparser.Error, UnicodeError):
            unverified.append({'owner': owner, 'reason': 'unparsed_entry_points'})
    return {'owner': owner, 'identity': normalized_name(values['Name']),
            'info': info_name, 'data': data_name, 'root': 'purelib' if wheel_values['Root-Is-Purelib'] == 'true' else 'platlib',
            'hashes': hashes, 'directories': directories, 'unverified': unverified}


def compare(wheels, layout, case_policy):
    nodes = {}
    unverified = [item for wheel in wheels for item in wheel['unverified']]
    for wheel in wheels:
        entries = [(p, 'file') for p in wheel['hashes']] + [(p, 'directory') for p in wheel['directories']]
        for source, kind in sorted(entries):
            parts = source.split('/')
            scheme = wheel['root']
            if parts[0] == wheel['data']:
                # The .data directory is a spreading container, not an installed directory.
                if len(parts) == 1:
                    continue
                scheme = parts[1]
                if scheme not in ('purelib', 'platlib'):
                    unverified.append({'owner': wheel['owner'], 'reason': 'unsupported_data_scheme', 'source': source})
                    continue
                if len(parts) == 2:
                    continue
                parts = parts[2:]
            target = '/'.join(parts)
            key = unicodedata.normalize('NFC', target).casefold() if case_policy == 'fold' else target
            key = ('site-packages' if layout == 'merged' else scheme) + '/' + key
            evidence = {'owner': wheel['owner'], 'source': source, 'target': target,
                        'kind': kind}
            if kind == 'file':
                evidence['sha256'] = wheel['hashes'][source]
            nodes.setdefault(key, []).append(evidence)
    conflicts = []
    for key in sorted(nodes):
        owners = nodes[key]
        files = [o for o in owners if o['kind'] == 'file']
        if len(files) > 1 or files and len(owners) > len(files):
            conflicts.append({'kind': 'exact' if len(files) > 1 else 'file_directory', 'path': key, 'owners': owners})
        parts = key.split('/')
        for length in range(1, len(parts)):
            prefix = '/'.join(parts[:length])
            parents = [o for o in nodes.get(prefix, []) if o['kind'] == 'file']
            if parents:
                conflicts.append({'kind': 'prefix', 'path': prefix, 'descendant': key, 'owners': parents + owners})
    return conflicts, unverified


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout', choices=('merged', 'split'), default='merged')
    parser.add_argument('--case-policy', choices=('fold', 'sensitive'), default='fold')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    parser.add_argument('wheels', nargs='+', type=Path, help='2..20 local .whl ZIP paths')
    args = parser.parse_args(argv)
    report = {'schema_version': 1, 'layout': args.layout, 'case_policy': args.case_policy,
              'conflicts': [], 'unverified': [], 'errors': [], 'exit_code': 0}
    try:
        require(2 <= len(args.wheels) <= 20, 'wheel_count_must_be_2_to_20')
        budget = {'entries': 0, 'bytes': 0}
        wheels = [inspect_wheel(path, budget) for path in args.wheels]
        require(len({wheel['identity'] for wheel in wheels}) == len(wheels), 'duplicate_distribution')
        report['conflicts'], report['unverified'] = compare(wheels, args.layout, args.case_policy)
        report['wheel_count'] = len(wheels)
        report['checked_bytes'] = budget['bytes']
        report['exit_code'] = 3 if report['unverified'] else 1 if report['conflicts'] else 0
    except (Invalid, OSError, zipfile.BadZipFile, zipfile.LargeZipFile, UnicodeError, csv.Error,
            RuntimeError, NotImplementedError, EOFError, zlib.error) as error:
        report['errors'] = [str(error) if isinstance(error, Invalid) else type(error).__name__]
        report['exit_code'] = 2
    if args.format == 'json':
        print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    else:
        print('wheel-collision-check: exit ' + str(report['exit_code']))
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return report['exit_code']


if __name__ == '__main__':
    sys.exit(main())
