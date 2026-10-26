import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def make_wheel(folder, name, files=None, pure=True, metadata=None, wheel=None,
               records=None, extra=None):
    dist = name.replace('-', '_')
    info = dist + '-1.0.dist-info'
    payload = dict(files or {})
    payload[info + '/METADATA'] = metadata or f'Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n\n'.encode()
    payload[info + '/WHEEL'] = wheel or f'Wheel-Version: 1.0\nGenerator: synthetic-test\nRoot-Is-Purelib: {str(pure).lower()}\nTag: py3-none-any\n\n'.encode()
    record = info + '/RECORD'
    rows = []
    for path, body in payload.items():
        if not path.endswith('/'):
            digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode()
            rows.append([path, 'sha256=' + digest, str(len(body))])
    rows.append([record, '', ''])
    out = io.StringIO(newline='')
    csv.writer(out, lineterminator='\n').writerows(records if records is not None else rows)
    payload[record] = out.getvalue().encode()
    path = Path(folder) / f'{dist}-1.0-py3-none-any.whl'
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for key, body in payload.items():
            archive.writestr(key, body)
        for key, body in extra or []:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                archive.writestr(key, body)
    return path


class CLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.a = make_wheel(self.temp.name, 'alpha', {'ns/a.py': b'a'})
        self.b = make_wheel(self.temp.name, 'beta', {'ns/b.py': b'b'})

    def run_cli(self, expected, *options, a=None, b=None):
        run = subprocess.run([sys.executable, str(ROOT / 'wheel_collision_check.py'),
                              '--format', 'json', *options, str(a or self.a), str(b or self.b)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
        data = json.loads(run.stdout)
        self.assertEqual(data['exit_code'], expected)
        self.assertEqual(run.stderr, '')
        return data

    def test_namespace_directories_are_shared(self):
        self.run_cli(0)

    def test_identical_file_is_conflict(self):
        self.b = make_wheel(self.temp.name, 'beta', {'ns/a.py': b'a'})
        result = self.run_cli(1)
        self.assertEqual(result['conflicts'][0]['kind'], 'exact')
        self.assertEqual(result['conflicts'][0]['owners'][0]['sha256'], hashlib.sha256(b'a').hexdigest())

    def test_prefix_and_explicit_directory_conflicts(self):
        for files in ({'ns': b'file'}, {'ns/a.py/': b''}):
            with self.subTest(files=files):
                self.b = make_wheel(self.temp.name, 'beta', files)
                self.run_cli(1)

    def test_casefold_unicode_policy(self):
        self.a = make_wheel(self.temp.name, 'alpha', {'CAF\u00c9.py': b'a'})
        self.b = make_wheel(self.temp.name, 'beta', {'cafe\u0301.py': b'b'})
        self.run_cli(1)
        self.run_cli(0, '--case-policy', 'sensitive')

    def test_data_mapping_and_layout(self):
        self.a = make_wheel(self.temp.name, 'alpha', {'same.py': b'a'})
        self.b = make_wheel(self.temp.name, 'beta', {'beta-1.0.data/platlib/same.py': b'b'})
        self.run_cli(1)
        self.run_cli(0, '--layout', 'split')

    def test_internal_mapped_collision(self):
        self.a = make_wheel(self.temp.name, 'alpha', {'x.py': b'a', 'alpha-1.0.data/purelib/x.py': b'a'})
        self.run_cli(1)

    def test_internal_file_and_explicit_directory_same_path(self):
        self.a = make_wheel(self.temp.name, 'alpha', {'occupied': b'x', 'occupied/': b''})
        self.run_cli(1)

    def test_unsupported_schemes_and_console_wrappers_have_priority(self):
        self.b = make_wheel(self.temp.name, 'beta', {'ns/a.py': b'a', 'beta-1.0.data/scripts/tool': b'hello',
            'beta-1.0.dist-info/entry_points.txt': b'[console_scripts]\ncommand = ns.a:main\n'})
        result = self.run_cli(3)
        self.assertEqual(len(result['unverified']), 2)
        self.assertTrue(result['conflicts'])

    def test_unknown_entrypoint_group_is_unverified(self):
        self.b = make_wheel(self.temp.name, 'beta', {'beta-1.0.dist-info/entry_points.txt': b'broken'})
        self.run_cli(3)

    def test_traversal_absolute_backslash_and_windows_paths(self):
        for name in ('../x', '/x', 'a/../x', 'a//x', 'C:/x', 'a\\x', 'a/./x', 'a./x', 'nul.py', 'a:stream'):
            with self.subTest(name=name):
                self.b = make_wheel(self.temp.name, 'beta', {name: b'x'})
                self.run_cli(2)

    def test_duplicate_zip_and_symlink(self):
        self.b = make_wheel(self.temp.name, 'beta', {'x': b'x'}, extra=[('x', b'x')])
        self.run_cli(2)
        item = zipfile.ZipInfo('link')
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.b = make_wheel(self.temp.name, 'beta', extra=[(item, b'target')])
        self.run_cli(2)

    def test_hash_tamper_and_missing_record(self):
        self.b = make_wheel(self.temp.name, 'beta', {'x': b'x'}, records=[['beta-1.0.dist-info/RECORD', '', '']])
        self.run_cli(2)
        self.b = make_wheel(self.temp.name, 'beta', {'x': b'x'}, records=[['x', 'sha256=' + 'A'*43, '1'], ['beta-1.0.dist-info/RECORD', '', '']])
        self.run_cli(2)

    def test_duplicate_record_row_and_wrong_size(self):
        for rows in ([['x', '', ''], ['x', '', '']], [['x', 'sha256=' + 'A'*43, '99']]):
            self.b = make_wheel(self.temp.name, 'beta', {'x': b'x'}, records=rows)
            self.run_cli(2)

    def test_metadata_and_info_identity(self):
        for metadata, wheel in ((b'Name: other\nVersion: 1.0\n', None),
                                (b'Name: beta\nName: beta\nVersion: 1.0\n', None),
                                (None, b'Wheel-Version: 2.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n'),
                                (None, b'Wheel-Version: 1.0\nRoot-Is-Purelib: maybe\nTag: py3-none-any\n')):
            self.b = make_wheel(self.temp.name, 'beta', metadata=metadata, wheel=wheel)
            self.run_cli(2)

    def test_multiple_info_and_wrong_data_identity(self):
        for files in ({'other-1.0.dist-info/METADATA': b'x'}, {'other-1.0.data/purelib/x': b'x'}):
            self.b = make_wheel(self.temp.name, 'beta', files)
            self.run_cli(2)

    def test_duplicate_distribution_identity(self):
        self.run_cli(2, b=self.a)

    def test_bounded_decompressed_bytes(self):
        self.b = make_wheel(self.temp.name, 'beta', {'big': b'0' * (17 * 1024 * 1024)})
        self.run_cli(2)

    def test_bad_zip_and_input_count(self):
        self.b.write_bytes(b'not zip')
        self.run_cli(2)
        run = subprocess.run([sys.executable, str(ROOT / 'wheel_collision_check.py'), str(self.a)], capture_output=True)
        self.assertEqual(run.returncode, 2)

    def test_data_container_cannot_be_regular_file(self):
        for path in ('beta-1.0.data', 'beta-1.0.data/purelib'):
            self.b = make_wheel(self.temp.name, 'beta', {path: b'x'})
            self.run_cli(2)

    def test_explicit_directories_and_signature_exclusions(self):
        self.b = make_wheel(self.temp.name, 'beta', {'ns/': b'', 'ns/b.py': b'x'},
                            extra=[('beta-1.0.dist-info/RECORD.jws', b'synthetic-not-a-signature')])
        self.run_cli(0)

    def test_archive_entry_and_metadata_budgets(self):
        self.b = make_wheel(self.temp.name, 'beta', {f'x/{n}': b'' for n in range(10001)})
        self.run_cli(2)
        self.b = make_wheel(self.temp.name, 'beta', metadata=b'Name: beta\n' + b' ' * (1024 * 1024))
        self.run_cli(2)

    def test_wheel_tag_and_missing_record_self(self):
        self.b = make_wheel(self.temp.name, 'beta', wheel=b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: cp311-none-any\n')
        self.run_cli(2)
        self.b = make_wheel(self.temp.name, 'beta', records=[])
        self.run_cli(2)

    def test_encrypted_flag_rejected(self):
        self.b = make_wheel(self.temp.name, 'beta')
        raw = bytearray(self.b.read_bytes())
        start = 0
        while (start := raw.find(b'PK\x01\x02', start)) >= 0:
            raw[start + 8] |= 1
            start += 4
        self.b.write_bytes(raw)
        self.run_cli(2)


if __name__ == '__main__':
    unittest.main()
