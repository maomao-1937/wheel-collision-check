"""Create deterministic synthetic wheel examples; never overwrite changed files."""
import base64
import csv
import hashlib
import io
from pathlib import Path
import sys
import zipfile


def wheel_bytes(name, files, *, pure=True, tamper=False):
    info = name + '-1.0.dist-info'
    payload = dict(files)
    payload[info + '/METADATA'] = f'Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n\n'.encode()
    payload[info + '/WHEEL'] = f'Wheel-Version: 1.0\nRoot-Is-Purelib: {str(pure).lower()}\nTag: py3-none-any\n\n'.encode()
    rows = []
    for key, body in sorted(payload.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode('ascii')
        rows.append([key, 'sha256=' + digest, str(len(body))])
    rows.append([info + '/RECORD', '', ''])
    record = io.StringIO(newline='')
    csv.writer(record, lineterminator='\n').writerows(rows)
    payload[info + '/RECORD'] = record.getvalue().encode()
    if tamper:
        payload['shared/module.py'] = b'# changed after RECORD was written\n'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for key, body in sorted(payload.items()):
            entry = zipfile.ZipInfo(key, date_time=(2026, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, body)
    return buffer.getvalue()


def generate():
    root = Path(__file__).resolve().parent
    output = root / 'generated'
    fixtures = {
        'alpha': ({'shared/module.py': b'# alpha payload\n'}, {}),
        'beta': ({'shared/other.py': b'# beta payload\n'}, {}),
        'collision': ({'shared/module.py': b'# collision payload\n'}, {}),
        'spread': ({'spread-1.0.data/platlib/shared/module.py': b'# spread payload\n'}, {}),
        'wrapper': ({'wrapper-1.0.dist-info/entry_points.txt': b'[console_scripts]\nsynthetic = shared.module:main\n'}, {}),
        'tampered': ({'shared/module.py': b'# original payload\n'}, {'tamper': True}),
    }
    expected = {name + '-1.0-py3-none-any.whl': wheel_bytes(name, files, **options)
                for name, (files, options) in fixtures.items()}
    try:
        if output.is_symlink() or output.exists() and not output.is_dir():
            raise ValueError('generated must be a normal directory')
        # Preflight every existing target before writing any missing target.
        for name, body in expected.items():
            target = output / name
            if target.is_symlink() or target.exists() and (not target.is_file() or target.read_bytes() != body):
                raise ValueError('refusing changed or unrelated existing target: ' + name)
        output.mkdir(exist_ok=True)
        for name, body in expected.items():
            target = output / name
            if not target.exists():
                with target.open('xb') as stream:
                    stream.write(body)
        print('6 synthetic wheels ready in examples/generated (existing identical files preserved)')
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(generate())
