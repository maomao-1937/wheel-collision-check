from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Generator(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy2(ROOT / 'examples' / 'generate.py', self.root / 'generate.py')

    def run_generator(self, code):
        result = subprocess.run([sys.executable, str(self.root / 'generate.py')], capture_output=True, text=True)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)

    def test_idempotent_and_preserves_unrelated_files(self):
        self.run_generator(0)
        output = self.root / 'generated'
        wheels = sorted(output.glob('*.whl'))
        before = [(p.name, p.read_bytes(), p.stat().st_mtime_ns) for p in wheels]
        unrelated = output / 'my-notes.txt'
        unrelated.write_text('personal data', encoding='utf-8')
        self.run_generator(0)
        self.assertEqual(before, [(p.name, p.read_bytes(), p.stat().st_mtime_ns) for p in wheels])
        self.assertEqual(unrelated.read_text(encoding='utf-8'), 'personal data')
        self.assertEqual(len(wheels), 6)

    def test_changed_target_refused_before_other_creation(self):
        output = self.root / 'generated'
        output.mkdir()
        target = output / 'wrapper-1.0-py3-none-any.whl'
        target.write_bytes(b'user file')
        self.run_generator(2)
        self.assertEqual(target.read_bytes(), b'user file')
        self.assertEqual(list(output.iterdir()), [target])

    def test_existing_non_directory_refused(self):
        output = self.root / 'generated'
        output.write_text('user file', encoding='utf-8')
        self.run_generator(2)
        self.assertEqual(output.read_text(encoding='utf-8'), 'user file')


if __name__ == '__main__':
    unittest.main()
