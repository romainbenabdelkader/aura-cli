"""The historical demo must not print a successful summary after a failure."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DemoScriptTests(unittest.TestCase):
    def run_demo(self, intercept=None, exit_code=0, message='', missing_asset=False):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name in ('aura_cli.py', 'demo_integrity.sh'):
                shutil.copy2(ROOT / name, work / name)
            (work / 'assets').mkdir()
            if not missing_asset:
                shutil.copy2(ROOT / 'assets/track.wav', work / 'assets/track.wav')
            interpreter = sys.executable
            if intercept is not None:
                wrapper = work / 'python-wrapper'
                wrapper.write_text(
                    '#!/bin/sh\ncase "$*" in\n*' + intercept + '*)\n'
                    + 'printf "%s\\n" ' + shlex.quote(message) + '\n'
                    + 'exit ' + str(exit_code) + '\n;;\nesac\n'
                    + 'exec ' + shlex.quote(sys.executable) + ' "$@"\n'
                )
                wrapper.chmod(0o700)
                interpreter = str(wrapper)
            return subprocess.run(
                ['bash', str(work / 'demo_integrity.sh')], cwd=work,
                env={**os.environ, 'PYTHON_BIN': interpreter},
                capture_output=True, text=True,
            )

    def assert_stopped(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('Demo summary', result.stdout)

    def test_expected_results(self):
        result = self.run_demo()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Demo summary (all expected results checked)', result.stdout)

    def test_failed_interpreter(self):
        self.assert_stopped(self.run_demo(intercept='', exit_code=1))

    def test_missing_asset(self):
        self.assert_stopped(self.run_demo(missing_asset=True))

    def test_altered_asset_unexpectedly_accepted(self):
        self.assert_stopped(self.run_demo(
            intercept='track.altered.wav', message='Verification result: VALID'))

    def test_unrelated_error_is_not_expected_rejection(self):
        self.assert_stopped(self.run_demo(
            intercept='track.altered.wav', exit_code=1, message='File missing'))

    def test_tampered_manifest_unexpectedly_accepted(self):
        self.assert_stopped(self.run_demo(
            intercept='track.tampered.aura.json', message='Verification result: VALID'))


if __name__ == '__main__':
    unittest.main()
