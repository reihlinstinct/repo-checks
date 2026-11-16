"""Execute the composite install shell with offline command recorders."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def install_shell():
    action = (ROOT / 'actions/a11y/action.yml').read_text()
    start = action.index('      run: |\n') + len('      run: |\n')
    end = action.index('\n    - name: Check local preview', start)
    return '\n'.join(line[8:] for line in action[start:end].splitlines())


class BrowserInstallContract(unittest.TestCase):
    def run_install(self, mode):
        with tempfile.TemporaryDirectory(prefix='browser-contract-') as folder:
            path = Path(folder)
            log = path / 'commands'
            for tool in ['npm', 'npx', 'node']:
                command = path / tool
                command.write_text('#!/bin/sh\nprintf "%s\\n" "' + tool +
                                   ' $*" >> "$COMMAND_LOG"\n')
                command.chmod(0o700)
            result = subprocess.run(
                ['/bin/bash', '-e', '-c', install_shell()], capture_output=True,
                text=True, env={'PATH': folder + ':/usr/bin:/bin',
                                'COMMAND_LOG': str(log), 'TRUSTED_ACTION': folder,
                                'BROWSER_RUNTIME': mode}, check=False)
            return result, log.read_text() if log.exists() else ''

    def test_invalid_runtime_fails_before_any_install_or_node_execution(self):
        for mode in ['', 'unknown', 'INSTALL', 'install; echo synthetic']:
            with self.subTest(mode=mode):
                result, commands = self.run_install(mode)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout.strip(), 'Invalid browser runtime')
                self.assertEqual(commands, '')

    def test_install_runs_locked_dependencies_browsers_then_preflight(self):
        result, commands = self.run_install('install')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(commands.splitlines(), [
            'npm ci --ignore-scripts --no-audit --no-fund',
            'npx --no-install playwright install --with-deps chromium webkit',
            'node runtime.mjs'])

    def test_preinstalled_never_downloads_browsers_but_still_preflights(self):
        result, commands = self.run_install('preinstalled')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(commands.splitlines(), [
            'npm ci --ignore-scripts --no-audit --no-fund', 'node runtime.mjs'])
