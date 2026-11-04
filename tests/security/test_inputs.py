import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[2] / 'src/repo_checks/inputs.py'
spec = importlib.util.spec_from_file_location('shared_inputs', P)
g = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = g
spec.loader.exec_module(g)

class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
    def tearDown(self): self.temp.cleanup()
    def tracked(self, path, data=b'fixed'):
        p = self.root / path; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        subprocess.run(['git', '-C', str(self.root), 'add', '--', path], check=True)
        return p
    def test_regular_unicode_and_newline_names(self):
        for name in ['docs/plain.md', 'docs/זז.md', 'docs/new\nline.md']: self.tracked(name)
        with g.Inputs(self.root) as inputs:
            for name in inputs.paths: self.assertEqual(inputs.read(name), 'fixed')
    def test_root_subdirectory_refused(self):
        (self.root/'sub').mkdir()
        with self.assertRaises(g.InputError):
            with g.Inputs(self.root/'sub'): pass
    def test_untracked_traversal_and_closed_refused(self):
        self.tracked('ok.md'); (self.root/'other.md').write_text('private')
        with g.Inputs(self.root) as inputs:
            for name in ['other.md', '../outside', '/absolute', 'x//y', 'x/./y', 'x\\y']:
                with self.assertRaises(g.InputError): inputs.read(name)
        with self.assertRaises(g.InputError): inputs.read('ok.md')
    def test_file_and_ancestor_symlinks_refused(self):
        p = self.tracked('docs/ok.md')
        outside = self.root/'outside'; outside.mkdir(); (outside/'ok.md').write_text('private')
        p.unlink(); p.symlink_to(outside/'ok.md')
        with g.Inputs(self.root) as inputs:
            with self.assertRaises(g.InputError): inputs.read('docs/ok.md')
        p.unlink(); p.parent.rmdir(); p.parent.symlink_to(outside, target_is_directory=True)
        with g.Inputs(self.root) as inputs:
            with self.assertRaises(g.InputError): inputs.read('docs/ok.md')
    def test_size_total_and_utf8_refusals(self):
        self.tracked('a.md', b'abcdef'); self.tracked('bad.md', b'\xff')
        with g.Inputs(self.root) as inputs:
            with self.assertRaises(g.InputError): inputs.read('a.md', cap=5)
            with patch.object(g, 'MAX_TOTAL', 5):
                with self.assertRaises(g.InputError): inputs.read('a.md')
            with self.assertRaises(g.InputError): inputs.read('bad.md')
    def test_git_output_cap_before_unbounded_allocation(self):
        self.tracked('a' * 40)
        with self.assertRaisesRegex(g.InputError, '^inventory_limit$'):
            g.git_output(self.root, ['ls-files', '-z'], cap=3)
    def test_path_count_cap(self):
        self.tracked('a'); self.tracked('b')
        with patch.object(g, 'MAX_PATHS', 1), self.assertRaises(g.InputError):
            with g.Inputs(self.root): pass
    def test_fsmonitor_candidate_helper_never_runs(self):
        marker = self.root/'executed'
        helper = self.root/'helper.sh'; helper.write_text('#!/bin/sh\ntouch '+str(marker)+'\n'); helper.chmod(0o700)
        subprocess.run(['git','-C',str(self.root),'config','core.fsmonitor',str(helper)], check=True)
        with g.Inputs(self.root): pass
        self.assertFalse(marker.exists())
    def test_fifo_refused_without_blocking(self):
        p = self.tracked('a'); p.unlink(); os.mkfifo(p)
        with g.Inputs(self.root) as inputs:
            with self.assertRaises(g.InputError): inputs.read('a')
    def test_invalid_git_and_failed_inventory_fixed_error(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(g.InputError):
            with g.Inputs(Path(d)): pass
    def test_file_replaced_during_read_fails(self):
        p = self.tracked('a', b'fixed'); real = os.read; fired = False
        def changing(fd, count):
            nonlocal fired
            value = real(fd, count)
            if value and not fired:
                fired = True; other = self.root/'new'; other.write_bytes(b'private'); other.replace(p)
            return value
        with g.Inputs(self.root) as inputs, patch.object(g.os, 'read', side_effect=changing):
            with self.assertRaisesRegex(g.InputError, '^file_changed$'): inputs.read('a')
    def test_ancestor_swap_never_follows_new_symlink(self):
        self.tracked('docs/a', b'fixed')
        outside = self.root/'outside'; outside.mkdir(); (outside/'a').write_text('private')
        real_open = os.open; switched = False
        def swap(path, flags, *args, **kwargs):
            nonlocal switched
            fd = real_open(path, flags, *args, **kwargs)
            if path == 'docs' and kwargs.get('dir_fd') is not None and not switched:
                switched = True
                (self.root/'docs').rename(self.root/'old-docs')
                (self.root/'docs').symlink_to(outside, target_is_directory=True)
            return fd
        with g.Inputs(self.root) as inputs, patch.object(g.os, 'open', side_effect=swap):
            self.assertEqual(inputs.read('docs/a'), 'fixed')
    def test_oversized_file_refused_before_read_allocation(self):
        self.tracked('a', b'abcdef')
        with g.Inputs(self.root) as inputs, patch.object(g.os, 'read', side_effect=AssertionError('must not read')):
            with self.assertRaisesRegex(g.InputError, '^file_limit$'): inputs.read('a', cap=5)
    def test_git_command_disables_candidate_helpers(self):
        real = subprocess.Popen; commands = []
        def capture(command, **kwargs):
            commands.append(command)
            return real(command, **kwargs)
        with patch.object(g.subprocess, 'Popen', side_effect=capture):
            g.git_output(self.root, ['ls-files', '-z'])
        self.assertIn('core.fsmonitor=false', commands[0])
        self.assertIn('core.hooksPath=' + os.devnull, commands[0])
    def test_final_symlink_swap_never_opens_or_reads_target(self):
        p = self.tracked('docs/a', b'fixed')
        outside = self.root/'secret'; outside.write_bytes(b'private-target')
        real_open = os.open; real_read = os.read; target_opens = []; target_reads = []
        def swap(path, flags, *args, **kwargs):
            if path == 'a' and kwargs.get('dir_fd') is not None:
                p.unlink(); p.symlink_to(outside)
            fd = real_open(path, flags, *args, **kwargs)
            if os.fstat(fd).st_ino == outside.stat().st_ino: target_opens.append(fd)
            return fd
        def observing(fd, size):
            if os.fstat(fd).st_ino == outside.stat().st_ino: target_reads.append(fd)
            return real_read(fd, size)
        with g.Inputs(self.root) as inputs, patch.object(g.os, 'open', side_effect=swap), patch.object(g.os, 'read', side_effect=observing):
            with self.assertRaises(g.InputError): inputs.read('docs/a')
        self.assertEqual(target_opens, [])
        self.assertEqual(target_reads, [])
    def test_ancestor_symlink_swap_never_traverses_target(self):
        self.tracked('docs/a', b'fixed')
        outside = self.root/'secret-dir'; outside.mkdir(); (outside/'a').write_bytes(b'private-target')
        real_open = os.open; traversed = []
        def swap(path, flags, *args, **kwargs):
            if path == 'docs' and kwargs.get('dir_fd') is not None:
                (self.root/'docs').rename(self.root/'old-docs')
                (self.root/'docs').symlink_to(outside, target_is_directory=True)
            fd = real_open(path, flags, *args, **kwargs)
            if os.fstat(fd).st_ino in [outside.stat().st_ino, (outside/'a').stat().st_ino]: traversed.append(fd)
            return fd
        with g.Inputs(self.root) as inputs, patch.object(g.os, 'open', side_effect=swap):
            with self.assertRaises(g.InputError): inputs.read('docs/a')
        self.assertEqual(traversed, [])
