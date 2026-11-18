#!/usr/bin/env python3
"""Offline fixtures for native Mosey collection; never executes adb or a target."""
from contextlib import redirect_stdout
import errno
import importlib.util
import io
import json
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'validation/collect_mosey.py'
SPEC = importlib.util.spec_from_file_location('collect_mosey', SCRIPT)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def proc_stat(pid, ticks):
    # Field3 state followed by numeric fields4..21, field22 starttime.
    return f'{pid} (mosey worker ) name) S '.encode() + b' '.join([b'0'] * 18 + [str(ticks).encode()]) + b'\n'


class NativeFixture:
    def __init__(self, malformed_pids=False):
        self.calls = []
        self.stat_calls = {}
        self.malformed_pids = malformed_pids

    def __call__(self, argv, capture_output, timeout):
        self.calls.append(argv)
        command = argv[-1]
        if command.startswith('su -c '):
            tokens = shlex.split(command)
            assert tokens[:2] == ['su', '-c'] and len(tokens) == 3
            command = tokens[2]
        result = subprocess.CompletedProcess(argv, 0, b'fixture\n', b'')
        if command == 'pidof mosey_server':
            result.stdout = b'321; touch /tmp/oops\n' if self.malformed_pids else b'654 321 321\n'
        elif command.startswith('sha256sum '):
            result.stdout = b''.join(f'{"a" * 64}  {path}\n'.encode() for path in collector.ARTIFACTS[:-1])
            result.returncode = 1
            result.stderr = b'last artifact absent\n'
        elif command == collector.BASE_COMMANDS['adapter_log']:
            raise subprocess.TimeoutExpired(argv, timeout, output=b'partial log\x00\xff', stderr=b'partial error\r\n')
        elif command == 'cat /proc/modules':
            raise FileNotFoundError(errno.ENOENT, 'fixture subprocess unavailable')
        elif command.startswith('cat /proc/') and command.endswith('/stat'):
            pid = int(command.split('/')[2])
            self.stat_calls[pid] = self.stat_calls.get(pid, 0) + 1
            ticks = 100 if pid == 321 else 200 + self.stat_calls[pid]
            result.stdout = proc_stat(pid, ticks)
        elif command.startswith('readlink /proc/'):
            result.stdout = b'/system_ext/bin/mosey_server\n'
        elif command.endswith('/attr/current'):
            result.stdout = b'u:r:mosey_server:s0\x00\n'
        elif command.endswith('/status'):
            result.stdout = b'Name:\tmosey_server\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000003000\nCapAmb:\t0000000000003000\nVmRSS:\t1234 kB\n'
        elif '/environ)' in command:
            result.stdout = b'LD_PRELOAD=/system_ext/lib64/libmosey_onyx_config.so\nKONOHA_MOSEY_WONDER=1\n'
        elif command.endswith('/maps'):
            if '/654/' in command:
                result.returncode, result.stdout, result.stderr = 1, b'', b'permission denied\n'
            else:
                result.stdout = b'00000100-00000200 r-xp 0000 00:00 1 /system_ext/lib64/libmosey_onyx_config.so\n00000300-00000400 r-xp 0000 00:00 2 /system_ext/lib64/libmosey_daemon_ffi.so\n'
        elif command.endswith('/auxv'):
            result.stdout = struct.pack('<QQQQQQ', 6, 4096, 23, 0, 0, 0)
        return result


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mosey-collector-')
        self.directory = Path(self.temporary.name)
        self.adb = self.directory / 'Windows tools' / 'adb.exe'
        self.adb.parent.mkdir()
        self.adb.write_bytes(b'MZoffline-fixture-only')

    def tearDown(self):
        self.temporary.cleanup()

    def test_windows_executable_is_required(self):
        self.assertEqual(collector.windows_adb(self.adb), str(self.adb.resolve()))
        linux = self.directory / 'adb.exe'
        linux.write_bytes(b'\x7fELFfake-linux')
        with self.assertRaises(ValueError):
            collector.windows_adb(linux)
        bare = self.directory / 'adb'
        bare.write_bytes(b'MZ')
        with self.assertRaises(ValueError):
            collector.windows_adb(bare)
        with self.assertRaises(ValueError):
            collector.windows_adb(self.directory / 'missing' / 'adb.exe')

    def test_dry_run_performs_no_device_or_output_action(self):
        output = io.StringIO()
        with mock.patch.object(collector, 'windows_adb', side_effect=AssertionError('device setup forbidden')):
            with redirect_stdout(output):
                self.assertEqual(collector.main(['--dry-run']), 0)
        plan = json.loads(output.getvalue())
        self.assertIn('process_commands', plan)
        self.assertIn('Read-only', plan['scope'])

    def test_command_timeout_preserves_exact_raw_streams(self):
        directory = self.directory / 'timeout'
        directory.mkdir()
        runner = NativeFixture()
        record, stdout = collector.capture_command(directory, 'log', collector.BASE_COMMANDS['adapter_log'],
            str(self.adb), 'SERIAL WITH SPACE', timeout=2, runner=runner)
        self.assertEqual(record['outcome'], 'timeout')
        self.assertIsNone(record['returncode'])
        self.assertEqual(stdout, b'partial log\x00\xff')
        self.assertEqual((directory / record['stdout']['path']).read_bytes(), stdout)
        self.assertEqual(record['stdout']['sha256'], collector.sha256(stdout))
        self.assertEqual((directory / record['stderr']['path']).read_bytes(), b'partial error\r\n')
        self.assertEqual(runner.calls[0][1:4], ['-s', 'SERIAL WITH SPACE', 'exec-out'])

    def test_launch_failure_is_a_record(self):
        directory = self.directory / 'launch'
        directory.mkdir()
        record, stdout = collector.capture_command(directory, 'module', 'cat /proc/modules',
            str(self.adb), 'SERIAL', runner=NativeFixture())
        self.assertEqual(record['outcome'], 'launch_failed')
        self.assertEqual(record['errno'], errno.ENOENT)
        self.assertEqual(stdout, b'')
        self.assertEqual(record['stderr']['size'], 0)

    def test_interruption_journals_completed_and_current_command(self):
        output = self.directory / 'interrupted'
        calls = []
        def runner(argv, capture_output, timeout):
            calls.append(argv)
            if len(calls) == 2:
                # The active command is already journaled before subprocess entry.
                saved = json.loads((output / 'capture.json').read_text())
                active = saved['snapshots'][0]['commands']['kernel_release']
                self.assertEqual(active['outcome'], 'running')
                self.assertEqual(active['argv'], argv)
                raise KeyboardInterrupt
            return subprocess.CompletedProcess(argv, 0, b'completed command\n', b'')
        report = collector.collect(output, str(self.adb), 'SERIAL', runner=runner)
        self.assertEqual(report['outcome'], 'interrupted')
        self.assertEqual(report['snapshots'][0]['outcome'], 'interrupted')
        records = report['snapshots'][0]['commands']
        self.assertEqual(records['boot_id']['outcome'], 'ok')
        self.assertEqual(records['kernel_release']['outcome'], 'interrupted')
        self.assertFalse(records['kernel_release']['stdout']['capture_complete'])
        self.assertEqual(json.loads((output / 'capture.json').read_text()), report)
        for record in records.values():
            for stream in ('stdout', 'stderr'):
                path = output / report['snapshots'][0]['directory'] / record[stream]['path']
                self.assertEqual(collector.sha256(path.read_bytes()), record[stream]['sha256'])

    def test_interrupted_process_snapshot_remains_in_report(self):
        fixture = NativeFixture()
        def runner(argv, capture_output, timeout):
            if argv[-1] == 'cat /proc/321/status':
                raise KeyboardInterrupt
            return fixture(argv, capture_output, timeout)
        report = collector.collect(self.directory / 'interrupted-process', str(self.adb), 'SERIAL', runner=runner)
        self.assertEqual(report['outcome'], 'interrupted')
        process = report['snapshots'][0]['processes'][0]
        self.assertEqual(process['pid'], 321)
        self.assertEqual(process['commands']['exe']['outcome'], 'ok')
        self.assertEqual(process['commands']['status']['outcome'], 'interrupted')
        self.assertNotIn('observations', process)

    def test_existing_output_is_preserved_before_any_command(self):
        output = self.directory / 'prior-capture'
        output.mkdir()
        original = output / 'capture.json'
        original.write_bytes(b'prior receipt\n')
        runner = NativeFixture()
        with self.assertRaises(FileExistsError):
            collector.collect(output, str(self.adb), 'SERIAL', runner=runner)
        self.assertFalse(runner.calls)
        self.assertEqual(original.read_bytes(), b'prior receipt\n')

    def test_capture_retains_failures_and_process_identity(self):
        output = self.directory / 'complete'
        runner = NativeFixture()
        expected = {path: 'a' * 64 for path in collector.ARTIFACTS}
        report = collector.collect(output, str(self.adb), 'SERIAL', root=True, expected=expected, runner=runner)
        self.assertEqual(report['outcome'], 'complete')
        snapshot = report['snapshots'][0]
        self.assertEqual(snapshot['commands']['adapter_log']['outcome'], 'timeout')
        self.assertEqual(snapshot['commands']['loaded_modules']['outcome'], 'launch_failed')
        self.assertEqual(snapshot['commands']['native_artifact_hashes']['outcome'], 'command_failed')
        self.assertIsNone(snapshot['artifact_identity'][collector.ARTIFACTS[-1]]['match'])
        self.assertTrue(snapshot['artifact_identity'][collector.ARTIFACTS[0]]['match'])
        self.assertEqual([p['pid'] for p in snapshot['processes']], [321, 654])
        stable = snapshot['processes'][0]['observations']
        self.assertTrue(stable['same_process_during_capture'])
        self.assertEqual(stable['selinux_domain'], 'u:r:mosey_server:s0')
        self.assertEqual(stable['auxiliary_vector']['at_secure'], 0)
        self.assertTrue(stable['observed_config_library_mapping'])
        self.assertTrue(stable['observed_ffi_library_mapping'])
        self.assertEqual(stable['config_environment']['KONOHA_MOSEY_WONDER'], '1')
        self.assertEqual(stable['process_status']['CapAmb'], '0000000000003000')
        self.assertNotIn('VmRSS', stable['process_status'])
        unstable = snapshot['processes'][1]['observations']
        self.assertFalse(unstable['same_process_during_capture'])
        self.assertIsNone(unstable['observed_config_library_mapping'])
        self.assertEqual(unstable['command_outcomes']['maps'], 'command_failed')
        self.assertEqual(len(runner.calls), len(collector.BASE_COMMANDS) + 2 + 16)
        self.assertTrue(all(Path(call[0]).name == 'adb.exe' and call[1:4] == ['-s', 'SERIAL', 'exec-out'] for call in runner.calls))
        self.assertTrue(all(call[-1].startswith('su -c ') for call in runner.calls))
        saved = json.loads((output / 'capture.json').read_text())
        self.assertEqual(saved, report)
        for record in list(snapshot['commands'].values()) + [r for p in snapshot['processes'] for r in p['commands'].values()]:
            for stream in ('stdout', 'stderr'):
                data = (output / snapshot['directory'] / record[stream]['path']).read_bytes()
                self.assertEqual(len(data), record[stream]['size'])
                self.assertEqual(collector.sha256(data), record[stream]['sha256'])

    def test_malformed_pid_text_cannot_become_a_shell_command(self):
        runner = NativeFixture(malformed_pids=True)
        report = collector.collect(self.directory / 'bad-pids', str(self.adb), 'SERIAL', runner=runner)
        snapshot = report['snapshots'][0]
        self.assertIn('pid_parse_error', snapshot)
        self.assertFalse(snapshot['processes'])
        self.assertFalse(any('touch' in call[-1] for call in runner.calls))

    def test_process_id_parser_rejects_zero_range_and_non_ascii(self):
        self.assertEqual(collector.parse_pids(b'321 321 654\n'), [321, 654])
        for value in (b'0', b'-1', b'2147483648', b'32;id', b'\xff'):
            with self.assertRaises((ValueError, UnicodeError)):
                collector.parse_pids(value)
        for value in (0, -1, '123', 2**31):
            with self.assertRaises(ValueError):
                collector.process_commands(value)

    def test_auxv_parser_is_binary_and_bounded(self):
        valid = struct.pack('<QQQQQQ', 6, 4096, 23, 1, 0, 0)
        self.assertEqual(collector.parse_auxv(valid)['at_secure'], 1)
        for invalid in (valid[:-1], b'', struct.pack('<QQ', 23, 0)):
            with self.assertRaises(ValueError):
                collector.parse_auxv(invalid)
        self.assertIsNone(collector.parse_auxv(struct.pack('<QQ', 0, 0))['at_secure'])

    def test_stat_handles_spaces_and_parentheses_in_comm(self):
        self.assertEqual(collector.parse_start_ticks(proc_stat(321, 912345)), 912345)
        with self.assertRaises(ValueError):
            collector.parse_start_ticks(b'321 (mosey) S 1 2\n')

    def test_environment_filter_excludes_other_values_before_capture(self):
        fixture = self.directory / 'environment'
        fixture.write_bytes(b'OTHER_PRIVATE_VALUE=not-captured\x00LD_PRELOAD=/chosen/config.so\x00KONOHA_MOSEY_WONDER=1\x00PATH=/system/bin\x00')
        command = collector.process_commands(321)['config_env'].replace('/proc/321/environ', shlex.quote(str(fixture)))
        # Execute only the filter against a local fixture, never a device tool.
        result = subprocess.run(['sh', '-c', command], capture_output=True, check=True)
        self.assertEqual(result.stdout, b'LD_PRELOAD=/chosen/config.so\nKONOHA_MOSEY_WONDER=1\n')

    def test_environment_read_failure_is_not_hidden_by_filter_pipeline(self):
        missing = self.directory / 'missing-environment'
        command = collector.process_commands(321)['config_env'].replace('/proc/321/environ', shlex.quote(str(missing)))
        result = subprocess.run(['sh', '-c', command], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_expected_identity_requires_known_paths_and_digests(self):
        path = self.directory / 'expected.json'
        path.write_text(json.dumps({collector.ARTIFACTS[0]: 'A' * 64}))
        self.assertEqual(collector.expected_artifacts(path), {collector.ARTIFACTS[0]: 'a' * 64})
        for invalid in ([], {'/proc/1/environ': 'a' * 64}, {collector.ARTIFACTS[0]: 'bad'}):
            path.write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):
                collector.expected_artifacts(path)

    def test_record_names_cannot_escape_capture_directory(self):
        runner = NativeFixture()
        with self.assertRaises(ValueError):
            collector.capture_command(self.directory, '../escape', 'id', str(self.adb), 'SERIAL', runner=runner)
        self.assertFalse(runner.calls)


if __name__ == '__main__':
    unittest.main(verbosity=2)
