import os
import io
import datetime
import builtins
import subprocess
import logging
import pytest
import argparse
import gettext


_ORIGINAL_OPEN = builtins.open

import report.docker_run as dr

# --- Tests for _parse_args ---

def test_parse_args_defaults():
    args = dr._parse_args([])
    assert args.benchmark_set == dr.BENCHMARK_SET
    assert args.frequency_label == dr.FREQUENCY_LABEL
    assert args.run_timeout == dr.RUN_TIMEOUT
    assert args.sub_dir == dr.SUB_DIR
    assert args.model == dr.MODEL
    assert args.delay == dr.DELAY
    assert args.local_introspector is False
    assert args.num_samples == dr.NUM_SAMPLES
    assert args.llm_fix_limit == dr.LLM_FIX_LIMIT
    assert args.vary_temperature is True
    assert args.agent is False
    assert args.max_round == dr.MAX_ROUND
    assert args.redirect_outs is False

    assert args.additional_args == []


def test_parse_args_with_custom_and_additional():
    cmd = [
        '-b', 'custom_set',
        '--frequency-label', 'weekly',
        '--run-timeout', '123',
        '-sd', 'subdir',
        '-m', 'custom_model',
        '-d', '5',
        '-i', 'true',
        '-ns', '20',
        '-nf', '3',
        '-vt', 'false',
        '-ag', 'true',
        '-mr', '50',
        '-rd', 'true',
        '--', 'extra1', 'extra2'
    ]
    args = dr._parse_args(cmd)
    # Check overridden values
    assert args.benchmark_set == 'custom_set'
    assert args.frequency_label == 'weekly'
    assert args.run_timeout == 123
    assert args.sub_dir == 'subdir'
    assert args.model == 'custom_model'
    assert args.delay == 5
    assert args.local_introspector is True
    assert args.num_samples == 20
    assert args.llm_fix_limit == 3
    assert args.vary_temperature is False
    assert args.agent is True
    assert args.max_round == 50
    assert args.redirect_outs is True

    assert args.additional_args == ['extra1', 'extra2']


# --- Tests for _run_command ---

def test_run_command_returncode(monkeypatch):
    class DummyProc:
        def __init__(self):
            self.returncode = 99
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: DummyProc())
    rc = dr._run_command(['any', 'cmd'], shell=True)
    assert rc == 99


# --- Tests for _authorize_gcloud ---

def test_authorize_gcloud_no_creds(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    monkeypatch.delenv('GOOGLE_APPLICATION_CREDENTIALS', raising=False)

    monkeypatch.setattr(dr, '_run_command', lambda *args, **kwargs: (_ for _ in ()).throw(Exception("Should not be called")))

    dr._authorize_gcloud()
    # Should log that credentials not set
    assert any("GOOGLE APPLICATION CREDENTIALS is not set." in rec.message for rec in caplog.records)


def test_authorize_gcloud_with_creds(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    # Set fake credentials
    monkeypatch.setenv('GOOGLE_APPLICATION_CREDENTIALS', '/path/to/creds.json')
    commands = []
    def fake_run(cmd, shell=False):
        commands.append((cmd, shell))
        return 0
    monkeypatch.setattr(dr, '_run_command', fake_run)

    dr._authorize_gcloud()
    # Should log that credentials are set
    assert any("GOOGLE APPLICATION CREDENTIALS set" in rec.message for rec in caplog.records)
    # Check that _run_command was called with gcloud auth activate-service-account
    assert any('gcloud' in cmd and 'activate-service-account' in cmd for cmd, _ in commands)


# --- Tests for _log_common_args ---

def test_log_common_args(caplog):
    caplog.set_level(logging.INFO)
    Args = type('A', (), {})()
    args = Args
    args.benchmark_set = 'set1'
    args.frequency_label = 'label1'
    args.run_timeout = 200
    args.sub_dir = 'sub1'
    args.model = 'model1'
    args.delay = 42

    dr._log_common_args(args)
    msgs = [rec.message for rec in caplog.records]
    assert any('Benchmark set is set1.' in m for m in msgs)
    assert any('Frequency label is label1.' in m for m in msgs)
    assert any('Run timeout is 200.' in m for m in msgs)
    assert any('Sub-directory is sub1.' in m for m in msgs)
    assert any('LLM is model1.' in m for m in msgs)
    assert any('DELAY is 42.' in m for m in msgs)


def test_run_on_data_from_scratch_flow(monkeypatch, tmp_path):

    monkeypatch.setattr(os.path, 'isdir', lambda path: True)


    monkeypatch.setattr(dr, '_authorize_gcloud', lambda: None)
    monkeypatch.setattr(dr, '_log_common_args', lambda args: None)

    monkeypatch.setattr(os.path, 'exists', lambda path: False)

    # Stub subprocess.check_call for starter script
    starter_calls = []
    monkeypatch.setattr(subprocess, 'check_call', lambda cmd, shell: starter_calls.append((cmd, shell)) or 0)

    RealDateTime = datetime.datetime
    class FakeDateTime(RealDateTime):
        @classmethod
        def now(cls):
            return RealDateTime(2025, 4, 22)
    monkeypatch.setattr(dr.datetime, 'datetime', FakeDateTime)

    # Stub os.listdir for projects
    def fake_listdir(path):
        return ['proj1', 'file.txt']
    monkeypatch.setattr(os, 'listdir', fake_listdir)

    # Stub subprocess.Popen for upload_report.sh
    class FakeProc:
        def __init__(self, cmd):
            self.cmd = cmd
        def wait(self):
            self.waited = True
    p_calls = []
    monkeypatch.setattr(subprocess, 'Popen', lambda cmd: p_calls.append(cmd) or FakeProc(cmd))

    # Stub subprocess.run for run_all_experiments
    def fake_run(cmd, stdout=None, stderr=None, env=None):
        class P:
            returncode = 7
        return P()
    monkeypatch.setattr(subprocess, 'run', fake_run)

    # Stub git check_output
    monkeypatch.setattr(subprocess, 'check_output',
                        lambda cmd: b'hash' if 'rev-parse' in cmd else b'2025-04-22')

    # Capture writes to /experiment_ended
    written = {}
    def fake_open(path, mode='r', **kwargs):
        assert path == '/experiment_ended'
        written['opened'] = True
        return io.StringIO()
    monkeypatch.setattr(builtins, 'open', fake_open)

    # Execute
    ret = dr.main([])

    assert ret is None

    assert starter_calls

    assert p_calls

    assert written.get('opened', False)


def test_run_standard_flow(monkeypatch, tmp_path):

    monkeypatch.setattr(os.path, 'isdir', lambda path: False)

    # Stub authorization and logging
    monkeypatch.setattr(dr, '_authorize_gcloud', lambda: None)
    monkeypatch.setattr(dr, '_log_common_args', lambda args: None)

    # Stub python path resolution to True to test /venv/bin/python3
    monkeypatch.setattr(os.path, 'exists', lambda path: True)

    # Stub subprocess.Popen for upload_report.sh
    p_calls = []
    class FakePopen:
        def __init__(self, cmd):
            self.cmd = cmd
        def wait(self):
            self.waited = True
    monkeypatch.setattr(subprocess, 'Popen', lambda cmd: p_calls.append(cmd) or FakePopen(cmd))

    # Stub subprocess.run for experiment and trends
    run_calls = []
    def fake_run(cmd, stdout=None, stderr=None, shell=False, env=None, check=False):
        run_calls.append(cmd)
        class P:
            returncode = 3
        return P()
    monkeypatch.setattr(subprocess, 'run', fake_run)

    # Stub git check_output
    def fake_check_output(cmd):
        if 'rev-parse' in cmd:
            return b'abc123'
        if '--format=%cs' in cmd:
            return b'2025-04-22'
        if 'branch' in cmd:
            return b'main'
        return b''
    monkeypatch.setattr(subprocess, 'check_output', fake_check_output)


    written = {}
    def fake_open(path, mode='r', **kwargs):
        if path == '/experiment_ended':
            written['opened'] = True
            return io.StringIO()
        return _ORIGINAL_OPEN(path, mode, **kwargs)
    monkeypatch.setattr(builtins, 'open', fake_open)

    # Execute
    ret = dr.main([])

    assert ret is None

    assert p_calls

    assert written.get('opened', False)

    assert any('run_all_experiments.py' in arg for c in run_calls for arg in c)

    assert any('-m' in c or '--model' in c for c in run_calls)
