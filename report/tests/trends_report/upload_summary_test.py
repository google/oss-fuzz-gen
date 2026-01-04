import json
import sys
import pytest

from report.trends_report import upload_summary
from dataclasses import dataclass

# Dummy classes for testing generate_summary
@dataclass
class DummyResult:
    build_success_rate: float
    crash_rate: float
    found_bug: bool
    max_coverage: float
    max_line_coverage_diff: float

@dataclass
class DummyBenchmark:
    id: str
    project: str
    function: str
    signature: str
    result: DummyResult

@dataclass
class DummyMacroInsights:
    total_build_success_rate: float
    total_crash_rate: float

@dataclass
class DummyProjectSummary:
    project: str
    num_benchmarks: int

class DummyResultsUtil:
    def __init__(self, results_dir=None, benchmark_set=None):
        pass

    def list_benchmark_ids(self):
        return ['bm1', 'bm2']

    def get_results(self, benchmark_id):
        return {}, {}

    def match_benchmark(self, benchmark_id, results, targets):
        # produce a DummyBenchmark with different values per id
        if benchmark_id == 'bm1':
            res = DummyResult(1.0, 0.1, True, 75.5, 5.0)
            return DummyBenchmark('bm1', 'proj1', 'func1', 'sig1', res)
        else:
            res = DummyResult(0.9, 0.2, False, 80.0, 3.5)
            return DummyBenchmark('bm2', 'proj2', 'func2', 'sig2', res)

    def get_macro_insights(self, benchmarks):
        assert len(benchmarks) == 2
        # return dummy insights
        return DummyMacroInsights(total_build_success_rate=1.9, total_crash_rate=0.3)

    def get_project_summary(self, benchmarks):
        # return list of DummyProjectSummary
        return [DummyProjectSummary('proj1', 1), DummyProjectSummary('proj2', 1)]


def test_generate_summary():
    # Use the dummy results util to generate summary
    dummy_util = DummyResultsUtil()
    summary = upload_summary.generate_summary(dummy_util)

    assert isinstance(summary.benchmarks, list)
    assert len(summary.benchmarks) == 2
    assert summary.benchmarks[0] == {
        'id': 'bm1',
        'project': 'proj1',
        'function': 'func1',
        'signature': 'sig1',
        'build_success_rate': 1.0,
        'crash_rate': 0.1,
        'found_bug': True,
        'max_coverage': 75.5,
        'max_line_coverage_diff': 5.0,
    }
    assert summary.benchmarks[1]['id'] == 'bm2'

    # Verify accumulated_results
    assert summary.accumulated_results == {
        'total_build_success_rate': 1.9,
        'total_crash_rate': 0.3,
    }

    # Verify projects
    assert summary.projects == [
        {'project': 'proj1', 'num_benchmarks': 1},
        {'project': 'proj2', 'num_benchmarks': 1},
    ]


def test_main_writes_summary(tmp_path, monkeypatch):
    output_file = tmp_path / 'summary.json'

    class DummyFileSystem:
        def __init__(self, path):
            # Ensure path matches expected
            assert path == str(output_file)
            self._path = path

        def open(self, mode, encoding):
            return open(self._path, mode, encoding=encoding)

    monkeypatch.setattr(upload_summary, 'FileSystem', DummyFileSystem)

    monkeypatch.setattr(upload_summary, 'Results', DummyResultsUtil)

    args = [
        'upload_summary.py',
        '--results-dir', 'dummy_results',
        '--output-path', str(output_file),
        '--date', '2025-04-21',
        '--name', 'test_report',
        '--url', 'http://example.com',
        '--benchmark-set', 'bset',
        '--run-timeout', '10',
        '--num-samples', '5',
        '--llm-fix-limit', '2',
        '--model', 'test_model',
        '--commit-hash', 'abc123',
        '--commit-date', '2025-04-20',
        '--git-branch', 'main',
        '--tags', 'tagA', 'tagB'
    ]
    monkeypatch.setattr(sys, 'argv', args)

    upload_summary.main()

    assert output_file.exists()
    data = json.loads(output_file.read_text(encoding='utf-8'))

    expected_keys = {
        'name', 'date', 'benchmark_set', 'llm_model', 'url',
        'run_parameters', 'build_info', 'tags',
        'benchmarks', 'accumulated_results', 'projects'
    }
    assert expected_keys <= set(data.keys())

    assert data['name'] == 'test_report'
    assert data['date'] == '2025-04-21'
    assert data['llm_model'] == 'test_model'
    assert data['url'] == 'http://example.com'
    assert data['benchmark_set'] == 'bset'

    assert data['tags'] == ['test_model', 'bset', 'tagA', 'tagB']

    assert data['run_parameters'] == {'run_timeout': 10, 'num_samples': 5, 'llm_fix_limit': 2}

    assert data['build_info'] == {
        'branch': 'main',
        'commit_hash': 'abc123',
        'commit_date': '2025-04-20'
    }
