import io
import json
import sys
import pytest

import report.aggregate_coverage_diff as aggregate_coverage_diff

# --- Tests for compute_coverage_diff ---

def test_compute_coverage_diff_basic(monkeypatch):
    # Simulate existing coverage and summary
    class ExistingTextcov:
        def __init__(self):
            self.covered_lines = 2
    monkeypatch.setattr(
        aggregate_coverage_diff.evaluator,
        'load_existing_textcov',
        lambda project: ExistingTextcov()
    )
    monkeypatch.setattr(
        aggregate_coverage_diff.evaluator,
        'load_existing_coverage_summary',
        lambda project: {'data': [{'totals': {'lines': {'count': 4}}}]}
    )

    # Dummy Textcov class to track merges
    class DummyTextcov:
        def __init__(self):
            self.covered_lines = 0
        def merge(self, other):
            self.covered_lines += other.covered_lines
        def subtract_covered_lines(self, existing):
            self.covered_lines -= existing.covered_lines
        @classmethod
        def from_file(cls, f):
            # File content is a simple integer string
            inst = cls()
            inst.covered_lines = int(f.read())
            return inst
    monkeypatch.setattr(
        aggregate_coverage_diff.textcov,
        'Textcov',
        DummyTextcov
    )

    # Fake storage client with two blobs
    class FakeBlob:
        def __init__(self, name, content):
            self.name = name
            self._content = content
        def open(self):
            return io.StringIO(self._content)
    class FakeClient:
        def bucket(self, name):
            return name  # bucket identifier passed through
        def list_blobs(self, bucket, prefix, delimiter):
            # Return two blobs with covered lines 3 and 5
            return [FakeBlob('a', '3'), FakeBlob('b', '5')]
    monkeypatch.setattr(
        aggregate_coverage_diff.storage,
        'Client',
        FakeClient
    )

    # Compute diff: (3+5 - 2) / 4 = 6/4
    ratio = aggregate_coverage_diff.compute_coverage_diff('proj', ['gs://bucket/foo'])
    assert ratio == pytest.approx(6/4)


def test_compute_coverage_diff_no_totals(monkeypatch):
    # existing covered lines = 0
    class ExistingTextcov:
        def __init__(self):
            self.covered_lines = 0
    monkeypatch.setattr(
        aggregate_coverage_diff.evaluator,
        'load_existing_textcov',
        lambda project: ExistingTextcov()
    )
    # Return empty summary to trigger KeyError
    monkeypatch.setattr(
        aggregate_coverage_diff.evaluator,
        'load_existing_coverage_summary',
        lambda project: {}
    )
    # Make textcov produce no new coverage
    class DummyTextcovEmpty:
        def __init__(self):
            self.covered_lines = 0
        def merge(self, other):
            pass
        def subtract_covered_lines(self, existing):
            pass
        @classmethod
        def from_file(cls, f):
            return cls()
    monkeypatch.setattr(
        aggregate_coverage_diff.textcov,
        'Textcov',
        DummyTextcovEmpty
    )
    # Fake client returning no blobs
    class FakeClientEmpty:
        def bucket(self, name):
            return name
        def list_blobs(self, bucket, prefix, delimiter):
            return []
    monkeypatch.setattr(
        aggregate_coverage_diff.storage,
        'Client',
        FakeClientEmpty
    )
    ratio = aggregate_coverage_diff.compute_coverage_diff('proj', ['gs://bucket/foo'])
    # With total_lines defaulting to 1, ratio should be 0
    assert ratio == 0

# --- Tests for main() ---

def test_main_prints_expected(monkeypatch, capsys):
    # Monkey-patch compute_coverage_diff to return fixed value
    monkeypatch.setattr(
        aggregate_coverage_diff,
        'compute_coverage_diff',
        lambda project, links: 0.5
    )
    # Prepare input JSON with one benchmark having a report link
    input_data = {'benchmarks': [
        {'benchmark': 'x-proj', 'max_line_coverage_diff_report': 'link1'},
        {'benchmark': 'y-proj2'}
    ]}
    monkeypatch.setattr(
        sys, 'stdin',
        io.StringIO(json.dumps(input_data))
    )
    # Capture output
    aggregate_coverage_diff.main()
    out = capsys.readouterr().out.strip()
    # Should only include 'proj':0.5
    assert out == "{'proj': 0.5}"
