import os
import sys
import json
import shutil
import pytest
import jinja2

from report.web import (
    JinjaEnv,
    GenerateReport,
    generate_report,
    launch_webserver,
    _parse_arguments,
    LOCAL_HOST,
)

# -- JinjaEnv filter tests --

def test_urlencode_filter():
    je = JinjaEnv()
    assert je._urlencode_filter("hello world!") == "hello%20world%21"


def test_percent():
    je = JinjaEnv()
    assert je._percent(0.123456) == "12.35"  # rounded two decimals


def test_cov_report_link_empty():
    je = JinjaEnv()
    assert je._cov_report_link("") == "#"


def test_cov_report_link_local_without_gcb():
    je = JinjaEnv()
    link = "/some/local/path"
    res = je._cov_report_link(link)
    assert res == "/some/local/pathreport.html"


def test_cov_report_link_cloud_paths():
    je = JinjaEnv()
    cloud_link = "gs://oss-fuzz-gcb-experiment-run-logs/foo/bar"
    expected = "https://llm-exp.oss-fuzz.com/foo/bar/report/linux/index.html"
    assert je._cov_report_link(cloud_link) == expected

    cloud_link2 = "gs://oss-fuzz-gcb-experiment-run-logs/foo/bar.txt"
    expected2 = "https://llm-exp.oss-fuzz.com/foo/bar.txt/report/linux/index.html"
    assert je._cov_report_link(cloud_link2) == expected2


def test_remove_trailing_empty_lines():
    je = JinjaEnv()
    code = "line1\nline2\n    \n  \n"
    assert je._remove_trailing_empty_lines(code) == "line1\nline2"
    assert je._remove_trailing_empty_lines("") == ""


def test_splitlines():
    je = JinjaEnv()
    text = "a\nb\r\nc"
    assert je._splitlines(text) == ["a", "b", "c"]
    assert je._splitlines("") == []

# -- GenerateReport.read_timings test --

def test_read_timings(tmp_path):
    data = {'a': 1, 'b': 2}
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    with open(results_dir / 'report.json', 'w') as f:
        json.dump(data, f)

    fake_jinja = JinjaEnv()
    gr = GenerateReport(results=None,
                        jinja_env=fake_jinja,
                        results_dir=str(results_dir),
                        output_dir=str(tmp_path / 'out'))
    timings = gr.read_timings()
    assert timings == data

# -- Argument parsing tests --

def test_parse_arguments_structure(monkeypatch):
    import sys
    monkeypatch.setattr(sys, 'argv', ['__main__.py', '-r', 'resdir'])
    ns = _parse_arguments()
    for attr in ['results_dir', 'output_dir', 'benchmark_set', 'model', 'serve', 'port']:
        assert hasattr(ns, attr)

# -- I/O-heavy methods tests --

def test_copy_and_set_coverage_report(tmp_path):

    class DummyResult:
        def __init__(self):
            self.coverage_report_path = ''
    class DummyBenchmark:
        def __init__(self, id):
            self.id = id
    class DummySample:
        def __init__(self, id):
            self.id = id
            self.result = DummyResult()

    # Create directories: results/benchmark1/code-coverage-reports/sample1/{linux, extra, style.css}
    results_dir = tmp_path / 'results'
    coverage_root = results_dir / 'benchmark1' / 'code-coverage-reports'
    sample_dir = coverage_root / 'sample1'
    (sample_dir / 'linux').mkdir(parents=True)
    (sample_dir / 'extra').mkdir()

    (sample_dir / 'style.css').write_text('')

    out_dir = tmp_path / 'out'
    gr = GenerateReport(results=None,
                        jinja_env=None,
                        results_dir=str(results_dir),
                        output_dir=str(out_dir))
    benchmark = DummyBenchmark('benchmark1')
    sample = DummySample('sample1')
    gr._copy_and_set_coverage_report(benchmark, sample)


    dest = out_dir / 'sample' / 'benchmark1' / 'coverage' / 'sample1' / 'linux'
    assert dest.exists()

    assert sample.result.coverage_report_path == '/sample/benchmark1/coverage/sample1/linux/'


def test_generate_report_invokes_generate(monkeypatch):
    from report.web import generate_report, GenerateReport, Results
    calls = {}

    monkeypatch.setattr('report.web.Results', lambda results_dir, benchmark_set: None)

    original_init = GenerateReport.__init__
    def fake_init(self, results, jinja_env, results_dir, output_dir):
        original_init(self, results=None, jinja_env=jinja_env, results_dir=results_dir, output_dir=output_dir)
    monkeypatch.setattr(GenerateReport, '__init__', fake_init)

    def fake_generate(self):
        calls['generated'] = True
    monkeypatch.setattr(GenerateReport, 'generate', fake_generate)

    from argparse import Namespace
    args = Namespace(results_dir='rdir', output_dir='odir', benchmark_set='', model='', serve=False, port=0)
    generate_report(args)
    assert calls.get('generated', False)


def test_launch_webserver(monkeypatch):
    from report.web import launch_webserver, LOCAL_HOST, ThreadingHTTPServer

    instances = []
    port = 12345

    class DummyServer:
        def __init__(self, addr, handler):
            # Assert that correct host and port are used
            assert addr[0] == LOCAL_HOST
            assert addr[1] == port
            instances.append(self)
        def serve_forever(self):
            self.serve_called = True
            raise SystemExit

    monkeypatch.setattr('report.web.ThreadingHTTPServer', DummyServer)
    from argparse import Namespace
    args = Namespace(port=port, output_dir='unused')
    with pytest.raises(SystemExit):
        launch_webserver(args)

    assert instances and getattr(instances[0], 'serve_called', False)

