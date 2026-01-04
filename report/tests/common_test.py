import os
import io
import json
import pytest
import tempfile
import run_one_experiment
from report.common import (
    AccumulatedResult,
    Sample,
    LogPart,
    _parse_log_parts,
    FileSystem,
    Target,
    Triage,
    Benchmark,
    Results,
    MAX_RUN_LOGS_LEN,
    
)

class DummyResult:
    def __init__(self, reproducer_path=None):
        self.reproducer_path = reproducer_path


def test_accumulated_result_properties():
    ar = AccumulatedResult(
        compiles=2,
        crashes=1,
        crash_cases=3,
        total_runs=2,
        total_coverage=50.0,
        total_line_coverage_diff=10.0,
    )
    # average_coverage = total_coverage / total_runs = 25.0
    assert ar.average_coverage == 25.0
    # average_line_coverage_diff = total_line_coverage_diff / total_runs = 5.0
    assert ar.average_line_coverage_diff == 5.0
    # build_rate = compiles / total_runs = 1.0
    assert ar.build_rate == 1.0


def test_parse_log_parts_no_markers():
    log = "plain log without markers"
    parts = _parse_log_parts(log)
    assert len(parts) == 1
    assert parts[0].content == log
    assert not parts[0].chat_prompt
    assert not parts[0].chat_response


def test_parse_log_parts_with_markers():
    log = (
        "start"
        "<CHAT PROMPT:ROUND 1>prompt1</CHAT PROMPT:ROUND 1>"
        "middle"
        "<CHAT RESPONSE:ROUND 1>response1</CHAT RESPONSE:ROUND 1>"
        "end"
    )
    parts = _parse_log_parts(log)
    # Should produce 5 parts: 'start', prompt, 'middle', response, 'end'
    assert len(parts) == 5
    assert parts[0].content == "start"
    assert parts[0].chat_prompt is False and parts[0].chat_response is False

    prompt_part = parts[1]
    assert prompt_part.chat_prompt
    assert not prompt_part.chat_response
    assert prompt_part.content == "prompt1"

    assert parts[2].content == "middle"

    response_part = parts[3]
    assert not response_part.chat_prompt
    assert response_part.chat_response
    assert response_part.content == "response1"

    assert parts[4].content == "end"


def test_sample_properties_with_result():
    # Create dummy result with reproducer_path
    path = "/tmp/reproducer"
    dummy = DummyResult(reproducer_path=path)
    sample = Sample(id="01", status="Done", result=dummy)

    assert sample.stacktrace == f"{path}/stacktrace"
    assert sample.target_binary == f"{path}/target_binary"
    assert sample.reproducer == f"{path}/artifacts"
    # run_log uses removesuffix logic: replaces 'reproducer' with '' and adds 'run.log'
    assert sample.run_log == f"/tmp/run.log"


def test_sample_properties_without_result():
    sample = Sample(id="02", status="Running", result=None)
    assert sample.stacktrace == ""
    assert sample.target_binary == ""
    assert sample.reproducer == ""
    assert sample.run_log == ""


def test_target_and_triage_dataclasses():
    target = Target(code="code snippet", fixer_prompt="fixer", build_script_code="script")
    assert target.code == "code snippet"
    assert target.fixer_prompt == "fixer"
    assert target.build_script_code == "script"

    triage = Triage(result="result text", triager_prompt="prompt text")
    assert triage.result == "result text"
    assert triage.triager_prompt == "prompt text"


def test_filesystem_local_operations(tmp_path):
    dir_path = tmp_path / "subdir"
    dir_path.mkdir()
    file_path = dir_path / "test.txt"
    content = "hello world"
    file_path.write_text(content)

    # Test FileSystem on file
    fs_file = FileSystem(str(file_path))
    assert fs_file.exists()
    assert fs_file.isfile()
    assert not fs_file.isdir()
    assert fs_file.getsize() == len(content)
    with fs_file.open() as f:
        assert f.read() == content

    # Test FileSystem on directory
    fs_dir = FileSystem(str(dir_path))
    assert fs_dir.exists()
    assert fs_dir.isdir()
    assert not fs_dir.isfile()
    listing = fs_dir.listdir()
    assert "test.txt" in listing

    # Test makedirs: create new nested dir
    new_dir = tmp_path / "a" / "b" / "c"
    fs_new = FileSystem(str(new_dir))
    fs_new.makedirs()
    assert new_dir.exists()

    # Test opening with write mode
    new_file = new_dir / "new.txt"
    fs_new_file = FileSystem(str(new_file))
    with fs_new_file.open("w") as f:
        f.write("data")
    assert fs_new_file.getsize() == 4

# Tests for Results class methods
def test_results_list_benchmark_ids(tmp_path):
    base = tmp_path / "results"
    base.mkdir()
    valid = base / "output-proj1-func1"
    valid.mkdir()
    (valid / "status").mkdir()
    invalid = base / "lost+found"
    invalid.mkdir()

    res = Results(results_dir=str(base), benchmark_set='all')
    ids = res.list_benchmark_ids()
    assert ids == ["output-proj1-func1"]


def test_results_match_benchmark(monkeypatch):
    # Dummy aggregated result
    dummy_aggr = run_one_experiment.AggregatedResult()
    monkeypatch.setattr(run_one_experiment, 'aggregate_results', lambda filtered, t: dummy_aggr)

    class DummyE:
        def __init__(self, finished): self.finished = finished
    results = [DummyE(True), DummyE(False), DummyE(True)]
    targets = ["t1", "t2", "t3"]
    r = Results()
    bm = r.match_benchmark("output-proj-f-func", results, targets)
    assert isinstance(bm, Benchmark)
    assert bm.id == "output-proj-f-func"
    assert bm.status.startswith("Running") or bm.status == "Done"
    assert bm.result is dummy_aggr


def test_get_final_target_code(tmp_path):
    rdir = tmp_path / "results"
    bdir = rdir / "bench1" / "fixed_targets"
    bdir.mkdir(parents=True)
    sample_file = bdir / "s1.code"
    sample_file.write_text("abc123")

    res = Results(results_dir=str(rdir))
    code = res.get_final_target_code("bench1", "s1")
    assert json.loads(code) == "abc123"


def test_get_logs_and_parse(tmp_path):
    rdir = tmp_path / "results"
    logdir = rdir / "bench" / "status" / "s" 
    logdir.mkdir(parents=True)
    txt = logdir / "log.txt"
    content = "<CHAT PROMPT:ROUND 1>p</CHAT PROMPT:ROUND 1>"
    txt.write_text(content)

    res = Results(results_dir=str(rdir))
    parts = res.get_logs("bench", "s")
    assert all(isinstance(p, LogPart) for p in parts)
    assert parts[0].content == 'p'


def test_get_run_logs_simple(tmp_path):
    # Create run logs
    rdir = tmp_path / "results"
    rundir = rdir / "bench" / "logs" / "run"
    rundir.mkdir(parents=True)
    f = rundir / "01.log"
    text = "short log"
    f.write_text(text)

    res = Results(results_dir=str(rdir))
    log = res.get_run_logs("bench", "01")
    assert log == text


def test_get_run_logs_truncated(tmp_path, monkeypatch):
    rdir = tmp_path / "results"
    rundir = rdir / "bench" / "logs" / "run"
    rundir.mkdir(parents=True)
    fname = "01.log"
    fpath = rundir / fname
    big = 'A' * (MAX_RUN_LOGS_LEN + 10)
    fpath.write_text(big)

    res = Results(results_dir=str(rdir))
    log = res.get_run_logs("bench", "01")
    assert '...truncated...' in log
    half = MAX_RUN_LOGS_LEN // 2
    assert log.startswith('A' * half)
    assert log.endswith('A' * half)


def test_get_triage_empty_and_with_data(tmp_path):
    rdir = tmp_path / "results"
    # empty
    res = __import__('report.common', fromlist=['Results']).Results(results_dir=str(rdir))
    tri = res.get_triage("b", "s")
    assert tri.result == '' and tri.triager_prompt == ''

    # with data
    tri_dir = rdir / "b" / "fixed_targets" / "s-triage"
    tri_dir.mkdir(parents=True)
    pfile = tri_dir / "prompt.txt"
    pfile.write_text(json.dumps([{"content": "hello"}]))
    rfile = tri_dir / "out.txt"
    rfile.write_text("res")
    tri2 = res.get_triage("b", "s")
    assert "hello" in tri2.triager_prompt
    assert tri2.result == "res"

def test_get_targets_fixed_and_agent(tmp_path):
    # Setup fixed_targets
    rdir = tmp_path / "results"
    bench = rdir / "bench"
    fixed = bench / "fixed_targets"
    fixed.mkdir(parents=True)
    # sample file
    sample_file = fixed / "01.txt"
    sample_file.write_text("code1")
    dir_f = fixed / "01-F00"
    dir_f.mkdir()
    p = dir_f / "prompt.txt"
    p.write_text(json.dumps([{"content":"fix prompt"}]))
    r = dir_f / "fix.rawoutput"
    r.write_text("fixed code")
    res = Results(results_dir=str(rdir))
    targets = res.get_targets("bench", "01")
    assert len(targets) == 2
    # First: code from sample_file
    assert targets[0].code == "code1"
    # Second: Target from fixed dir
    assert targets[1].code == "fixed code"
    assert "fix prompt" in targets[1].fixer_prompt

# Tests for get_samples

def test_get_samples_mapping():
    all_targets = ["t1", "t2", "t3"]
    results_list = [object(), None, object()]
    res = Results()
    samples = res.get_samples(results_list, all_targets)
    assert len(samples) == 3
    assert samples[0].status == "Done"
    assert samples[1].status == "Running"
    assert samples[2].status == "Done"
    assert isinstance(samples[0], Sample)

# Tests for get_prompt

def test_get_prompt_raw_and_structured(tmp_path):
    rdir = tmp_path / "results"
    bench = rdir / "bench"
    bench.mkdir(parents=True)
    # raw text prompt
    pt = bench / "prompt1.txt"
    pt.write_text("hello raw")
    res = Results(results_dir=str(rdir))
    assert "hello raw" in res.get_prompt("bench")
    # structured prompt
    pt.write_text(json.dumps([{"content":"line1"},{"content":"line2"}]))
    assert "line1" in res.get_prompt("bench")
    assert "line2" in res.get_prompt("bench")

# Tests for get_results

def test_get_results_and_targets(tmp_path, monkeypatch):
    # Prepare raw_targets and result.json
    rdir = tmp_path / "results"
    bench = rdir / "bench"
    raw = bench / "raw_targets"
    raw.mkdir(parents=True)
    f1 = raw / "00.py"
    f1.write_text("dummy")
    status = bench / "status"
    s0 = status / "00"
    s0.mkdir(parents=True)
    res_file = s0 / "result.json"
    res_file.write_text("{}")
    # Monkeypatch evaluator.Result to accept no args
    class DummyE:
        def __init__(self):
            pass
    import report.common as rc
    monkeypatch.setattr(rc.evaluator, "Result", DummyE)
    results, targets = Results(results_dir=str(rdir)).get_results("bench")
    assert isinstance(results[0], DummyE)
    # The target path should match f1
    assert targets == [str(f1)]

# Tests for get_macro_insights

def test_get_macro_insights():
    # Create dummy benchmarks
    ag1 = run_one_experiment.AggregatedResult()
    ag1.build_success_rate = 1.0; ag1.found_bug=1; ag1.max_coverage=10; ag1.max_line_coverage_diff=2
    ag2 = run_one_experiment.AggregatedResult()
    ag2.build_success_rate = 0.0; ag2.found_bug=0; ag2.max_coverage=20; ag2.max_line_coverage_diff=3
    b1 = Benchmark("id1","Done",ag1)
    b2 = Benchmark("id2","Done",ag2)
    acc = Results().get_macro_insights([b1,b2])

    assert acc.compiles == 1
    assert acc.crashes == 1
    assert acc.total_runs == 2
    assert acc.average_coverage == 15
    assert acc.average_line_coverage_diff == 2.5

# Tests for get_coverage_language_gains and get_project_summary

def test_get_coverage_language_gains_and_project_summary(tmp_path):
    # Deploy report.json with project_summary
    rdir = tmp_path / "results"
    rdir.mkdir(parents=True)
    summary = {"project_summary":{
        "p1":{
            "coverage_diff":5,
            "coverage_relative_gain":0.1,
            "coverage_ofg_total_new_covered_lines":2,
            "coverage_existing_total_covered_lines":3,
            "coverage_existing_total_lines":10,
            "coverage_ofg_total_covered_lines":7
        }
    }}
    j = rdir / "report.json"
    j.write_text(json.dumps(summary))
    # Prepare benchmarks list
    class DummyAg:
        build_success_count = 1

    b = Benchmark(id="id-p1-f", status="Done", result=DummyAg(), signature="", project="p1", function="", language="")

    gains = Results(results_dir=str(rdir)).get_coverage_language_gains()
    assert "project_summary" in gains
    assert "p1" in gains["project_summary"]
    assert gains["project_summary"]["p1"]["coverage_diff"] == 5
    # get_project_summary maps summary into Project objects
    ps = Results(results_dir=str(rdir)).get_project_summary([b])
    assert len(ps) == 1
    proj = ps[0]
    assert proj.name == "p1"
    assert proj.coverage_gain == 5
    assert proj.coverage_relative_gain == 0.1
    assert proj.coverage_ofg_total_new_covered_lines == 2
    assert proj.coverage_existing_total_covered_lines == 3
    assert proj.coverage_existing_total_lines == 10
    assert proj.coverage_ofg_total_covered_lines == 7
