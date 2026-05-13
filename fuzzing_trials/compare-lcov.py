#!/usr/bin/env python3
"""
cov_report_compare.py

Refactored coverage post-processing and comparison tool.

Usage:
    python cov_report_compare.py -p <project> -r <results_dir>
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

BENCHMARK_NAME = ""

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process and compare LCOV branch coverage (.lcov_total) reports.")
    parser.add_argument("-r", "--results-dir", type=Path, required=True)
    return parser.parse_args()

# --- LCOV parsing -----------------------------------------------------------

def parse_branch_cov_output(lcov_path: Path) -> Set[str]:
    """
    Parse an lcov-style .lcov_total file and return a set of branch identifiers
    in the form: "{source_path}:{line}:{block}:{branch}" for branches that have hits > 0.

    Skips files under src/synthesized_driver/.
    """
    hits = set()
    if not lcov_path.exists():
        return hits

    current_file = None
    with lcov_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("SF:"):
                current_file = line[3:].strip()
                continue

            # Guard: don't try to inspect current_file if not yet set
            if current_file and "src/synthesized_driver/" in current_file:
                continue

            if current_file and not BENCHMARK_NAME in current_file:
                continue

            if line.startswith("BRDA:"):
                # format: BRDA:<line>,<block>,<branch>,<count or - >
                payload = line[len("BRDA:"):]
                parts = payload.split(",")
                if len(parts) != 4:
                    # unexpected format; skip
                    continue
                line_number, block_num, branch_num, hit_count = parts
                try:
                    if hit_count.strip() == "-" or int(hit_count) <= 0:
                        continue
                except ValueError:
                    continue
                if current_file:
                    hits.add(f"{current_file}:{line_number}:{block_num}:{branch_num}")
            elif line.startswith("end_of_record"):
                current_file = None

    return hits

def find_cov_report_for_dir(base_dir: Path, report_subdir: str, pattern: str = "*.lcov_total") -> Optional[Path]:
    """
    Given a trial directory `base_dir`, look in base_dir / report_subdir for a single .lcov_total file.
    If not exactly one found, return None.
    """
    cov_dir = base_dir / "code-coverage-reports" / report_subdir
    if not cov_dir.exists() or not cov_dir.is_dir():
        return None
    matches = list(cov_dir.rglob(pattern))
    print(matches, report_subdir, base_dir)
    assert len(matches) == 1
    return matches[0]

def collect_cov_for_tool(appr: str, trial_dirs: Iterable[Path], baseline: bool = False) -> Dict[int, Set[str]]:
    """
    For each trial dir in trial_dirs, find the .lcov_total report (under code-coverage-reports/<appr> or <appr>_baseline)
    and parse it into a set of branch-hit strings. Returns dict: trial_num -> set(hits).
    If a dir is missing or ambiguous, that trial_num will map to an empty set and a warning is printed.
    """
    results = {}
    report_subdir = f"{appr}_baseline" if baseline else appr

    for d in trial_dirs:
        # Expect directory names with trailing "-<trialnum>"
        try:
            trial_num = int(d.name.split("-")[-1])
        except Exception:
            print(f"WARNING: cannot parse trial number from directory name '{d.name}' - skipping", file=sys.stderr)
            continue

        report_path = find_cov_report_for_dir(d, report_subdir)
        if report_path is None:
            print(f"WARNING: missing report for trial {trial_num} in {d} (looking in {report_subdir})", file=sys.stderr)
            results[trial_num] = set()
            continue

        hits = parse_branch_cov_output(report_path)
        results[trial_num] = hits

    return results

def union_all(trial_map: Dict[int, Set[str]]) -> Set[str]:
    """Union of all sets across trials."""
    union_set: Set[str] = set()
    for s in trial_map.values():
        union_set |= s
    return union_set

def compare_pre_post(pre: Dict[int, Set[str]], post: Dict[int, Set[str]]) -> Tuple[Dict[int, Dict[str, int]], Dict[str, int]]:
    """
    Compare pre- and post- coverage per trial and aggregate.

    Returns:
      per_trial_stats: { trial_num: {"pre_total":int,"post_total":int,"newly_covered":int} }
      aggregate_stats: {"pre_total":int,"post_total":int,"newly_covered":int}
    """
    per_trial: Dict[int, Dict[str,int]] = {}
    all_pre_union = union_all(pre)
    all_post_union = union_all(post)

    # compute per trial
    trial_keys = sorted(set(pre.keys()) | set(post.keys()))
    for t in trial_keys:
        pre_set = pre.get(t, set())
        post_set = post.get(t, set())
        newly = post_set - pre_set
        per_trial[t] = {
            "pre_total": len(pre_set),
            "post_total": len(post_set),
            "newly_covered": len(newly),
        }

    aggregate_stats = {
        "pre_total": len(all_pre_union),
        "post_total": len(all_post_union),
        "newly_covered": len(all_post_union - all_pre_union),
    }

    return per_trial, aggregate_stats


def print_table_header(tool_names: List[str]):
    header = " ".join(f"{name:>24}" for name in tool_names)
    print(header)
    fmt = ("{0:>12} {1:>12} {2:>12} {3:>12} {4:>12} "
           "{5:>12} {6:>12} {7:>12} {8:>12} {9:>12}")
    print(fmt.format(
        "tool_total", "tool_unique",
        "ofg_total", "ofg_unique",
        "bpf_total", "bpf_unique",
        "prom_total", "prom_unique",
        "lib_total", "lib_unique",
    ))

def print_tool_summary_row(values: Tuple[int, ...]):
    fmt = ("{0:>12} {1:>12} {2:>12} {3:>12} {4:>12} "
           "{5:>12} {6:>12} {7:>12} {8:>12} {9:>12}")
    print(fmt.format(*values))

def process_and_report(tool_dirs: Dict[str, List[Path]], baseline: bool):
    """
    For each tool name -> list of directories, parse coverage.
    Returns mapping tool_name -> trial_map.
    """
    results_by_tool = {}
    for tool, dirs in tool_dirs.items():
        results_by_tool[tool] = collect_cov_for_tool(tool, dirs, baseline=baseline)
    return results_by_tool

def summarize_tools(results_by_tool: Dict[str, Dict[int, Set[str]]]):
    """
    Print a summary table similar to your original output:
    For trial numbers 0..4 prints counts: total and unique per tool.
    """
    spreadsheet_str = ""
    tools = ["bluebird_ofg", "ofg", "bluebird_promefuzz", "promefuzz", "ogharn"]
    print(f"{'bluebird_ofg':>24} {'ofg':>24} {'bluebird_promefuzz':>24} {'promefuzz':>24} {'ogharn':>24}")
    fmt = ("{0:>12} {1:>12} {2:>12} {3:>12} {4:>12} "
           "{5:>12} {6:>12} {7:>12} {8:>12} {9:>12}")

    for trial_num in range(5):
        b_ofg = results_by_tool.get("bluebird_ofg", {}).get(trial_num, set())
        b_pf  = results_by_tool.get("bluebird_promefuzz", {}).get(trial_num, set())
        ofg   = results_by_tool.get("ofg", {}).get(trial_num, set())
        lib   = results_by_tool.get("ogharn", {}).get(trial_num, set())
        pro   = results_by_tool.get("promefuzz", {}).get(trial_num, set())

        b_ofg_u = b_ofg.difference(b_pf, ofg, lib, pro)
        b_pf_u  = b_pf.difference(b_ofg, ofg, lib, pro)
        ofg_u   = ofg.difference(b_pf, b_ofg, lib, pro)
        lib_u   = lib.difference(b_pf, ofg, b_ofg, pro)
        pro_u   = pro.difference(b_pf, ofg, lib, b_ofg)

        values = (
            len(b_ofg), len(b_ofg_u),
            len(ofg),   len(ofg_u),
            len(b_pf),  len(b_pf_u),
            len(pro),   len(pro_u),
            len(lib),   len(lib_u),
        )
        print(fmt.format(*values))
        spreadsheet_str += (",".join(map(str, values))) + "\n"

    print(spreadsheet_str)

def summarize_pre_vs_post(pre_results_by_tool: Dict[str, Dict[int, Set[str]]], post_results_by_tool: Dict[str, Dict[int, Set[str]]]):
    """
    Total coverage is equal to the branches covered AFTER the initial seed inputs
    We get unique coverage by looking at approach's total unique coverage, and subtracting that which was covered by seed inputs
    """
    tools = ["bluebird_ofg", "ofg", "bluebird_promefuzz", "promefuzz", "ogharn"]
    print(f"{'bluebird_ofg':>24} {'ofg':>24} {'bluebird_promefuzz':>24} {'promefuzz':>24} {'ogharn':>24}")
    fmt = ("{0:>12} {1:>12} {2:>12} {3:>12} {4:>12} "
           "{5:>12} {6:>12} {7:>12} {8:>12} {9:>12}")
    spreadsheet_str = ""
    for trial_num in range(5):
        b_ofg_pre = pre_results_by_tool.get("bluebird_ofg", {}).get(trial_num, set())
        b_pf_pre  = pre_results_by_tool.get("bluebird_promefuzz", {}).get(trial_num, set())
        ofg_pre   = pre_results_by_tool.get("ofg", {}).get(trial_num, set())
        lib_pre  = pre_results_by_tool.get("ogharn", {}).get(trial_num, set())
        pro_pre  = pre_results_by_tool.get("promefuzz", {}).get(trial_num, set())

        b_ofg_u_pre = b_ofg_pre.difference(b_pf_pre, ofg_pre, lib_pre, pro_pre)
        b_pf_u_pre  = b_pf_pre.difference(b_ofg_pre, ofg_pre, lib_pre, pro_pre)
        ofg_u_pre   = ofg_pre.difference(b_ofg_pre, b_pf_pre, lib_pre, pro_pre)
        lib_u_pre   = lib_pre.difference(b_ofg_pre, ofg_pre, b_pf_pre, pro_pre)
        pro_u_pre   = pro_pre.difference(b_ofg_pre, ofg_pre, lib_pre, b_pf_pre)

        b_ofg = post_results_by_tool.get("bluebird_ofg", {}).get(trial_num, set())
        b_pf  = post_results_by_tool.get("bluebird_promefuzz", {}).get(trial_num, set())
        ofg   = post_results_by_tool.get("ofg", {}).get(trial_num, set())
        lib  = post_results_by_tool.get("ogharn", {}).get(trial_num, set())
        pro   = post_results_by_tool.get("promefuzz", {}).get(trial_num, set())

        b_ofg_post = post_results_by_tool.get("bluebird_ofg", {}).get(trial_num, set()) - b_ofg_pre
        b_pf_post  = post_results_by_tool.get("bluebird_promefuzz", {}).get(trial_num, set()) - b_pf_pre
        ofg_post   = post_results_by_tool.get("ofg", {}).get(trial_num, set()) - ofg_pre
        lib_post  = post_results_by_tool.get("ogharn", {}).get(trial_num, set()) - lib_pre
        pro_post   = post_results_by_tool.get("promefuzz", {}).get(trial_num, set()) - pro_pre


        b_ofg_u = b_ofg.difference(b_pf, ofg, lib, pro) - b_ofg_u_pre
        b_pf_u  = b_pf.difference(b_ofg, ofg, lib, pro) - b_pf_u_pre
        ofg_u   = ofg.difference(b_ofg, b_pf, lib, pro) - ofg_u_pre
        lib_u  = lib.difference(b_ofg, ofg, b_pf, pro) - lib_u_pre
        pro_u  = pro.difference(b_ofg, ofg, lib, b_pf) - pro_u_pre

        values = (
            len(b_ofg_post), len(b_ofg_u),
            len(ofg_post),   len(ofg_u),
            len(b_pf_post),  len(b_pf_u),
            len(pro_post),   len(pro_u),
            len(lib_post),   len(lib_u),
        )
        print(fmt.format(*values))
        spreadsheet_str += (",".join(map(str, values))) + "\n"

    print(spreadsheet_str)

# --- high-level compare that user requested --------------------------------

def compare_pre_post_for_all_tools(pre_all: Dict[str, Dict[int, Set[str]]],
                                   post_all: Dict[str, Dict[int, Set[str]]]) -> None:
    """
    For each tool, compute per-trial and aggregate increases and print them.
    """
    for tool in sorted(set(pre_all.keys()) | set(post_all.keys())):
        print("\n" + "="*72)
        print(f"Tool: {tool}")
        pre_map = pre_all.get(tool, {})
        post_map = post_all.get(tool, {})

        per_trial, aggregate = compare_pre_post(pre_map, post_map)
        print("Per-trial stats (pre_total, post_total, newly_covered):")
        for t in sorted(per_trial.keys()):
            stats = per_trial[t]
            print(f"  trial {t}: pre={stats['pre_total']} post={stats['post_total']} new={stats['newly_covered']}")

        print("Aggregate across trials:")
        print(f"  pre_total = {aggregate['pre_total']}")
        print(f"  post_total = {aggregate['post_total']}")
        print(f"  newly_covered (post - pre) = {aggregate['newly_covered']}")

def main() -> None:
    global BENCHMARK_NAME
    args = parse_args()
    results_dir: Path = args.results_dir
    if not results_dir.exists():
        print(f"ERROR: results dir {results_dir} does not exist", file=sys.stderr)
        sys.exit(2)
    BENCHMARK_NAME = results_dir.name.split("results-")[-1]
    

    all_dirs = list(results_dir.iterdir())
    bluebird_ofg_dirs = [p for p in all_dirs if "bluebird_ofg" in p.name]
    bluebird_promefuzz_dirs = [p for p in all_dirs if "bluebird_promefuzz" in p.name]
    ofg_dirs = [p for p in all_dirs if "ofg" in p.name and "bluebird_ofg" not in p.name]
    ogharn_dirs = [p for p in all_dirs if "ogharn" in p.name]
    promefuzz_dirs = [p for p in all_dirs if "promefuzz" in p.name and "bluebird_promefuzz" not in p.name]

    tool_dirs = {
        "bluebird_ofg": bluebird_ofg_dirs,
        "bluebird_promefuzz": bluebird_promefuzz_dirs,
        "ofg": ofg_dirs,
        "ogharn": ogharn_dirs,
        "promefuzz": promefuzz_dirs,
    }

    # process post-fuzzing and pre-fuzzing (baseline)
    post_results_by_tool = process_and_report(tool_dirs, baseline=False)
    # pre_results_by_tool = process_and_report(tool_dirs, baseline=True)

    print("\nPOST-FUZZING SUMMARY")
    summarize_tools(post_results_by_tool)
    
    # print("\nSUBTRACTED BASELINE COVERAGE")
    # summarize_pre_vs_post(pre_results_by_tool, post_results_by_tool)

if __name__ == "__main__":
    main()