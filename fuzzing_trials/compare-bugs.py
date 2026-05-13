#!/usr/bin/python3

import os
from pathlib import Path
import random
import re
import shutil
import signal
import argparse
import string
import subprocess
import sys
from functools import partial
from multiprocessing import Pool, cpu_count

bounds_dict = dict()


def random_string(size=6, chars=string.ascii_uppercase + string.digits):
  return ''.join(random.choice(chars) for _ in range(size))


def handle_sigint(sig, frame):
  print('\n[*] Ctrl+C pressed! Stopping processing.')
  sys.exit(0)
  return


#--------------------------------------------------------------------
# Helper function to create CASR directories for ASAN / GDB reports.
#--------------------------------------------------------------------
def setup_casr_dirs(results_dir):
  casr_dir = "%s/casr/" % results_dir
  casr_raw_dir = "%s/casr/raw" % results_dir
  casr_post_dir = "%s/casr/post" % results_dir

  try:
    shutil.rmtree(casr_dir)
  except:
    pass

  os.mkdir(casr_dir)
  os.mkdir(casr_raw_dir)
  os.mkdir(casr_post_dir)
  return


#--------------------------------------------------------------------
# Helper function to run CASR's deduplication on ASAN / GDB reports.
#--------------------------------------------------------------------
def run_casr_dedup(results_dir):
  casr_dir = "%s/casr/" % results_dir
  casr_raw_dir = "%s/casr/raw" % results_dir
  casr_post_dir = "%s/casr/post" % results_dir

  casr_dedup_cmd = "casr-cluster -d %s %s" \
      % (casr_raw_dir, casr_post_dir)

  if (os.getenv("DEBUG")):
    subprocess.call(casr_dedup_cmd, shell=True)
  else:
    subprocess.call(casr_dedup_cmd, shell=True, \
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

  casr_report_cmd = "casr-cli %s" % (casr_raw_dir)

  with open("%s/report.txt" % casr_dir, "w") as f:
    subprocess.call(casr_report_cmd, shell=True, \
        stderr=subprocess.DEVNULL, stdout=f)
  return


#--------------------------------------------------------------------
# Helper function to run CASR's ASAN / GDB crash report generation.
#--------------------------------------------------------------------
def run_casr(results_dir, cmd):
  casr_raw_dir = "%s/casr/raw" % results_dir

  tid = re.search(r'^(?:id_)([0-9]{6})|^(?:id:)([0-9]{6})', \
      os.path.basename(cmd)).group()

  casr_gdb_cmd = "casr-gdb -o %s/%s.gdb.casrep -- %s" \
      % (casr_raw_dir, tid, cmd)

  if (os.getenv("DEBUG")):
    subprocess.call(casr_gdb_cmd, shell=True)
  else:
    subprocess.call(casr_gdb_cmd, shell=True, \
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

  casr_san_cmd = "casr-san -o %s/%s.san.casrep -- %s" \
      % (casr_raw_dir, tid, cmd)
  print(casr_san_cmd)

  if (os.getenv("DEBUG")):
    subprocess.call(casr_san_cmd, shell=True)
  else:
    subprocess.call(casr_san_cmd, shell=True, \
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
  return


#--------------------------------------------------------------------
# Read the CASR-generated reports into a set of bugs + source lines.
# Merge both crash sets based on uniqueness of crashing source line.
#--------------------------------------------------------------------
def get_crash_set(results_dir):
  with open("%s/casr/report.txt" % results_dir, "r") as crash_data:
    print(crash_data.read())
    matches_gdb = set([(x, os.path.basename(y)) for (x,y) \
        in re.findall(r'^\s*\w*.gdb.casrep\W*\w*:\s([\w\-\(\)]*):\s([\/\w\-\.]*[.c.h.cpp.cc.hpp]\:[\w]*)', \
        crash_data.read(), re.MULTILINE)])
  with open("%s/casr/report.txt" % results_dir, "r") as crash_data:
    matches_san = set([(x, os.path.basename(y)) for (x,y) \
        in re.findall(r'^\s*\w*\s*casrep\W*\w*:\s([\w\-\(\)]*):\s([\/\w\-\.]*[.c.h.cpp.cc.hpp]\:[\w]*)', \
        crash_data.read(), re.MULTILINE)])
  return matches_san.union([(x,y) for (x,y) \
      in matches_gdb if y not in [b for (a,b) in matches_san]])


#--------------------------------------------------------------------
# Retrieve crashes for AFL-like fuzzers.
#--------------------------------------------------------------------
def process_afl(result_dirs, prefix):
  bugs_set = set()
  cpu_pool = Pool(cpu_count())

  for d in sorted(result_dirs):
    results_path = os.path.normpath(d)
    afl_output_path = os.path.join(d, "afl_output")
    harness_path = os.path.join(results_path, "artifacts", f"{prefix}-F0-00", "asan_driver")
    setup_casr_dirs(afl_output_path)
    crash_path = os.path.join(afl_output_path, "default", "crashes")

    rep_crash_cmds = [f"{harness_path} {crash_path}/{x}" \
                    for x in os.listdir(crash_path) \
                    if x.startswith('id:')]

    cpu_pool.map(partial(run_casr, afl_output_path), rep_crash_cmds)
    run_casr_dedup(afl_output_path)
    bugs_set = bugs_set.union(get_crash_set(afl_output_path))
  return bugs_set


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process and compare LCOV branch coverage (.lcov_total) reports.")
    parser.add_argument("-r", "--results-dir", type=Path, required=True)
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    results_dir = args.results_dir
    if not results_dir.exists():
        print(f"ERROR: results dir {results_dir} does not exist", file=sys.stderr)
        sys.exit(2)

    all_dirs = list(results_dir.iterdir())
    bluebird_ofg_dirs = [p for p in all_dirs if "bluebird_ofg" in p.name]
    ofg_dirs = [p for p in all_dirs if "ofg" in p.name and "bluebird_ofg" not in p.name]
    bluebird_promefuzz_dirs = [p for p in all_dirs if "bluebird_promefuzz" in p.name]
    promefuzz_dirs = [p for p in all_dirs if "promefuzz" in p.name and "bluebird_promefuzz" not in p.name]
    ogharn_dirs = [p for p in all_dirs if "ghar" in p.name]

    bugs_bluebird_ofg = process_afl(bluebird_ofg_dirs, "bluebird_ofg")
    bugs_ofg = process_afl(ofg_dirs, "ofg")
    bugs_bluebird_promefuzz = process_afl(bluebird_promefuzz_dirs, "bluebird_promefuzz")
    bugs_promefuzz = process_afl(promefuzz_dirs, "promefuzz")
    bugs_ogharn = process_afl(ogharn_dirs, "ogharn")


    all_sets = {
    "bluebird_ofg": bugs_bluebird_ofg,
    "ofg": bugs_ofg,
    "bluebird_promefuzz": bugs_bluebird_promefuzz,
    "promefuzz": bugs_promefuzz,
    "ogharn": bugs_ogharn,
    }

    print("[*] Bug-finding comparison for: %s" % (results_dir))
    for name, bugset in all_sets.items():
        others_union = set().union(*(s for n, s in all_sets.items() if n != name))
        unique = bugset - others_union

        print(f"--- {name} Total  :", len(bugset))
        print(*bugset, sep="\n")
        print()
        print(f"--- {name} Unique :", len(unique))
        print(*unique, sep="\n")
        print("\n")


if __name__ == "__main__":
    main()