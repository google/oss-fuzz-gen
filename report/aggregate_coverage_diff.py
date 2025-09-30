#!/usr/bin/env python3

# This generates a per-PROJECT coverage diff (as opposed to the default
# per-benchmark).
# Usage: curl http://localhost:PORT/json | python aggregate_coverage_diff.py
# (where http://localhost:PORT comes from `python web.py <results-dir> <port>`)
# TODO: Generate this into the default web report.

import json
import logging
import re
import sys
import traceback

from google.cloud import storage

from experiment import evaluator, textcov

def compute_coverage_diff(project: str, coverage_links: list[str]):
  existing_textcov = evaluator.load_existing_textcov(project)
  coverage_summary = evaluator.load_existing_coverage_summary(project)

  # Can't use an anonymous client here as the coverage links may be on private
  # buckets.
  storage_client = storage.Client()
  new_textcov = textcov.Textcov()

  for coverage_link in coverage_links:
    path = coverage_link.removeprefix('gs://').split('/')
    bucket = storage_client.bucket(path[0])
    textcovs_path = '/'.join(path[1:] + ['textcov_reports'])

    blobs = storage_client.list_blobs(bucket,
                                      prefix=f'{textcovs_path}/',
                                      delimiter='/')
    for blob in blobs:
      logging.info('Loading %s', blob.name)
      with blob.open() as f:
        # TODO: skip other functions defined the target.
        new_textcov.merge(textcov.Textcov.from_file(f))

  new_textcov.subtract_covered_lines(existing_textcov)
  try:
    total_lines = coverage_summary['data'][0]['totals']['lines']['count']
  except KeyError:
    total_lines = 1

  return new_textcov.covered_lines / total_lines
  #print(f'{project}:', new_textcov.covered_lines / total_lines)

def main():
  logging.basicConfig(level=logging.INFO)

  project_coverages = {}

  data = json.load(sys.stdin)
  for benchmark in data['benchmarks']:
    # TODO(ochang): Properly store the project, as projects can have '-' in the name.
    project = benchmark['benchmark'].split('-')[1]
    report = benchmark.get('max_line_coverage_diff_report')
    if report:
      project_coverages.setdefault(project, []).append(report)

  diffs = {}
  for project, coverage_links in project_coverages.items():
    logging.info('Computing coverage diff for %s', project)
    try:
      diffs[project] = compute_coverage_diff(project, coverage_links)
    except Exception:
      logging.error('Failed to compute coverage for %s', project)
      traceback.print_exc()

  print(diffs)

if __name__ == '__main__':
  main()
