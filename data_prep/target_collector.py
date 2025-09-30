#!/usr/bin/env python3
"""Collects the fuzz target files in a project."""
# Sample usage:
# 1. Copy this file to /src/ in an OSS-Fuzz project container.
# 2. Run `./target_collector.py <project_name>` the script
#  will create /src/targets/ save all fuzz target files to it.

import datetime
import json
import logging
import os
import shutil
import sys
from typing import Set

import requests

logger = logging.getLogger(__name__)

def _extract_introspector_report(project_name, date_str):
  project_url = ('https://storage.googleapis.com/oss-fuzz-introspector/'
                 f'{project_name}/inspector-report/{date_str}/summary.json')
  # Read the introspector artifact.
  try:
    raw_introspector_json_request = requests.get(project_url, timeout=10)
    introspector_report = json.loads(raw_introspector_json_request.text)
  except:
    return None
  return introspector_report

def _get_targets(project_name: str) -> Set[str]:
  """Fetches the latest fuzz targets and function signatures of |project_name|
    from FuzzIntrospector."""
  yesterday = datetime.date.today() - datetime.timedelta(days=2)
  introspector_json_report = _extract_introspector_report(
      project_name, yesterday.strftime('%Y%m%d'))
  if introspector_json_report is None:
    logger.info('Error: No fuzz introspector report is found.')
    return set()

  annotated_cfg = introspector_json_report['analyses']['AnnotatedCFG']
  return set(annotated_cfg[fuzzer]['src_file'] for fuzzer in annotated_cfg)

def main() -> None:
  """Installs tools, gets signatures, and writes them to the result file."""
  project_name = sys.argv[1]
  targets = _get_targets(project_name)
  os.makedirs(f'/work/out/{project_name}', exist_ok=True)
  for target in targets:
    shutil.copy(target, f'/work/out/{project_name}')

if __name__ == '__main__':
  main()
