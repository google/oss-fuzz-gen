# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Post process results by from-scratch OSS-Fuzz generation."""

import argparse
import json
import logging
import os
import shutil
import sys
from typing import Any, Dict, List, Optional

import constants

logger = logging.getLogger(name=__name__)
LOG_FMT = '[%(filename)s:%(lineno)d]: %(message)s'


def _get_edge_cov_from_line(line: str) -> Optional[int]:
  """Extracts the edge coverage of a line output by libFuzzer."""
  split_line = line.split(' ')
  for line_idx, word in enumerate(split_line):
    if word == 'cov:':
      try:
        return int(split_line[line_idx + 1])
      except (ValueError, IndexError):
        pass
  return None


def interpret_llvm_run(log_path: str) -> dict[str, Any]:
  """Interprets a stderr log from a libFuzzer run and returns the edge coverage
  as well as the lines reported by ASAN errors."""
  with open(log_path, 'r', encoding='ISO-8859-1') as libfuzzer_out:
    cov_history = []
    addr_sanitizer_lines = []
    for line in libfuzzer_out:
      edge_coverage = _get_edge_cov_from_line(line)
      if edge_coverage is not None:
        cov_history.append(edge_coverage)
      if 'ERROR: AddressSanitizer' in line:
        addr_sanitizer_lines.append(line)

  return {'cov_history': cov_history, 'addr_san': addr_sanitizer_lines}


def oss_fuzz_out_dir(oss_fuzz_dir: str) -> str:
  """Returns the out folder of a given OSS-Fuzz repository."""
  return os.path.join(oss_fuzz_dir, 'build', 'out')


def get_oss_fuzz_generated_projects(oss_fuzz_dir: str) -> list[str]:
  """Gets the sample sessions for auto-gen projects in a given OSS-Fuzz dir."""
  project_indices = []
  for project_out in os.listdir(oss_fuzz_out_dir(oss_fuzz_dir)):
    if project_out.startswith(constants.PROJECT_BASE):
      try:
        project_indices.append(
            int(project_out.replace(constants.PROJECT_BASE, '')))
      except ValueError:
        pass

  sorted_project_folders = [
      constants.PROJECT_BASE + f'{idx}' for idx in list(sorted(project_indices))
  ]
  return sorted_project_folders


def interpret_single_harness_setup(
    oss_fuzz_dir: str, project_folder_out: str, generated_sample_setup: str,
    generated_sample_setup_dir: str) -> Optional[dict[str, Any]]:
  """Analyses a single auto-generated set up within an auto-generated
  session."""
  fuzz_run = os.path.join(generated_sample_setup_dir, 'fuzz-run.err')
  if not os.path.isfile(fuzz_run):
    return None

  run_results = interpret_llvm_run(fuzz_run)
  run_results['target'] = fuzz_run

  # Check the covreage run
  coverage_proj = os.path.basename(
      project_folder_out) + '-cov-' + generated_sample_setup
  harness_run_stats = os.path.join(oss_fuzz_out_dir(oss_fuzz_dir),
                                   coverage_proj, 'fuzzer_stats', 'fuzzer.json')
  if os.path.isfile(harness_run_stats):
    with open(harness_run_stats, 'r') as stats_file:
      cov_stats = json.load(stats_file)
    lines_coverage = cov_stats['data'][0]['totals']['lines']['percent']
  else:
    lines_coverage = -1.0
  run_results['line_coverage'] = lines_coverage

  # if there are no results then return None
  if len(run_results['cov_history']) <= 1:
    return None
  return run_results


def extract_results_from_generated_samples(
    oss_fuzz_dir: str, project_folder_out: str) -> list[dict[str, Any]]:
  """Iterates an auto-gen session and returns a list of successful results."""
  total_outcomes = []
  for generated_sample_setup in os.listdir(
      os.path.join(project_folder_out, constants.SHARED_MEMORY_RESULTS_DIR)):
    generated_sample_setup_dir = os.path.join(
        project_folder_out, constants.SHARED_MEMORY_RESULTS_DIR,
        generated_sample_setup)
    if not os.path.isdir(generated_sample_setup_dir):
      continue

    sample_result = interpret_single_harness_setup(oss_fuzz_dir,
                                                   project_folder_out,
                                                   generated_sample_setup,
                                                   generated_sample_setup_dir)
    if sample_result:
      total_outcomes.append(sample_result)
  return total_outcomes


def read_session_project_report(project_folder_out):
  """Reads the report generated by a auto-generation sessions for a given
  target repository."""
  report_file = os.path.join(project_folder_out,
                             constants.SHARED_MEMORY_RESULTS_DIR, 'report.txt')
  if not os.path.isfile(report_file):
    return None

  with open(report_file, 'r') as file:
    lines = [line.rstrip() for line in file]

  total_funcs = -1
  target_language = 'N/A'
  project = 'N/A'
  for line in lines:
    if 'Analysing: ' in line:
      project = line.replace('Analysing: ', '')
    if 'Total functions in' in line:
      total_funcs = max(total_funcs, int(line.split(' ')[-1]))
    if 'Target language: ' in line:
      target_language = line.split(' ')[-1]

  return {
      'total-functions': total_funcs,
      'language': target_language,
      'project': project
  }


def analyse_project_session(oss_fuzz_dir: str,
                            project_folder_out: str,
                            to_print: bool = False) -> List[Dict[str, Any]]:
  """Interprets the results for a auto-gen session."""
  logger.info('Analysing: %s', project_folder_out)
  project_report = read_session_project_report(project_folder_out)
  if not project_report:
    return []

  total_outcomes = extract_results_from_generated_samples(
      oss_fuzz_dir, project_folder_out)

  sorted_outcomes = sorted(total_outcomes,
                           key=lambda x: x['cov_history'][-1],
                           reverse=True)
  if to_print:
    logger.info('Results: %s', project_report['project'])
    logger.info('- Language: %s', project_report['language'])
    logger.info('- Functions from Fuzz Introspector: %s',
                project_report['total-functions'])
    logger.info('- Harnesses generated: %d', len(total_outcomes))
    for harness_result in sorted_outcomes:
      logger.info('%s :: %d :: %d :: [asan errors: %d] :: coverage: %f ',
                  harness_result['target'], harness_result['cov_history'][0],
                  harness_result['cov_history'][-1],
                  len(harness_result['addr_san']),
                  harness_result['line_coverage'])
  return sorted_outcomes


def analyse_oss_fuzz_build(oss_fuzz_dir: str) -> None:
  """Interprets the results from all auto-generated folders in a given
  OSS-Fuzz repository."""
  sorted_project_folders = get_oss_fuzz_generated_projects(oss_fuzz_dir)

  for target_project in sorted_project_folders:
    project_folder_out = os.path.join(oss_fuzz_out_dir(oss_fuzz_dir),
                                      target_project)
    if not os.path.isdir(project_folder_out):
      continue

    analyse_project_session(oss_fuzz_dir, project_folder_out, True)


def get_top_projects(oss_fuzz_dir: str) -> List[Dict[str, Any]]:
  """Gets the top project for each auto-generated project."""
  sorted_project_folders = get_oss_fuzz_generated_projects(oss_fuzz_dir)

  top_projects = []
  for target_project in sorted_project_folders:
    project_folder_out = os.path.join(oss_fuzz_out_dir(oss_fuzz_dir),
                                      target_project)
    if not os.path.isdir(project_folder_out):
      continue

    sorted_projects = analyse_project_session(oss_fuzz_dir, project_folder_out)
    if sorted_projects:
      top_projects.append(sorted_projects[0])

  for top_project in top_projects:
    logger.info('%s :: %d :: %d :: [asan errors: %d] :: coverage: %f ',
                top_project['target'],
                top_project['cov_history'][0], top_project['cov_history'][-1],
                len(top_project['addr_san']), top_project['line_coverage'])
  return top_projects


def get_oss_fuzz_project_name(oss_fuzz_dir: str, project: str) -> str:
  """Utility to create OSS-Fuzz project names."""
  idx = 0
  while True:
    project_name = f'auto-gen-{project}-{idx}'
    dst = os.path.join(oss_fuzz_dir, project_name)
    if not os.path.isdir(dst):
      return project_name
    idx += 1


def extract_repo_from_report(report_file: str) -> str:
  """Extract the GitHub project used for auto-generation."""
  with open(report_file, 'r') as f:
    report_content = f.read()
  target = report_content.split('\n')[0].replace('Analysing: ', '')
  github_project = target.split('/')[-1]
  return github_project


def copy_top_projects_to_dst(oss_fuzz_dir: str, destination: str) -> None:
  """Copies top generated projects into a given destination folder."""
  top_projects = get_top_projects(oss_fuzz_dir)

  os.makedirs(destination, exist_ok=True)
  for top_project in top_projects:
    project_basedir = os.path.dirname(top_project['target'])

    # Prepare destiantion project name
    project_report = os.path.join(project_basedir, '../report.txt')
    base_oss_fuzz_name = extract_repo_from_report(project_report)
    auto_gen_oss_fuzz_name = get_oss_fuzz_project_name(destination,
                                                       base_oss_fuzz_name)
    dst_oss_project = os.path.join(destination, auto_gen_oss_fuzz_name)

    # Copy the generate OSS-Fuzz project to the destination
    project_oss_fuzz_dir = os.path.join(project_basedir, 'oss-fuzz-project')
    shutil.copytree(project_oss_fuzz_dir, dst_oss_project)
    logger.info('- Created OSS-Fuzz project: %s', dst_oss_project)


def extract_builds(oss_fuzz_dir, dst_dir):
  """Extracts valid empty builds and copies to dst."""

  if os.path.isdir(dst_dir):
    logger.info('Destination directory exsits. Please delete it first.')
    sys.exit(0)

  os.makedirs(dst_dir, exist_ok=True)

  projects_added = set()
  for build_project in os.listdir(os.path.join(oss_fuzz_dir, 'build', 'out')):
    if 'temp-project-' not in build_project:
      continue

    project_dir = os.path.join(oss_fuzz_dir, 'build', 'out', build_project)

    # Get project name and the number of functions in potential builds.
    report_txt = os.path.join(project_dir, 'autogen-results', 'report.txt')

    if not os.path.isfile(report_txt):
      continue

    project_name = ''
    build_function_counts = []
    with open(report_txt, 'r', encoding='utf-8') as f:
      for line in f:
        if 'Analysing:' in line:
          project_name = line.split('/')[-1].replace('\n', '')
        if 'Total functions in' in line:
          build_function_counts.append(
              int(line.split(' ')[-1].replace('\n', '')))

    if project_name and build_function_counts:
      logger.debug('Project: %s', project_name)
      for idx, function_count in enumerate(build_function_counts):
        logger.debug('- %d, %d', idx, function_count)
        # Only include if we have at least two functions identified in the
        # fuzz introspector build
        if function_count >= 2:
          # Copy to destination.
          src_proj = os.path.join(project_dir, f'empty-build-{idx}')
          dst_proj = os.path.join(dst_dir, f'{project_name}-empty-build-{idx}')

          if os.path.isdir(dst_proj):
            logger.warning('Skipping %s to %s as dst already exists', src_proj,
                           dst_proj)
            continue
          shutil.copytree(src_proj, dst_proj)

          # Save project name for stats
          projects_added.add(project_name)
  logger.info('Found a total of %d projects', len(projects_added))
  for project in projects_added:
    logger.info('- %s', project)


def parse_args() -> argparse.Namespace:
  """Parses commandline arguments."""
  parser = argparse.ArgumentParser()

  subparsers = parser.add_subparsers(dest='command')
  print_parser = subparsers.add_parser(
      'print',
      help='prints results of auto-gen to stdout',
  )
  print_parser.add_argument('--oss-fuzz-dir',
                            type=str,
                            help='OSS-Fuzz directory with generated results',
                            required=True)
  top_finder = subparsers.add_parser(
      'top-projects',
      help='prints status of top projects',
  )
  top_finder.add_argument('--oss-fuzz-dir',
                          type=str,
                          help='OSS-Fuzz directory with generated results',
                          required=True)
  extract_top = subparsers.add_parser(
      'extract-top',
      help='Copies top projects to target folder.',
  )
  extract_top.add_argument('--oss-fuzz-dir',
                           type=str,
                           help='OSS-Fuzz directory with generated results',
                           required=True)
  extract_top.add_argument('--destination',
                           type=str,
                           help='Destination folder to store projects.',
                           required=True)

  extract_builds = subparsers.add_parser(
      'extract-builds',
      help='Extracts the generated projects with valid empty builds.')

  extract_builds.add_argument('--oss-fuzz', help='OSS-Fuzz directory.')
  extract_builds.add_argument('--dst', help='Destination folder.')

  args = parser.parse_args()
  return args


def setup_logging() -> None:
  """Instantiates logging with right format."""
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)


def main() -> None:
  """Entrypoint"""
  setup_logging()
  args = parse_args()
  if args.command == 'print':
    analyse_oss_fuzz_build(args.oss_fuzz_dir)
  elif args.command == 'top-projects':
    get_top_projects(args.oss_fuzz_dir)
  elif args.command == 'extract-top':
    copy_top_projects_to_dst(args.oss_fuzz_dir, args.destination)
  elif args.command == 'extract-builds':
    extract_builds(args.oss_fuzz, args.dst)


if __name__ == '__main__':
  main()
