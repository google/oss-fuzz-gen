#!/usr/bin/env python3
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
"""
Generates function-under-test and fuzz targets of OSS-Fuzz projects in pairs
for training.
"""

import argparse
import json
import os
import re
import sys
from multiprocessing.pool import ThreadPool
from typing import Dict, List

from google.cloud import storage

from data_prep import introspector, project_src
from experiment import oss_fuzz_checkout

OSS_FUZZ_EXP_BUCKET = 'oss-fuzz-llm-public'
# TODO(dongge): Use tmp dir.
OSS_FUZZ_PATH = os.path.join(os.path.dirname(__file__), '..', 'oss-fuzz')


def _get_fuzz_target_dir(project_name: str) -> str:
  """Returns the directory that contains the fuzz targets of |project_name|.
    """
  data_dir = os.path.abspath(
      os.path.join(os.path.dirname(__file__), '..', 'oss-fuzz-data'))
  fuzz_target_dir = os.path.join(data_dir, 'fuzz_targets')
  os.makedirs(fuzz_target_dir, exist_ok=True)

  project_fuzz_target_dir = os.path.join(fuzz_target_dir, project_name)
  os.makedirs(project_fuzz_target_dir, exist_ok=True)

  storage_client = storage.Client.create_anonymous_client()
  bucket = storage_client.bucket(OSS_FUZZ_EXP_BUCKET)
  project_prefix = os.path.join('human_written_targets', project_name)
  blobs = bucket.list_blobs(prefix=project_prefix)
  for blob in blobs:
    file_relpath = blob.name.replace(f'{project_prefix}/', '')
    filedir = os.path.dirname(
        os.path.join(project_fuzz_target_dir, file_relpath))
    os.makedirs(filedir, exist_ok=True)
    blob.download_to_filename(
        os.path.join(project_fuzz_target_dir, file_relpath))

  return project_fuzz_target_dir


def _match_target_path_content(target_paths: List[str],
                               fuzz_target_dir: str) -> Dict[str, str]:
  """Returns a dictionary with |target_paths| as keys and its file content
       from |fuzz_target_dir| as values."""
  path_contents = {}
  # Walk through the directory
  for dirpath, _, filenames in os.walk(fuzz_target_dir):
    for filename in filenames:
      # Compute the relative file path
      relative_path = os.path.relpath(os.path.join(dirpath, filename),
                                      fuzz_target_dir)
      for target_path in target_paths:
        if os.path.basename(target_path) != os.path.basename(relative_path):
          continue

        file_path = os.path.join(fuzz_target_dir, relative_path)
        with open(file_path) as file:
          content = file.read()
          path_contents[target_path] = filter_target_lines(content)

  return path_contents


def _bucket_match_target_content_signatures(
    target_funcs: Dict[str, List[Dict]], fuzz_target_dir: str,
    project_name: str) -> Dict[str, List[str]]:
  """Returns a list of dictionary with function signatures as keys and
    its fuzz target content as values."""
  if not target_funcs:
    print('Error: No fuzz target functions available.')
    return {}
  if not os.path.isdir(fuzz_target_dir):
    print('Error: Fuzz target directory does not exist ({fuzz_target_dir})')
    return {}

  target_path_contents = _match_target_path_content(list(target_funcs.keys()),
                                                    fuzz_target_dir)
  target_content_signature_dict = {}
  for target_path, functions in target_funcs.items():
    content = target_path_contents.get(target_path)
    # Some projects' `target_path` is different from the actual
    # path in container, due to relocation in build process.
    # For example, targe_path is /src/hiredis/format_command_fuzzer.c, different
    # from the actual path /src/hiredis/fuzzing/format_command_fuzzer.c in
    # https://storage.googleapis.com/oss-fuzz-introspector/hiredis/inspector-report/20240120/summary.json
    if not content:
      adjusted_target_paths = [
          t_path for t_path in target_path_contents
          if os.path.basename(t_path) == os.path.basename(target_path)
      ]
      if adjusted_target_paths:
        adjusted_target_path = adjusted_target_paths[0]
        content = target_path_contents.get(adjusted_target_path)
    if not content:
      return {}
    if content not in target_content_signature_dict:
      target_content_signature_dict[content] = []

    signatures = [
        introspector.query_introspector_function_signature(
            project_name,
            introspector.get_raw_function_name(func_info, project_name))
        for func_info in functions
    ]
    target_content_signature_dict[content].extend(signatures)

  return target_content_signature_dict


def generate_data(project_name: str,
                  sig_per_target: int = 1,
                  max_samples: int = 1,
                  cloud_experiment_bucket: str = ''):
  """Generates project-specific fuzz targets examples."""
  target_funcs = introspector.get_project_funcs(project_name)
  project_fuzz_target_dir = _get_fuzz_target_dir(project_name)
  target_content_signature_dict = _bucket_match_target_content_signatures(
      target_funcs, project_fuzz_target_dir, project_name)

  if target_content_signature_dict:
    print(f'Downloaded human-written fuzz targets of {project_name} from Google'
          f' Cloud Bucket: {OSS_FUZZ_EXP_BUCKET}.')
  else:
    print(f'Failed to download human-written fuzz target of {project_name} '
          f'from Google Cloud Bucket: {OSS_FUZZ_EXP_BUCKET}.')
    print('Will try to build from Google Cloud or local docker image.')
    target_content_signature_dict = _match_target_content_signatures(
        target_funcs, project_name, cloud_experiment_bucket)
  if not target_content_signature_dict:
    return []

  # Ensures the most complex fuzz target is always at the end.
  contents = sorted(target_content_signature_dict.keys(), key=len)
  sig_contents = []
  for i in range(sig_per_target):
    for content in contents:
      sigs = target_content_signature_dict.get(content, [])
      if i >= len(sigs):
        continue
      sig_contents.append([sigs[i], content])

  return sig_contents[-max_samples:]


def _remove_header_comments(code: str) -> str:
  """Removes comments and empty lines in the code."""
  # Remove single-line comments.
  single_line_comment = re.compile(r'//.*?\n')
  code = re.sub(single_line_comment, '\n', code)

  # Remove multi-line comments.
  multi_line_comment = re.compile(r'/\*.*?\*/', re.DOTALL)
  code = re.sub(multi_line_comment, '', code)

  # Remove empty lines.
  empty_line = re.compile(r'\n+\s*\n+')
  code = re.sub(empty_line, '\n', code)
  return code


def _remove_header(code: str) -> str:
  """Removes header comments (e.g. copyright) only before the first #include.
    """
  # Split the code at the first #include.
  parts = code.split('#include', 1)
  header = parts[0]
  content = '#include' + parts[1] if len(parts) > 1 else ''
  return _remove_header_comments(header) + content


def filter_target_lines(target_content: str) -> str:
  """Remove non-interesting lines in the target_content."""
  target_content = _remove_header(target_content)
  return target_content


def _match_target_content_signatures(
    target_funcs: Dict[str, List[Dict]],
    project_name: str,
    cloud_experiment_bucket: str = '') -> Dict[str, List[str]]:
  """Returns a list of dictionary with function signatures as keys and
    its fuzz target content as values."""
  if not target_funcs:
    print('Error: No fuzz target functions available.')
    return {}

  source_content = project_src.search_source(
      project_name, [], cloud_experiment_bucket=cloud_experiment_bucket)

  if not source_content[0]:
    print(f'Error: No fuzz target found for project {project_name}.')
    return {}

  target_path_contents = source_content[0]

  target_content_signature_dict = {}
  for target_path, functions in target_funcs.items():
    content = target_path_contents.get(target_path)
    # Some projects' `target_path` is different from the actual
    # path in container, due to relocation in build process.
    # For example, targe_path is /src/hiredis/format_command_fuzzer.c, different
    # from the actual path /src/hiredis/fuzzing/format_command_fuzzer.c in
    # https://storage.googleapis.com/oss-fuzz-introspector/hiredis/inspector-report/20240120/summary.json
    if not content:
      adjusted_target_paths = [
          t_path for t_path in target_path_contents
          if os.path.basename(t_path) == os.path.basename(target_path)
      ]
      if adjusted_target_paths:
        adjusted_target_path = adjusted_target_paths[0]
        content = target_path_contents.get(adjusted_target_path)
    if not content:
      return {}
    if content not in target_content_signature_dict:
      target_content_signature_dict[content] = []

    signatures = [
        introspector.query_introspector_function_signature(
            project_name,
            introspector.get_raw_function_name(func_info, project_name))
        for func_info in functions
    ]
    target_content_signature_dict[content].extend(signatures)

  return target_content_signature_dict


def _parse_arguments():
  """Parses command line args."""
  parser = argparse.ArgumentParser(
      description='Parse project-related arguments')

  # project_name argument
  parser.add_argument('-p',
                      '--project-name',
                      type=str,
                      required=True,
                      help='Name of the project')

  # result_path argument
  parser.add_argument('-r',
                      '--result-path',
                      type=str,
                      help='Path to store the results')

  # number of signatures per target argument
  parser.add_argument(
      '-n',
      '--num-signature-per-target',
      type=int,
      default=1,
      help='Number of signatures per fuzz target (default is 1 if unspecified)')

  # maximum number of samples per project argument
  parser.add_argument(
      '-m',
      '--max-samples',
      type=int,
      default=0,
      help='Maximum number of samples per project (default is 0 if unspecified)'
  )

  # number of threads argument
  parser.add_argument('-t',
                      '--num-threads',
                      type=int,
                      default=4,
                      help='Number of threads to use')

  parser.add_argument('-cb',
                      '--cloud-experiment-bucket',
                      type=str,
                      default='',
                      help='A gcloud bucket to store experiment files.')

  parsed_args = parser.parse_args()
  if not parsed_args.result_path:
    parsed_args.result_path = f'{parsed_args.project_name}.json'
  return parsed_args


def _generate_project_training_data(project_name: str,
                                    sig_per_target,
                                    max_samples,
                                    cloud_experiment_bucket: str = ''):
  try:
    return generate_data(project_name, sig_per_target, max_samples,
                         cloud_experiment_bucket)
  except Exception as e:
    print(f'Project {project_name} failed:\n{e}')
    return None


def main():
  args = _parse_arguments()
  project_name = args.project_name
  result_path = args.result_path
  sig_per_target = args.num_signature_per_target
  max_samples = args.max_samples
  num_threads = args.num_threads

  all_projects = []
  if project_name == 'all':
    all_projects = oss_fuzz_checkout.list_c_cpp_projects()
  else:
    all_projects = [project_name]

  training_data = []
  configs = [[
      project,
      sig_per_target,
      max_samples,
      args.cloud_experiment_bucket,
  ] for project in all_projects]
  with ThreadPool(num_threads) as p:
    for data in p.starmap(_generate_project_training_data, configs):
      if data is None:
        continue
      training_data.extend(data)

  result_name, result_ext = os.path.splitext(result_path)
  result_path = f'{result_name}_{len(training_data)}{result_ext}'
  with open(result_path, 'w+') as file:
    json.dump(training_data, file, indent=4)


if __name__ == '__main__':
  sys.exit(main())
