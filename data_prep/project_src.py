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
"""Project source parser."""
import argparse
import logging
import os
import subprocess as sp
import tempfile
import uuid
from multiprocessing import pool
from typing import Dict

from google.cloud import storage

from experiment import benchmark, oss_fuzz_checkout

logger = logging.getLogger(__name__)

SEARCH_IGNORE_DIRS = ['aflplusplus', 'fuzztest', 'honggfuzz', 'libfuzzer']
SEARCH_EXTS = ['.c', '.cc', '.cpp', '.cxx', '.c++']


def _parse_arguments() -> argparse.Namespace:
  """Parses command line args."""
  parser = argparse.ArgumentParser(
      description='Parse arguments to generate fuzz targets')

  parser.add_argument('-p',
                      '--project-name',
                      type=str,
                      required=True,
                      help='Name of the project')

  parser.add_argument('-r',
                      '--result-dir',
                      type=str,
                      default='example_targets',
                      help='Path to store the results')

  parser.add_argument('-t',
                      '--num-threads',
                      type=int,
                      default=4,
                      help='Number of threads to use')

  parser.add_argument('-f',
                      '--interesting-filenames',
                      nargs='*',
                      type=str,
                      default=[],
                      help='Other interesting filenames to parse.')
  parser.add_argument('-cb',
                      '--cloud-experiment-bucket',
                      type=str,
                      default='',
                      help='A gcloud bucket to store experiment files.')
  args = parser.parse_args()
  args.interesting_filenames = list(set(args.interesting_filenames))
  return args


def _read_harness(src_file: str, encoding_error_handling: str = 'replace'):
  """Reads content of a harness |src_file| and handles encoding error."""
  with open(src_file, encoding='utf-8', errors=encoding_error_handling) as fp:
    try:
      content = fp.read()
    except Exception as e:
      raise type(e)(f'Failed to decode fuzz target {src_file} with '
                    f'{encoding_error_handling}.')
  return content


def _format_source(src_file: str) -> str:
  """Runs Clang format and returns formatted code."""
  # Need to install clang-format, e.g., apt install clang-format.
  cmd = ['clang-format', '-style={ColumnLimit: 1000}', '-i', src_file]
  timeout_seconds = 60
  try:
    result = sp.run(cmd,
                    check=True,
                    capture_output=True,
                    stdin=sp.DEVNULL,
                    timeout=timeout_seconds)
  except sp.TimeoutExpired:
    logger.debug(
        'Could not format in %d seconds: %s',
        timeout_seconds,
        src_file,
    )
  except Exception as e:
    logger.debug('Failed to format %s: %s', src_file, e)
  else:
    if result.returncode:
      logger.warning('Failed to format %s:', src_file)
      logger.warning('STDOUT: %s', result.stdout)
      logger.warning('STDERR: %s', result.stderr)
  if os.path.isfile(src_file):
    return _read_harness(src_file) or _read_harness(src_file, 'ignore') or ''
  logger.warning('Failed to find file: %s', src_file)

  return ''


def _get_interesting_file(src_file: str, out: str) -> tuple[str, str]:
  """Returns the path name and content of |src_file|"""
  short_path = src_file[len(out):]
  content = _format_source(src_file)
  if not content:
    return '', ''
  return short_path, content


def _get_harness(src_file: str, out: str, language: str) -> tuple[str, str]:
  """Returns the path name and content of harness."""

  content = _format_source(src_file)

  if language.lower() in {'c++', 'c'
                         } and 'int LLVMFuzzerTestOneInput' not in content:
    return '', ''
  if language.lower(
  ) == 'jvm' and 'static void fuzzerTestOneInput' not in content:
    return '', ''

  short_path = src_file[len(out):]
  return short_path, content


def _build_project_local_docker(project: str):
  """Builds the project with OSS-Fuzz."""
  helper_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'infra',
                             'helper.py')
  command = [
      'python3', helper_path, 'build_image', '--cache', '--no-pull', project
  ]
  logger.info('Building project image: %s', ' '.join(command))
  result = sp.run(command,
                  stdout=sp.PIPE,
                  stderr=sp.STDOUT,
                  stdin=sp.DEVNULL,
                  check=False)
  if result.returncode:
    logger.error('Failed to build OSS-Fuzz image for %s:', project)
    logger.error('return code %d: %s', result.returncode, result.stdout)
    raise Exception('Failed to build OSS-Fuzz image for {project}')
  logger.info('Done building image.')


def _copy_project_src(project: str,
                      out: str,
                      cloud_experiment_bucket: str = ''):
  """Copies /|src| from cloud if bucket is available or from local image."""
  if cloud_experiment_bucket:
    logger.info(
        f'Retrieving human-written fuzz targets of {project} from Google '
        'Cloud Build.')
    bucket_dirname = _build_project_on_cloud(project, cloud_experiment_bucket)
    _copy_project_src_from_cloud(bucket_dirname, out, cloud_experiment_bucket)
  else:
    logger.info(
        f'Retrieving human-written fuzz targets of {project} from local '
        'Docker build.')
    _build_project_local_docker(project)
    _copy_project_src_from_local(project, out)


def _build_project_on_cloud(project: str, cloud_experiment_bucket: str) -> str:
  """Builds project image on cloud and copies /src."""
  # project => cloud_experiment_name
  uid = project + '-' + str(uuid.uuid4())
  search_regex = '-o'.join(f' -name "*{ext}" ' for ext in SEARCH_EXTS)
  ignore_regex = ' '.join(
      f'! -path "/src/{bad_dir}/*"' for bad_dir in SEARCH_IGNORE_DIRS)
  cp_command = (f'find /src \\({search_regex}\\) {ignore_regex} '
                '-exec cp --parents {} /workspace/out/ \\;')
  cloud_build_command = [
      f'./{oss_fuzz_checkout.VENV_DIR}/bin/python3',
      'infra/build/functions/project_experiment.py',
      f'--project={project}',
      f'--command={cp_command}',
      f"--upload_output=gs://{cloud_experiment_bucket}/{uid}",
      f'--experiment_name={uid}',
  ]
  cloud_build_result = sp.run(cloud_build_command,
                              capture_output=True,
                              stdin=sp.DEVNULL,
                              text=True,
                              check=False,
                              cwd=oss_fuzz_checkout.OSS_FUZZ_DIR)
  if (cloud_build_result.returncode or
      'failed: step exited with non-zero status' in cloud_build_result.stdout):
    logger.error('Failed to upload /src/ in OSS-Fuzz image of %s:', project)
    logger.error('STDOUT: %s', cloud_build_result.stdout)
    logger.error('STDERR: %s', cloud_build_result.stderr)
    raise Exception(
        f'Failed to run cloud build command: {" ".join(cloud_build_command)}')

  return uid


def _copy_project_src_from_cloud(bucket_dirname: str, out: str,
                                 cloud_experiment_bucket: str):
  """Copies /src from |bucket_dirname|."""
  storage_client = storage.Client()
  bucket = storage_client.bucket(cloud_experiment_bucket)
  blobs = bucket.list_blobs(prefix=bucket_dirname)
  # Download each file in the directory
  for blob in blobs:
    # Ignore directories
    if blob.name.endswith('/'):
      continue
    # Create a local path that mirrors the structure in the bucket.
    relative_path = blob.name[len(bucket_dirname) + 1:]
    local_file_path = os.path.join(out, 'src', relative_path)
    # Create local directories if they don't exist
    local_dir = os.path.dirname(local_file_path)
    os.makedirs(local_dir, exist_ok=True)

    # Download the file
    blob.download_to_filename(local_file_path)
    logger.info(f"Downloaded {blob.name} to {local_file_path}")
    blob.delete()
    logger.info(f"Deleted {blob.name} from the bucket.")


def _copy_project_src_from_local(project: str, out: str):
  """Runs the project's OSS-Fuzz image to copy /|src| to /|out|."""
  run_container = [
      'docker',
      'run',
      '-d',
      '--rm',
      '--shm-size=2g',
      '--platform',
      'linux/amd64',
      '-e',
      'FUZZING_ENGINE=libfuzzer',
      '-e'
      'SANITIZER=address',
      '-e',
      'ARCHITECTURE=x86_64',
      '-e',
      f'PROJECT_NAME={project}',
      '-e',
      'HELPER=True',
      '-e',
      'FUZZING_LANGUAGE=c++',
      '--name',
      f'{project}-container',
      f'gcr.io/oss-fuzz/{project}',
  ]
  result = sp.run(run_container,
                  capture_output=True,
                  stdin=sp.DEVNULL,
                  check=False)
  if result.returncode:
    logger.error('Failed to run OSS-Fuzz image of %s:', project)
    logger.error('STDOUT: %s', result.stdout)
    logger.error('STDERR: %s', result.stderr)
    raise Exception(f'Failed to run docker command: {" ".join(run_container)}')

  try:
    copy_src = ['docker', 'cp', f'{project}-container:/src', out]
    result = sp.run(copy_src,
                    capture_output=True,
                    stdin=sp.DEVNULL,
                    check=False)
    if result.returncode:
      logger.error('Failed to copy /src from OSS-Fuzz image of %s:', project)
      logger.error('STDOUT: %s', result.stdout)
      logger.error('STDERR: %s', result.stderr)
      raise Exception(f'Failed to run docker command: {" ".join(copy_src)}')
    logger.info('Done copying %s /src to %s.', project, out)
  finally:
    # Shut down the container that was just started.
    result = sp.run(['docker', 'container', 'stop', f'{project}-container'],
                    capture_output=True,
                    stdin=sp.DEVNULL,
                    check=False)
    if result.returncode:
      logger.error('Failed to stop container image: %s-container', project)
      logger.error('STDOUT: %s', result.stdout)
      logger.error('STDERR: %s', result.stderr)


def _identify_fuzz_targets(out: str, interesting_filenames: list[str],
                           language: str) -> tuple[list[str], list[str]]:
  """
  Identifies fuzz target file contents and |interesting_filenames| in |out|.
  """
  logger.debug('len(interesting_filenames): %d', len(interesting_filenames))

  interesting_filepaths = []
  potential_harnesses = []

  for root, _, filenames in os.walk(out):
    is_bad = False
    for ignore_dir in SEARCH_IGNORE_DIRS:
      # Exclude engine source.
      if f'out/src/{ignore_dir}' in root:
        is_bad = True
        break
    if is_bad:
      continue
    for filename in filenames:
      if not benchmark.get_file_type(filename):
        continue
      path = os.path.join(root, filename)
      if language == 'jvm':
        # For JVM
        if path.endswith(tuple(interesting_filenames)):
          interesting_filepaths.append(path)
        if path.endswith('.java'):
          potential_harnesses.append(path)
      else:
        # For C/C++
        short_path = path[len(out):]
        if short_path in interesting_filenames:
          interesting_filepaths.append(path)
        # TODO(dongge): Figure out why the path does not match Bazel projects.
        if os.path.basename(short_path) in interesting_filenames:
          interesting_filepaths.append(path)

        if any(path.endswith(suffix) for suffix in SEARCH_EXTS):
          potential_harnesses.append(path)

  return potential_harnesses, interesting_filepaths


def _parse_fuzz_targets(project: str, out: str, potential_harnesses: list[str],
                        interesting_filepaths: list[str],
                        language: str) -> tuple[dict[str, str], dict[str, str]]:
  """
  Parses fuzz target file contents and |interesting_filenames| in |out|.
  """
  interesting_files = {}
  for src_file in interesting_filepaths:
    short_path, content = _get_interesting_file(src_file, out)
    if short_path == content == '':
      continue
    interesting_files[short_path] = content

  fuzz_targets = {}
  for harness in potential_harnesses:
    short_path, content = _get_harness(harness, out, language)
    if short_path == content == '':
      continue
    fuzz_targets[short_path] = content
  # Sometimes you will get /src/$DEPENDENCY/$FUZZER (e.g. /src/cJSON when
  # fuzzing mosquitto). OSS-Fuzz is too popular.
  pruned = {k: v for k, v in fuzz_targets.items() if project in k}
  fuzz_targets = pruned or fuzz_targets

  return fuzz_targets, interesting_files


def _copy_fuzz_targets(harness_path: str, dest_dir: str, project: str):
  """Copies the harness from |harness_path| to ./|dest_dir|/|project|/."""
  if not dest_dir:
    return
  dest_dir = os.path.join(dest_dir, project)
  os.makedirs(dest_dir, exist_ok=True)
  command = ['cp', harness_path, dest_dir]
  result = sp.run(command, capture_output=True, stdin=sp.DEVNULL, check=True)
  if result.returncode:
    logger.error('Failed to copy harness from %s to %s: %s %s.', harness_path,
                 dest_dir, result.stdout, result.stderr)
    raise Exception(f'Failed to copy harness from {harness_path} to {dest_dir}',
                    harness_path, dest_dir)

  logger.info('Retrieved fuzz targets from %s:\n  %s', project,
              '\n  '.join(os.listdir(dest_dir)))


def search_source(
    project: str,
    interesting_filenames: list,
    language: str,
    result_dir: str = '',
    cloud_experiment_bucket: str = '',
) -> tuple[Dict[str, str], Dict[str, str]]:
  """Searches source code of the target OSS-Fuzz project for the files listed
    in |interesting_filenames|. Returns a dictionary of fuzz targets (path:
    contents) and a dictionary of interesting files to their contents."""
  with tempfile.TemporaryDirectory() as temp_dir:
    out = os.path.join(temp_dir, 'out')
    os.makedirs(out)

    _copy_project_src(project, out, cloud_experiment_bucket)

    potential_harnesses, interesting_filepaths = _identify_fuzz_targets(
        out, interesting_filenames, language)
    fuzz_targets, interesting_files = _parse_fuzz_targets(
        project, out, potential_harnesses, interesting_filepaths, language)

    for short_path in fuzz_targets.keys():
      _copy_fuzz_targets(os.path.join(out, short_path[1:]), result_dir, project)
  return fuzz_targets, interesting_files


def main():
  args = _parse_arguments()
  projects = []
  if args.project_name == 'all':
    projects = oss_fuzz_checkout.list_c_cpp_projects()
  else:
    projects = [args.project_name]

  configs = [[
      project,
      args.interesting_filenames,
      args.result_dir,
      args.cloud_experiment_bucket,
  ] for project in projects]
  oss_fuzz_checkout.clone_oss_fuzz()
  oss_fuzz_checkout.postprocess_oss_fuzz()
  with pool.ThreadPool(args.num_threads) as p:
    p.starmap(search_source, configs)


if __name__ == '__main__':
  main()
