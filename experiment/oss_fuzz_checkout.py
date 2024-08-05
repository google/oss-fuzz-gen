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
Tools used for experiments.
"""

import atexit
import logging
import os
import shutil
import subprocess as sp
import tempfile

import yaml

logger = logging.getLogger(__name__)

BUILD_DIR: str = 'build'
GLOBAL_TEMP_DIR: str = ''
ENABLE_CACHING = bool(int(os.getenv('OFG_USE_CACHING', '0')))
# Assume OSS-Fuzz is at repo root dir by default.
# This will change if temp_dir is used.
OSS_FUZZ_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'oss-fuzz')

VENV_DIR: str = 'venv'


def _remove_temp_oss_fuzz_repo():
  """Deletes the temporary OSS-Fuzz directory."""
  # Ensure we aren't deleting a real repo someone cares about.
  assert not OSS_FUZZ_DIR.endswith('oss-fuzz')
  try:
    shutil.rmtree(OSS_FUZZ_DIR)
  except PermissionError as e:
    logger.warning('No permission to remove %s: %s', OSS_FUZZ_DIR, e)
  except FileNotFoundError as e:
    logger.warning('No OSS-Fuzz directory %s: %s', OSS_FUZZ_DIR, e)


def _set_temp_oss_fuzz_repo():
  """Creates a temporary directory for OSS-Fuzz repo and update |OSS_FUZZ_DIR|.
  """
  # Holding the temp directory in a global object to ensure it won't be deleted
  # before program ends.
  global GLOBAL_TEMP_DIR
  GLOBAL_TEMP_DIR = tempfile.mkdtemp()
  global OSS_FUZZ_DIR
  OSS_FUZZ_DIR = GLOBAL_TEMP_DIR
  atexit.register(_remove_temp_oss_fuzz_repo)
  _clone_oss_fuzz_repo()


def _clone_oss_fuzz_repo():
  """Clones OSS-Fuzz to |OSS_FUZZ_DIR|."""
  clone_command = [
      'git', 'clone', 'https://github.com/google/oss-fuzz', '--depth', '1',
      OSS_FUZZ_DIR
  ]
  proc = sp.Popen(clone_command,
                  stdout=sp.PIPE,
                  stderr=sp.PIPE,
                  stdin=sp.DEVNULL)
  stdout, stderr = proc.communicate()
  if proc.returncode != 0:
    logger.info(stdout)
    logger.info(stderr)


def clone_oss_fuzz(oss_fuzz_dir: str = ''):
  """Clones the OSS-Fuzz repository."""
  if oss_fuzz_dir:
    global OSS_FUZZ_DIR
    OSS_FUZZ_DIR = oss_fuzz_dir
  else:
    _set_temp_oss_fuzz_repo()

  if not os.path.exists(OSS_FUZZ_DIR):
    _clone_oss_fuzz_repo()
  # Remove existing targets.
  clean_command = ['git', 'clean', '-fxd', '-e', VENV_DIR, '-e', BUILD_DIR]
  sp.run(clean_command,
         capture_output=True,
         stdin=sp.DEVNULL,
         check=True,
         cwd=OSS_FUZZ_DIR)


def postprocess_oss_fuzz() -> None:
  """Prepares the oss-fuzz directory for experiments."""
  # Write .gcloudignore to make submitting to GCB faster.
  with open(os.path.join(OSS_FUZZ_DIR, '.gcloudignore'), 'w') as f:
    f.write('__pycache__\n')
    f.write('build\n')
    f.write('.git\n')
    f.write('.pytest_cache\n')
    f.write('venv\n')

  # Set up dependencies to run OSS-Fuzz build scripts
  if os.path.exists(os.path.join(OSS_FUZZ_DIR, VENV_DIR)):
    return

  # If already in a virtualenv environment assume all is set up
  if os.environ.get('VIRTUAL_ENV', ''):
    return

  result = sp.run(['python3', '-m', 'venv', VENV_DIR],
                  check=True,
                  capture_output=True,
                  stdin=sp.DEVNULL,
                  cwd=OSS_FUZZ_DIR)
  result = sp.run([
      f'./{VENV_DIR}/bin/pip', 'install', '-r',
      'infra/build/functions/requirements.txt'
  ],
                  check=True,
                  cwd=OSS_FUZZ_DIR,
                  stdin=sp.DEVNULL,
                  capture_output=True)
  if result.returncode:
    logger.info(f'Failed to postprocess OSS-Fuzz ({OSS_FUZZ_DIR})')
    logger.info('stdout: ', result.stdout)
    logger.info('stderr: ', result.stderr)


def list_c_cpp_projects() -> list[str]:
  """Returns a list of all c/c++ projects from oss-fuzz."""
  projects = []
  clone_oss_fuzz()
  projects_dir = os.path.join(OSS_FUZZ_DIR, 'projects')
  for project in os.listdir(projects_dir):
    project_yaml_path = os.path.join(projects_dir, project, 'project.yaml')
    with open(project_yaml_path) as yaml_file:
      config = yaml_file.read()
      if 'language: c' in config:
        projects.append(project)
  return sorted(projects)


def get_project_language(project: str) -> str:
  """Returns the |project| language read from its project.yaml."""
  project_yaml_path = os.path.join(OSS_FUZZ_DIR, 'projects', project,
                                   'project.yaml')
  if not os.path.isfile(project_yaml_path):
    logger.warning('Failed to find the project yaml of %s, assuming it is C++',
                   project)
    return 'C++'

  with open(project_yaml_path, 'r') as benchmark_file:
    data = yaml.safe_load(benchmark_file)
    return data.get('language', 'C++')


def get_project_repository(project: str) -> str:
  """Returns the |project| repository read from its project.yaml."""
  project_yaml_path = os.path.join(OSS_FUZZ_DIR, 'projects', project,
                                   'project.yaml')
  if not os.path.isfile(project_yaml_path):
    logger.warning(
        'Failed to find the project yaml of %s, return empty repository',
        project)
    return ''

  with open(project_yaml_path, 'r') as benchmark_file:
    data = yaml.safe_load(benchmark_file)
    return data.get('main_repo', '')


def get_project_cache_name(project: str) -> str:
  """Gets name of cached container for a project."""
  return f'gcr.io.oss-fuzz.{project}_cache'


def get_project_cache_image_name(project: str, sanitizer: str) -> str:
  """Gets name of cached Docker image for a project and a respective
  sanitizer."""
  return f'gcr.io/oss-fuzz/{project}_{sanitizer}_cache'
