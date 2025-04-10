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
"""Manager for running auto-gen from scratch."""

import argparse
import logging
import os
import shutil
import subprocess
import sys
import threading
from typing import List

from experimental.build_generator import constants, templates

silent_global = False

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def setup_worker_project(oss_fuzz_base: str, project_name: str, llm_model: str):
  """Setup empty OSS-Fuzz project used for analysis."""
  temp_project_dir = os.path.join(oss_fuzz_base, "projects", project_name)
  if os.path.isdir(temp_project_dir):
    shutil.rmtree(temp_project_dir)

  os.makedirs(temp_project_dir)
  with open(os.path.join(temp_project_dir, 'project.yaml'), 'w') as f:
    f.write(templates.EMPTY_PROJECT_YAML)
  with open(os.path.join(temp_project_dir, 'build.sh'), 'w') as f:
    f.write(templates.EMPTY_OSS_FUZZ_BUILD)
  with open(os.path.join(temp_project_dir, 'Dockerfile'), 'w') as f:
    f.write(templates.AUTOGEN_DOCKER_FILE)

  if llm_model == 'vertex':
    json_config = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', None)
    if json_config is None:
      logger.info('vertex model is set but could not find configuration file.')
      logger.info('Plese set GOOGLE_APPLICATION_CREDENTIALS env variable.')
      sys.exit(1)
    shutil.copyfile(json_config, os.path.join(temp_project_dir, 'creds.json'))

  # Copy over the generator
  files_to_copy = {
      'build_script_generator.py', 'manager.py', 'templates.py', 'constants.py'
  }
  for target_file in files_to_copy:
    shutil.copyfile(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), target_file),
        os.path.join(temp_project_dir, target_file))

  # Build a version of the project
  if silent_global:
    subprocess.check_call(
        f'python3 infra/helper.py build_fuzzers {project_name}',
        shell=True,
        cwd=oss_fuzz_base,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
  else:
    subprocess.check_call(
        f'python3 infra/helper.py build_fuzzers {project_name}',
        shell=True,
        cwd=oss_fuzz_base)


def run_autogen(github_url,
                outdir,
                oss_fuzz_base,
                worker_project,
                model,
                openai_api_key=None,
                build_heuristics='all',
                max_successful_builds: int = -1,
                max_timeout: int = 0):
  """Launch auto-gen analysis within OSS-Fuzz container."""

  initiator_cmd = f'python3 /src/manager.py {github_url} -o {outdir}'
  initiator_cmd += f' --model={model}'
  if max_successful_builds > 0:
    initiator_cmd += f' --max-successful={max_successful_builds}'

  extra_environment = []
  if model == constants.MODEL_VERTEX:
    extra_environment.append('-e')
    extra_environment.append('GOOGLE_APPLICATION_CREDENTIALS=/src/creds.json')
  elif model == constants.MODEL_GPT_35_TURBO:
    extra_environment.append('-e')
    extra_environment.append(f'OPENAI_API_KEY={openai_api_key}')
  elif model == constants.MODEL_GPT_4:
    extra_environment.append('-e')
    extra_environment.append(f'OPENAI_API_KEY={openai_api_key}')

  cmd = [
      'docker',
      'run',
      '--rm',
      '-e',
      'FUZZING_ENGINE=libfuzzer',
      '-e',
      'SANITIZER=address',
      '-e',
      'ARCHITECTURE=x86_64',
      '-e',
      'HELPER=True',
      '-e',
      'FUZZING_LANGUAGE=c++',
      '-e',
      f'BUILD_HEURISTICS={build_heuristics}',
  ] + extra_environment

  if max_timeout:
    cmd = ['timeout', str(max_timeout)] + cmd

  cmd += [
      '-v',
      f'{oss_fuzz_base}/build/out/{worker_project}:/out',
      '-v',
      f'{oss_fuzz_base}/build/work/{worker_project}:/work',
      '-t',
      f'gcr.io/oss-fuzz/{worker_project}',
      # Command to run inside the container
      initiator_cmd
  ]

  cmd_to_run = ' '.join(cmd)
  try:
    if silent_global:
      subprocess.check_call(cmd_to_run,
                            cwd=oss_fuzz_base,
                            shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    else:
      subprocess.check_call(cmd_to_run, cwd=oss_fuzz_base, shell=True)
  except subprocess.CalledProcessError:
    pass


def read_targets_file(filename: str) -> List[str]:
  """Parse input file."""
  res_targets = []
  with open(filename, 'r') as f:
    targets = f.read().split("\n")
    for e in targets:
      if len(e) < 6:
        continue
      if e:
        res_targets.append(e)
  return res_targets


def run_on_targets(target,
                   oss_fuzz_base,
                   worker_project_name,
                   idx,
                   llm_model,
                   semaphore=None,
                   build_heuristics='all',
                   output='',
                   max_timeout: int = 0):
  """Thread entry point for single project auto-gen."""

  if semaphore is not None:
    semaphore.acquire()

  openai_api_key = os.getenv('OPENAI_API_KEY', None)

  outdir = os.path.join('/out/', constants.SHARED_MEMORY_RESULTS_DIR)
  with open('status-log.txt', 'a') as f:
    f.write(f'Targeting: {target} :: {idx}\n')
  run_autogen(target,
              outdir,
              oss_fuzz_base,
              worker_project_name,
              llm_model,
              openai_api_key=openai_api_key,
              build_heuristics=build_heuristics,
              max_timeout=max_timeout)

  # Cleanup the OSS-Fuzz docker image
  clean_up_cmd = [
      'docker', 'image', 'rm', f'gcr.io/oss-fuzz/{worker_project_name}'
  ]
  try:
    subprocess.check_call(' '.join(clean_up_cmd), shell=True)
  except subprocess.CalledProcessError:
    pass

  # Write to output directory
  copy_result_to_out(worker_project_name, oss_fuzz_base, output)

  if semaphore is not None:
    semaphore.release()


def get_next_worker_project(oss_fuzz_base: str) -> str:
  """Gets next OSS-Fuzz worker projecet."""
  max_idx = -1
  for project_dir in os.listdir(os.path.join(oss_fuzz_base, 'projects')):
    if not constants.PROJECT_BASE in project_dir:
      continue
    try:
      tmp_idx = int(project_dir.replace(constants.PROJECT_BASE, ''))
      max_idx = max(tmp_idx, max_idx)
    except:
      continue
  return f'{constants.PROJECT_BASE}{max_idx+1}'


def copy_result_to_out(project_generated, oss_fuzz_base, output) -> None:
  """Copy raw results into an output directory and in a refined format."""
  # Go through the output
  os.makedirs(output, exist_ok=True)
  raw_result_dir = os.path.join(output, 'raw-results')
  os.makedirs(raw_result_dir, exist_ok=True)

  project_directory = os.path.join(oss_fuzz_base, 'build', 'out',
                                   project_generated)
  if not os.path.isdir(project_directory):
    logger.info('Could not find project %s', project_directory)
    return
  shutil.copytree(project_directory,
                  os.path.join(raw_result_dir, project_generated))

  oss_fuzz_projects = os.path.join(output, 'oss-fuzz-projects')
  os.makedirs(oss_fuzz_projects, exist_ok=True)

  # get project name
  report_txt = os.path.join(raw_result_dir, project_generated,
                            'autogen-results', 'report.txt')
  if not os.path.isfile(report_txt):
    return
  project_name = ''
  with open(report_txt, 'r') as f:
    for line in f:
      if 'Analysing' in line:
        project_name = line.split('/')[-1].replace('\n', '')
  if not project_name:
    return

  idx = 0
  while True:
    base_build_dir = f'empty-build-{idx}'
    idx += 1

    build_dir = os.path.join(raw_result_dir, project_generated, base_build_dir)
    if not os.path.isdir(build_dir):
      break

    dst_project = f'{project_name}-{base_build_dir}'
    dst_dir = os.path.join(oss_fuzz_projects, dst_project)
    if os.path.isdir(dst_dir):
      logger.info('Destination dir alrady exists: %s. Skipping', dst_dir)
      continue
    shutil.copytree(build_dir, dst_dir)


def run_parallels(oss_fuzz_base,
                  target_repositories,
                  llm_model,
                  build_heuristics,
                  output,
                  parallel_jobs=6,
                  max_timeout=0):
  """Run auto-gen on a list of projects in parallel.

  Parallelisation is done by way of threads. Practically
  all of the computation will happen inside an OSS-Fuzz
  Docker container and not within this Python script as such."""
  semaphore = threading.Semaphore(parallel_jobs)
  jobs = []
  projects_generated = []
  for idx, target in enumerate(target_repositories):
    worker_project_name = get_next_worker_project(oss_fuzz_base)
    logger.info('Worker project name: %s', worker_project_name)
    projects_generated.append(worker_project_name)
    setup_worker_project(oss_fuzz_base, worker_project_name, llm_model)
    proc = threading.Thread(target=run_on_targets,
                            args=(target, oss_fuzz_base, worker_project_name,
                                  idx, llm_model, semaphore, build_heuristics,
                                  output, max_timeout))
    jobs.append(proc)
    proc.start()

  for proc in jobs:
    proc.join()


def parse_commandline():
  """Parse the commandline."""
  parser = argparse.ArgumentParser()
  parser.add_argument('--oss-fuzz', '-of', help='OSS-Fuzz base')
  parser.add_argument('--input', '-i', help='Input to analyze')
  parser.add_argument('--out',
                      '-o',
                      default='Generated builds',
                      help='Directory to store output.')
  parser.add_argument('--silent',
                      '-s',
                      help='Disable logging in subprocess.',
                      action='store_true')
  parser.add_argument('--build-heuristics',
                      '-b',
                      help='Comma-separated string of build heuristics to use',
                      default='all')
  parser.add_argument(
      '--model',
      '-m',
      help=f'LLM model to use. Available: {str(constants.MODELS)}',
      type=str)
  return parser.parse_args()


def setup_logging():
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)


def extract_target_repositories(target_input) -> list[str]:
  if os.path.isfile(target_input):
    target_repositories = read_targets_file(target_input)
  else:
    target_repositories = [target_input]
  logger.info(target_repositories)
  return target_repositories


def main():
  global silent_global

  args = parse_commandline()

  setup_logging()
  target_repositories = extract_target_repositories(args.input)
  silent_global = args.silent

  run_parallels(os.path.abspath(args.oss_fuzz), target_repositories, args.model,
                args.build_heuristics, args.out)


if __name__ == '__main__':
  main()
