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

import git
from openai import OpenAIError

from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from experimental.build_generator import (constants, file_utils, llm_agent,
                                          templates)
from llm_toolkit import models
from results import Result

silent_global = False

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def setup_worker_project(oss_fuzz_base: str,
                         project_name: str,
                         llm_model: str,
                         github_url: str = '',
                         from_agent: bool = False,
                         workdir: str = '') -> str:
  """Setup empty OSS-Fuzz project used for analysis."""
  language = ''

  temp_project_dir = os.path.join(oss_fuzz_base, "projects", project_name)
  if os.path.isdir(temp_project_dir):
    shutil.rmtree(temp_project_dir)

  os.makedirs(temp_project_dir)
  with open(os.path.join(temp_project_dir, 'project.yaml'), 'w') as f:
    f.write(templates.EMPTY_PROJECT_YAML)
  with open(os.path.join(temp_project_dir, 'build.sh'), 'w') as f:
    f.write(templates.EMPTY_OSS_FUZZ_BUILD)
  with open(os.path.join(temp_project_dir, 'Dockerfile'), 'w') as f:
    if from_agent:
      file_content = templates.CLEAN_OSS_FUZZ_DOCKER
      file_content = file_content.replace('{additional_packages}', '')
      file_content = file_content.replace('{repo_url}', github_url)
      file_content = file_content.replace('{project_repo_dir}',
                                          github_url.split('/')[-1])
    else:
      file_content = templates.AUTOGEN_DOCKER_FILE

    f.write(file_content)

  # Prepare demo fuzzing harness source
  if from_agent:
    repo_path = os.path.join(workdir, 'temp_repo')
    git.Repo.clone_from(github_url, repo_path)
    try:
      language = file_utils.determine_project_language(repo_path)
      _, _, name, code = file_utils.get_language_defaults(language)
      with open(os.path.join(temp_project_dir, name.split('/')[-1]), 'w') as f:
        f.write(code)
    finally:
      if os.path.exists(repo_path) and os.path.isdir(repo_path):
        shutil.rmtree(repo_path)

  if llm_model == 'vertex':
    json_config = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', None)
    if json_config is None:
      logger.info('vertex model is set but could not find configuration file.')
      logger.info('Plese set GOOGLE_APPLICATION_CREDENTIALS env variable.')
      sys.exit(1)
    shutil.copyfile(json_config, os.path.join(temp_project_dir, 'creds.json'))

  # Copy over the generator (only for general approach
  if not from_agent:
    files_to_copy = {
        'build_script_generator.py', 'manager.py', 'templates.py', 'constants.py',
        'file_utils.py'
    }
    for target_file in files_to_copy:
      shutil.copyfile(
          os.path.join(os.path.dirname(os.path.abspath(__file__)), target_file),
          os.path.join(temp_project_dir,
                       target_file.split('/')[-1]))

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

  return language


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
  elif openai_api_key:
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


def copy_result_to_out(project_generated,
                       oss_fuzz_base,
                       output,
                       from_agent=False,
                       project_name='') -> None:
  """Copy raw results into an output directory and in a refined format."""
  # Go through the output
  os.makedirs(output, exist_ok=True)
  raw_result_dir = os.path.join(output, 'raw-results')
  os.makedirs(raw_result_dir, exist_ok=True)

  if from_agent:
    project_directory = os.path.join(oss_fuzz_base, 'projects',
                                     project_generated)
  else:
    project_directory = os.path.join(oss_fuzz_base, 'build', 'out',
                                     project_generated)

  if not os.path.isdir(project_directory):
    logger.info('Could not find project %s', project_directory)
    return
  shutil.copytree(project_directory,
                  os.path.join(raw_result_dir, project_generated),
                  dirs_exist_ok=True)

  oss_fuzz_projects = os.path.join(output, 'oss-fuzz-projects')
  os.makedirs(oss_fuzz_projects, exist_ok=True)

  if from_agent:
    build_dir = os.path.join(raw_result_dir, project_generated)
    if not os.path.isdir(build_dir):
      return

    dst_project = f'{project_name}-agent'
    dst_dir = os.path.join(oss_fuzz_projects, dst_project)
    shutil.copytree(build_dir, dst_dir, dirs_exist_ok=True)
  else:
    report_txt = os.path.join(raw_result_dir, project_generated,
                              'autogen-results', 'report.txt')
    if not os.path.isfile(report_txt):
      return

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

      build_dir = os.path.join(raw_result_dir, project_generated,
                               base_build_dir)
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


def run_agent(target_repositories: List[str], args: argparse.Namespace):
  """Generates build script and fuzzer harnesses for a GitHub repository using
  llm agent approach."""
  # Process default arguments
  oss_fuzz_base = os.path.abspath(args.oss_fuzz)
  work_dirs = WorkDirs(args.work_dirs, keep=True)

  # Prepare environment
  worker_project_name = get_next_worker_project(oss_fuzz_base)

  # Prepare LLM model
  llm = models.LLM.setup(
      ai_binary=os.getenv('AI_BINARY', ''),
      name=args.model,
      max_tokens=4096,
      num_samples=1,
      temperature=0.4,
      temperature_list=[],
  )

  # All agents
  llm_agents = [llm_agent.BuildSystemBuildScriptAgent]

  for target_repository in target_repositories:
    logger.info('Target repository: %s', target_repository)
    language = setup_worker_project(oss_fuzz_base, worker_project_name,
                                    args.model, target_repository, True,
                                    os.path.abspath(args.work_dirs))
    benchmark = Benchmark(worker_project_name, worker_project_name, '', '', '',
                          '', [], '')

    for llm_agent_ctr in llm_agents:
      build_script = ''
      harness = ''
      build_success = False
      for trial in range(args.max_round):
        logger.info('Agent: %s. Round %d', llm_agent_ctr.__name__, trial)
        agent = llm_agent_ctr(trial=trial,
                              llm=llm,
                              args=args,
                              github_url=target_repository,
                              language=language)
        result_history = [
            Result(benchmark=benchmark, trial=trial, work_dirs=work_dirs)
        ]

        try:
          build_result = agent.execute(result_history)
        except OpenAIError:
          logger.info(('Round %d build script generation failed for project %s'
                       ' with openai errors'), trial, target_repository)
          break

        if build_result.compiles:
          build_success = True
          build_script = build_result.build_script_source
          harness = build_result.fuzz_target_source
          break

        logger.info('Round %d build script generation failed for project %s',
                    trial, target_repository)

      if build_success:
        logger.info('Build script generation success for project %s',
                    target_repository)

        # Update build script
        build_script_path = os.path.join(oss_fuzz_base, 'projects',
                                         worker_project_name, 'build.sh')
        with open(build_script_path, 'w') as f:
          f.write(build_script)

        # Update harness code
        _, _, harness_name, default_code = file_utils.get_language_defaults(
            language)
        if not harness:
          harness = default_code

        harness_path = os.path.join(oss_fuzz_base, 'projects',
                                    worker_project_name,
                                    harness_name.split('/')[-1])
        with open(harness_path, 'w') as f:
          f.write(harness)

        # Copy result to out
        copy_result_to_out(worker_project_name, oss_fuzz_base, args.out, True,
                           target_repository.split('/')[-1])
        break

  # Clean up workdir
  if os.path.isdir(args.work_dirs):
    shutil.rmtree(args.work_dirs)


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
  parser.add_argument('--agent',
                      '-a',
                      help='Use LLM Agent Builder or not.',
                      action='store_true')
  parser.add_argument('--max-round',
                      '-mr',
                      help='Max round of trial for the llm build script agent.',
                      type=int,
                      default=10)
  parser.add_argument('--work-dirs',
                      '-w',
                      help='Working directory path.',
                      type=str,
                      default='./work_dirs')

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

  if args.agent:
    run_agent(target_repositories, args)
  else:
    run_parallels(os.path.abspath(args.oss_fuzz), target_repositories,
                  args.model, args.build_heuristics, args.out)


if __name__ == '__main__':
  main()
