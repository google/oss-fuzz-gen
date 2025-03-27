#!/usr/bin/env python3
# Copyright 2025 Google LLC
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
"""Create OSS-Fuzz projects from scratch."""

import argparse
import logging
import os
import sys
import shutil
import time
import subprocess
import requests

from experimental.build_generator import runner
from llm_toolkit import models

silent_global = False

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def setup_workdirs():
  """Sets up the working directory."""

  workdir = 'work'
  os.makedirs(workdir, exist_ok=True)

  # Clone two OSS-Fuzz projects
  subprocess.check_call(
      'git clone https://github.com/google/oss-fuzz oss-fuzz-1',
      shell=True,
      cwd=workdir)

  # Clone another OSS-Fuzz, for OFG core
  subprocess.check_call('git clone https://github.com/google/oss-fuzz oss-fuzz',
                        shell=True,
                        cwd=workdir)

  # Clone Fuzz Introspector
  subprocess.check_call('git clone https://github.com/ossf/fuzz-introspector',
                        shell=True,
                        cwd=workdir)

  # Ensure fuzz introspector's requirements.txt is installed
  subprocess.check_call('python3 -m pip install -r requirements.txt',
                        shell=True,
                        cwd=os.path.join(workdir, 'fuzz-introspector'))
  subprocess.check_call('python3 -m pip install -r requirements.txt',
                        shell=True,
                        cwd=os.path.join(workdir, 'fuzz-introspector', 'tools',
                                         'web-fuzzing-introspection'))
  return workdir


def extract_introspector_reports_for_benchmarks(projects_to_run, workdir):
  """Runs introspector through each report to collect program analysis data."""
  oss_fuzz_dir = os.path.join(workdir, 'oss-fuzz')
  runner_script = os.path.join(workdir, 'fuzz-introspector',
                               'oss_fuzz_integration', 'runner.py')
  for project in projects_to_run:
    cmd = ['python3']
    cmd.append(runner_script)  # introspector helper script
    cmd.append('introspector')  # force an introspector run
    cmd.append(project)  # target project
    cmd.append('1')  # run the harness for 1 second
    cmd.append('--disable-webserver')  # do not launch FI webapp
    subprocess.check_call(' '.join(cmd), shell=True, cwd=oss_fuzz_dir)


def shutdown_fi_webapp():
  """Shutsdown the FI webapp if it exists."""
  try:
    subprocess.check_call('curl --silent http://localhost:8080/api/shutdown',
                          shell=True)
  except subprocess.CalledProcessError:
    pass


def create_fi_db(workdir):
  """Creates the FI webapp database"""
  oss_fuzz_dir = os.path.join(workdir, 'oss-fuzz')

  fi_db_dir = os.path.join(workdir, 'fuzz-introspector', 'tools',
                           'web-fuzzing-introspection', 'app', 'static',
                           'assets', 'db')
  cmd = ['python3']
  cmd.append('web_db_creator_from_summary.py')
  cmd.append('--local-oss-fuzz')
  cmd.append(oss_fuzz_dir)
  try:
    logger.info('Creating fuzz introspector database')
    subprocess.check_call(' '.join(cmd), shell=True, cwd=fi_db_dir)
    logger.info('Created database successfully')
  except subprocess.CalledProcessError:
    logger.info('Failed creation of DB')
  return


def launch_fi_webapp(workdir):
  """Launches webapp so OFG can query projects."""
  logger.info('Launching webapp')
  oss_fuzz_dir = os.path.join(workdir, 'oss-fuzz')
  fi_webapp_dir = os.path.join(workdir, 'fuzz-introspector', 'tools',
                               'web-fuzzing-introspection', 'app')
  environ = os.environ.copy()
  environ['FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ'] = oss_fuzz_dir
  cmd = ['python3']
  cmd.append('main.py')
  cmd.append('>> /dev/null &')
  subprocess.check_call(' '.join(cmd),
                        shell=True,
                        cwd=fi_webapp_dir,
                        env=environ)

  return


def wait_until_fi_webapp_is_launched():
  """Return when the webapp has started"""
  logger.info('Waiting for the webapp to start')

  sec_to_wait = 10
  for _ in range(10):
    time.sleep(sec_to_wait)

    resp = requests.get('http://127.0.0.1:8080', timeout=10)
    if 'Fuzzing' in resp.text:
      return
  # If this is reached then the webapp likely didn't start.
  # Exit.
  logger.info('Could not start FI webapp')
  sys.exit(0)


def run_ofg_generation(model, projects_to_run, agent, workdir):
  """Runs harness generation"""
  logger.info('Running OFG experiment: %s', os.getcwd())
  oss_fuzz_dir = os.path.join(workdir, 'oss-fuzz')
  cmd = ['python3', 'run_all_experiments.py']
  cmd.append('--model')
  cmd.append(model)
  cmd.append('-g')
  cmd.append(
      'far-reach-low-coverage,low-cov-with-fuzz-keyword,easy-params-far-reach')
  cmd.append('-gp')
  cmd.append(','.join(projects_to_run))
  cmd.append('-gm')
  cmd.append('4')
  cmd.append('-of')
  cmd.append(oss_fuzz_dir)
  cmd.append('-e')
  cmd.append('http://127.0.0.1:8080/api')
  if agent:
    cmd.append('--agent')

  environ = os.environ.copy()

  environ['LLM_NUM_EVA'] = '4'
  environ['LLM_NUM_EXP'] = '4'
  environ['OFG_CLEAN_UP_OSS_FUZZ'] = '0'

  subprocess.check_call(' '.join(cmd), shell=True, env=environ)


def copy_generated_projects_to_harness_gen(out_gen):
  """Copies projects from build generation ready for harness generation."""
  projects_dir = os.path.join(out_gen, 'oss-fuzz-projects')
  if not os.path.isdir(projects_dir):
    logger.info('Found no projects.')
    return

  # Copy projects over
  projects_to_run = []
  for project in os.listdir(projects_dir):
    dst = os.path.join('work', 'oss-fuzz', 'projects', project)
    if os.path.isdir(dst):
      shutil.rmtree(dst)
    logger.info('Copying: %s :: %s', os.path.join(projects_dir, project),
                os.path.join('work', 'oss-fuzz', 'projects', project))
    shutil.copytree(os.path.join(projects_dir, project),
                    os.path.join('work', 'oss-fuzz', 'projects', project))
    projects_to_run.append(project)
  return projects_to_run


def run_harness_generation(out_gen, model, agent, workdir):
  """Runs harness generation based on the projects in `out_gen`"""

  abs_workdir = os.path.abspath(workdir)
  projects_to_run = copy_generated_projects_to_harness_gen(out_gen)
  extract_introspector_reports_for_benchmarks(projects_to_run, abs_workdir)
  shutdown_fi_webapp()
  create_fi_db(abs_workdir)
  shutdown_fi_webapp()
  launch_fi_webapp(abs_workdir)
  wait_until_fi_webapp_is_launched()
  run_ofg_generation(model, projects_to_run, agent, abs_workdir)


def setup_logging():
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)


def run_analysis(input_file, out, model, agent):
  workdir = setup_workdirs()

  oss_fuzz_dir = os.path.join('work', 'oss-fuzz-1')
  target_repositories = runner.extract_target_repositories(input_file)
  runner.run_parallels(os.path.abspath(oss_fuzz_dir), target_repositories,
                       model, 'all', out)

  run_harness_generation(out, model, agent, workdir)


def parse_commandline():
  """Parse the commandline."""
  parser = argparse.ArgumentParser()
  # parser.add_argument('--oss-fuzz', '-of', help='OSS-Fuzz base')
  parser.add_argument('--input', '-i', help='Input to analyze')
  parser.add_argument('--out',
                      '-o',
                      default='Generated builds',
                      help='Directory to store output.')
  parser.add_argument('--silent',
                      '-s',
                      help='Disable logging in subprocess.',
                      action='store_true')
  parser.add_argument('--model',
                      '-m',
                      help=('Models available: '
                            f'{", ".join(models.LLM.all_llm_names())}.'),
                      type=str)
  parser.add_argument('--agent',
                      '-a',
                      help='Enable agent workflow',
                      action='store_true')
  return parser.parse_args()


def main():
  global silent_global
  args = parse_commandline()
  setup_logging()
  silent_global = args.silent
  run_analysis(args.input, args.out, args.model, args.agent)


if __name__ == '__main__':
  main()
