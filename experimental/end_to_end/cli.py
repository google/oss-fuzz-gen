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
import shutil
import subprocess

from experimental.build_generator import runner
from llm_toolkit import models

silent_global = False

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def run_harness_generation(out_gen, model, agent):
  """Runs harness generation based on the projects in `out_gen`"""

  projects_dir = os.path.join(out_gen, 'oss-fuzz-projects')
  if not os.path.isdir(projects_dir):
    logger.info('Found no projects.')
    return

  # Set up if needed
  if not os.path.isdir('work'):
    subprocess.check_call('./scripts/run-new-oss-fuzz-project/setup.sh',
                          shell=True)

  # Copy projects over
  projects_to_run = []
  for project in os.listdir(projects_dir):
    dst = os.path.join('work', 'oss-fuzz', 'projects', project)
    if os.path.isdir(dst):
      shutil.rmtree(dst)
    shutil.copytree(os.path.join(projects_dir, project),
                    os.path.join('work', 'oss-fuzz', 'projects', project))
    projects_to_run.append(project)

  # Run project generation
  project_string = ' '.join(projects_to_run)
  environ = os.environ
  environ['MODEL'] = model
  if agent:
    environ['EXTRA_OFG_ARGS'] = '--agent'
  subprocess.check_call(
      f'./scripts/run-new-oss-fuzz-project/run-project.sh {project_string}',
      shell=True)


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


def setup_logging():
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)


def run_analysis(oss_fuzz_dir, input_file, out, model, agent):
  target_repositories = runner.extract_target_repositories(input_file)
  runner.run_parallels(os.path.abspath(oss_fuzz_dir), target_repositories,
                       model, 'all', out)

  run_harness_generation(out, model, agent)


def main():
  global silent_global
  args = parse_commandline()
  setup_logging()
  silent_global = args.silent
  run_analysis(args.oss_fuzz, args.input, args.out, args.model, args.agent)


if __name__ == '__main__':
  main()
