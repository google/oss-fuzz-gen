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

from experimental.jvm import utils

silent_global = False

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def parse_commandline():
  """Parse the commandline."""
  parser = argparse.ArgumentParser()
  parser.add_argument('--workdir', '-w', help='Working directory')
  parser.add_argument('--oss-fuzz', '-o', help='OSS-Fuzz base')
  parser.add_argument(
      '--github-url',
      '-u',
      help='A comma separated string with all GitHub URLs of target projects')
  parser.add_argument('--silent',
                      '-s',
                      help='Disable logging in subprocess.',
                      action='store_true')
  return parser.parse_args()


def main():
  global silent_global

  args = parse_commandline()
  oss_fuzz_dir = os.path.abspath(args.oss_fuzz)
  work_dir = os.path.abspath(args.workdir)
  silent_global = args.silent
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)

  generated_project_name_list = []
  for url in args.github_url.split(','):
    # Retrieve project name
    project_name = utils.get_project_name(url)
    if not project_name:
      # Malformed url
      logger.warning('Skipping wrong github url: %s', url)
      continue

    # Clone project for static analysis
    base_dir = os.path.join(oss_fuzz_dir, 'projects', project_name)
    if os.path.isdir(base_dir):
      # Project already exists, reuse the existing project directly
      generated_project_name_list.append(os.path.basename(base_dir))
      continue

    project_dir = os.path.join(base_dir, 'proj')
    if not utils.git_clone_project(url, project_dir):
      # Clone error or invalid url
      logger.warning('Failed to clone from the github url: %s', url)
      shutil.rmtree(base_dir)
      continue

    # Prepare OSS-Fuzz base files
    if not utils.prepare_base_files(base_dir, project_name, url):
      # Invalid build type or non-Java project
      logger.warning('Build type of project %s is not supported.', project_name)
      shutil.rmtree(base_dir)
      continue

    # Clean up project and store generated project name
    generated_project_name_list.append(os.path.basename(base_dir))
    shutil.rmtree(project_dir)

  # Store generated project name
  if generated_project_name_list:
    with open(os.path.join(work_dir, 'project-name'), 'w') as file:
      file.write(','.join(generated_project_name_list))


if __name__ == '__main__':
  main()
