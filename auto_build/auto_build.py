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
"""Provides set of functions for processing new OSS-Fuzz integration."""

import logging
import os
import shutil

from auto_build import utils
from experiment import benchmark as benchmarklib
from experiment import oss_fuzz_checkout

logger = logging.getLogger(__name__)

def generate_benchmarks_from_github_url(benchmark_dir: str, url: str) -> None:
  """This function generate benchmark yaml for the given project url."""

  project_name = utils.get_project_name(url)
  if not project_name:
    # Invalid url
    logger.warning(f'Skipping wrong github url: {url}')
    return

  # Clone project for static analysis
  base_dir = utils.get_next_project_dir(oss_fuzz_checkout.OSS_FUZZ_DIR)
  project_dir = os.path.join(base_dir, 'proj')
  if not utils.git_clone_project(url, project_dir):
    # Invalid url
    logger.warning(f'Failed to clone from the github url: {url}')
    shutil.rmtree(base_dir)
    return

  # Prepare OSS-Fuzz base files
  if not utils.prepare_base_files(base_dir, project_name, url):
    # Invalid build type or non-Java project
    logger.warning(f'Build type of project {project_name} is not supported.')
    shutil.rmtree(base_dir)
    return

  # Run OSS-Fuzz build and static analysis on the project
  data_yaml_path = utils.run_oss_fuzz_build(os.path.basename(base_dir),
                                            oss_fuzz_checkout.OSS_FUZZ_DIR)
  if not data_yaml_path:
    # Failed to build or run static analysis on the project
    logger.warning(f'Failed to build project {project_name} with JDK15.')
    shutil.rmtree(base_dir)
    return

  # Save data.yaml from static analysis as benchmark files
  benchmarks = benchmarklib.Benchmark.from_java_data_yaml(
      data_yaml_path, project_name, project_dir)
  if benchmarks:
    benchmarklib.Benchmark.to_yaml(benchmarks, benchmark_dir)

  # Clean up the working directory for generating benchmark from scratch
  shutil.rmtree(base_dir)

