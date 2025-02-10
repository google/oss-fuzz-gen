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
A class to represent the experiment working directory.
"""

import os
import re
from shutil import rmtree
from typing import Optional


class WorkDirs:
  """Working directories."""

  RUN_LOG_NAME_PATTERN = re.compile(r'.*-F(\d+).log')

  def __init__(self, base_dir, keep: bool = False):
    self._base_dir = os.path.realpath(base_dir)
    if os.path.exists(self._base_dir) and not keep:
      # Clear existing directory.
      rmtree(self._base_dir, ignore_errors=True)

    os.makedirs(self._base_dir, exist_ok=True)
    os.makedirs(self.status, exist_ok=True)
    os.makedirs(self.raw_targets, exist_ok=True)
    os.makedirs(self.fixed_targets, exist_ok=True)
    os.makedirs(self.build_logs, exist_ok=True)
    os.makedirs(self.run_logs, exist_ok=True)
    os.makedirs(self._corpus_base, exist_ok=True)
    os.makedirs(self.dills, exist_ok=True)
    os.makedirs(self.fuzz_targets, exist_ok=True)

  @property
  def base(self):
    return self._base_dir

  @property
  def _corpus_base(self):
    return os.path.join(self._base_dir, 'corpora')

  def corpus(self, sample_id):
    corpus_dir = os.path.join(self._corpus_base, str(sample_id))
    os.makedirs(corpus_dir, exist_ok=True)
    return corpus_dir

  def code_coverage_report(self, benchmark):
    coverage_dir = os.path.join(self._base_dir, 'code-coverage-reports')
    os.makedirs(coverage_dir, exist_ok=True)

    benchmark_coverage = os.path.join(coverage_dir, benchmark)
    return benchmark_coverage

  @property
  def status(self):
    return os.path.join(self._base_dir, 'status')

  @property
  def prompt(self):
    return os.path.join(self._base_dir, 'prompt.txt')

  @property
  def fuzz_targets(self):
    return os.path.join(self._base_dir, 'fuzz_targets')

  # TODO(dongge): Deprecate this.
  @property
  def raw_targets(self):
    return os.path.join(self._base_dir, 'raw_targets')

  # TODO(dongge): Deprecate this.
  @property
  def fixed_targets(self):
    return os.path.join(self._base_dir, 'fixed_targets')

  @property
  def build_logs(self):
    return os.path.join(self._base_dir, 'logs', 'build')

  @property
  def dills(self):
    return os.path.join(self._base_dir, 'dills')

  @property
  def run_logs(self):
    return os.path.join(self._base_dir, 'logs', 'run')

  def build_logs_target(self, generated_target_name: str, iteration: int):
    return os.path.join(self.build_logs,
                        f'{generated_target_name}-F{iteration}.log')

  def error_logs_target(self, generated_target_name: str,
                        iteration: int) -> str:
    return os.path.join(self.build_logs,
                        f'{generated_target_name}-F{iteration}.err.log')

  def run_logs_target(self, generated_target_name: str, iteration: int):
    return os.path.join(self.run_logs,
                        f'{generated_target_name}-F{iteration}.log')

  @classmethod
  def get_run_log_iteration(cls, filename: str) -> Optional[int]:
    match = cls.RUN_LOG_NAME_PATTERN.match(filename)
    if match:
      return int(match.group(1))
    return None
