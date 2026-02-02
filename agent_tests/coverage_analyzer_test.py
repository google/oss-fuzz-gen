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
"""Class for executing CoverageAnalyzer agent directly."""

import os

from agent_tests.base_agent_test import BaseAgentTest
from results import CoverageResult, RunResult


class CoverageAnalyzerAgentTest(BaseAgentTest):
  """Test for the CoverageAnalyzer agent."""

  def setup_initial_result_list(self, benchmark, prompt):
    """Sets up the initial result list for the CoverageAnalyzer agent test."""

    # Get necessary data from prompt
    fuzz_target_source = self._parse_tag(prompt, 'fuzz target')
    fuzzing_log = self._parse_tag(prompt, 'fuzzing log')
    function_requirements = self._parse_tag(prompt, 'function-requirements')

    if function_requirements:
      # Save to requirements file
      self.write_requirements_to_file(self.args, function_requirements)

    # Walk through the directory to find coverage report files
    covreports = []
    for root, dirs, files in os.walk(self.args.additional_files_path):
      for file in files:
        file_path = os.path.join(root, file)
        if file.endswith('.covreport'):
          covreports.append(file_path)

    if covreports:
      textcov_dir = os.path.join(
          self.args.work_dirs.code_coverage_report(
              f'{self.trial:02d}.fuzz-target'), 'textcov')

      os.makedirs(textcov_dir, exist_ok=True)
      dst_file_path = os.path.join(textcov_dir, os.path.basename(covreports[0]))

      with open(covreports[0], 'rb') as file:
        with open(dst_file_path, 'wb') as dst_file:
          dst_file.write(file.read())

    run_result = RunResult(benchmark=benchmark,
                           trial=self.trial,
                           work_dirs=self.args.work_dirs,
                           author=None,
                           chat_history={},
                           crashes=False,
                           fuzz_target_source=fuzz_target_source,
                           run_log=fuzzing_log)

    return [run_result]
