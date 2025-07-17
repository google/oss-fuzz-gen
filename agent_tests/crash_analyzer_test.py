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

from agent_tests.base_agent_test import BaseAgentTest
from results import AnalysisResult, CrashResult, RunResult
import re
import os


class CrashAnalyzerAgentTest(BaseAgentTest):
  """Test for the CrashAnalyzer agent."""

  def get_artifact_path(self, prompt: str) -> str:
    """Extracts the artifact path from the prompt."""
    pattern = r"The testcase that triggers runtime crash is stored at '([^']+)'"
    match = re.search(pattern, prompt)
    if match:
        artifact_path = match.group(1)
        # Extract the filename from the path
        filename = artifact_path.split('/')[-1]
        # Create the relative path
        relative_path = f"agent_tests/artifacts/{filename}"
        # Check if the file exists
        if os.path.exists(relative_path):
            return os.path.abspath(relative_path)

    raise ValueError(
        "Artifact path not found in the prompt: {}".format(prompt))

  def setup_initial_result_list(self, benchmark, prompt):
    """Sets up the initial result list for the CrashAnalyzer agent test."""

    fuzz_target_path = 'agent_tests/run_result_files/Result-reports_ofg-pr_2025-07-11-1144-pamusuo-analyzer-tests-1_results_output-libsndfile-sf_open_fuzz_targets_01.fuzz_target'
    build_script_path = 'agent_tests/run_result_files/Result-reports_ofg-pr_2025-07-11-1144-pamusuo-analyzer-tests-1_results_output-libsndfile-sf_open_fuzz_targets_01.build_script'

    if not os.path.exists(fuzz_target_path) or os.path.getsize(fuzz_target_path) == 0:
      raise FileNotFoundError(f"Fuzz target file not found: {fuzz_target_path}")
    with open(fuzz_target_path, 'r') as file:
      fuzz_target_source = file.read()
    if os.path.exists(build_script_path) and os.path.getsize(build_script_path) > 0:
      with open(build_script_path, 'r') as file:
          build_script_source = file.read()
    else:
      build_script_source = ''
    num_lines = fuzz_target_source.count('\n') + 1
    run_error = self._parse_tag(prompt, 'log')
    crash_func = {'LLVMFuzzerTestOneInput': set([num_lines])}

    artifact_path = self.get_artifact_path(prompt)

    run_result = RunResult(benchmark=benchmark,
                           trial=self.trial,
                           work_dirs=self.args.work_dirs,
                           author=None,
                           chat_history={},
                           crashes=True,
                           fuzz_target_source=fuzz_target_source,
                           build_script_source=build_script_source,
                           run_error=run_error,
                           crash_func=crash_func,
                           artifact_path=artifact_path)

    return [run_result]