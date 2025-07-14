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


class ContextAnalyzerAgentTest(BaseAgentTest):
  """Test for the ContextAnalyzer agent."""

  def setup_initial_result_list(self, benchmark, prompt):
    """Sets up the initial result list for the ContextAnalyzer agent test."""

    # Get necessary data from prompt
    fuzz_target_source = self._parse_tag(prompt, 'fuzz-target')
    function_requirement = self._parse_tag(prompt, 'function-requirements')
    stacktrace = self._parse_tag(prompt, 'crash-stacktrace')
    insight = self._parse_tag(prompt, 'crash-analysis')

    if function_requirement:
      # Save function requirements to file
      self.write_requirements_to_file(self.args, function_requirement)

    run_result = RunResult(benchmark=benchmark,
                         trial=self.trial,
                         work_dirs=self.args.work_dirs,
                         author=None,
                         chat_history={},
                         crashes=True,
                         fuzz_target_source=fuzz_target_source)

    crash_result = CrashResult(
        benchmark=benchmark,
        trial=self.trial,
        work_dirs=self.args.work_dirs,
        author=None,
        chat_history={},
        stacktrace=stacktrace,
        true_bug=True,
        insight=insight,
    )

    analysis_result = AnalysisResult(author=None,
                                   run_result=run_result,
                                   crash_result=crash_result,
                                   chat_history={})

    return [run_result, analysis_result]


