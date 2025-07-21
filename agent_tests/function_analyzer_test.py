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
from results import AnalysisResult, CrashResult, Result, RunResult


class FunctionAnalyzerAgentTest(BaseAgentTest):
  """Test for the FunctionAnalyzer agent."""

  def setup_initial_result_list(self, benchmark, prompt):
    """Sets up the initial result list for the FunctionAnalyzer agent test."""

    return [
      Result(benchmark=benchmark, trial=self.args.trial, work_dirs=self.args.work_dirs)
  ]
