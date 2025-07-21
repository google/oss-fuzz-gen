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

import os
import re

from agent_tests.base_agent_test import BaseAgentTest
from results import AnalysisResult, CrashResult, RunResult


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

    raise ValueError("Artifact path not found in the prompt: {}".format(prompt))

  def get_fuzz_target_and_build_script_paths(
      self, additional_files_path: str) -> tuple[str, str]:
    """Gets the file paths ending with .fuzz_target and .build_script from additional files path.

    Args:
        additional_files_path: Directory path containing the files

    Returns:
        tuple: (fuzz_target_path, build_script_path)

    Raises:
        FileNotFoundError: If fuzz_target file is not found
        ValueError: If multiple files with same extension are found
    """
    if not os.path.exists(additional_files_path):
      raise FileNotFoundError(
          f"Additional files path does not exist: {additional_files_path}")

    fuzz_target_files = []
    build_script_files = []

    # Walk through the directory to find files with specified extensions
    for root, dirs, files in os.walk(additional_files_path):
      for file in files:
        file_path = os.path.join(root, file)
        if file.endswith('.fuzz_target'):
          fuzz_target_files.append(file_path)
        elif file.endswith('.build_script'):
          build_script_files.append(file_path)

    # Check for fuzz_target file
    if not fuzz_target_files:
      raise FileNotFoundError(
          f"No .fuzz_target file found in {additional_files_path}")
    elif len(fuzz_target_files) > 1:
      raise ValueError(
          f"Multiple .fuzz_target files found: {fuzz_target_files}")

    fuzz_target_path = fuzz_target_files[0]

    # Build script is optional, so we don't raise error if not found
    build_script_path = build_script_files[0] if build_script_files else ''

    if len(build_script_files) > 1:
      raise ValueError(
          f"Multiple .build_script files found: {build_script_files}")

    return fuzz_target_path, build_script_path

  def setup_initial_result_list(self, benchmark, prompt):
    """Sets up the initial result list for the CrashAnalyzer agent test."""

    # Extract the fuzz target and build script from the self.args.additional_files_path
    if not self.args.additional_files_path:
      raise ValueError("Additional files path is not provided.")

    # Get the file ending with .fuzz_target and .build_script from
    fuzz_target_path, build_script_path = self.get_fuzz_target_and_build_script_paths(
        self.args.additional_files_path)

    with open(fuzz_target_path, 'r') as file:
      fuzz_target_source = file.read()
    if os.path.exists(build_script_path) and os.path.getsize(
        build_script_path) > 0:
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
