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
"""A dedicated parser to parse the run log and extract
information such as the crash details, crash symptoms,
stack traces, etc. to be rendered in the report."""

import re
from experiment import oss_fuzz_checkout

def extract_project_from_coverage_path(file_path: str) -> str:
  """Extract the project name from coverage file paths."""
  if file_path.startswith('/src/'):
    path_parts = file_path.removeprefix('/src/').split('/')
    if path_parts:
      return path_parts[0]
  return ""

def get_source_url(coverage_file_path: str) -> str:
  """Get the GitHub source URL for the given coverage file path."""
  code_line_number = ""
  if ":" in coverage_file_path:
    parts = coverage_file_path.split(":")
    if len(parts) < 2:
      return ""
    coverage_file_path = parts[0]
    code_line_number = parts[1]

  project_name = extract_project_from_coverage_path(coverage_file_path)
  if not project_name:
    # Hardcoding llvm-project paths due to OSS Fuzz not being able to find its project YAML
    # However, the path to the GitHub repo is still correct, so we can use it
    if "llvm-project" in coverage_file_path:
      project_name = "llvm-project"
    else:
      return "" 

  repo_url = oss_fuzz_checkout.get_project_repository(project_name)
  if not repo_url:
    if "llvm-project" in coverage_file_path:
      repo_url = "https://github.com/llvm/llvm-project"
    else:
      return ""
  
  relative_path = coverage_file_path.removeprefix(f'/src/{project_name}/')

  if repo_url.endswith('.git'):
    repo_url = repo_url[:-4]
  
  if code_line_number:
    return f"{repo_url}/blob/master/{relative_path}#L{code_line_number}"
  return f"{repo_url}/blob/master/{relative_path}"

class RunLogsParser:
  """Parse the run log."""

  def __init__(self, run_logs: str):
    self._run_logs = run_logs
    self._lines = run_logs.split('\n')

  def get_crash_details(self) -> str:
    """Get the raw crash details for the given sample."""
    crash_details = ""
    start_idx = 0
    end_idx = len(self._lines) - 1

    for idx, line in enumerate(self._lines):
      if "==========" in line:
        start_idx = idx
      if 0 < start_idx < idx and "artifact_prefix" in line:
        end_idx = idx

    # If we found a start index, then we can get the crash details
    # Otherwise, return an empty string (for rendering purposes,
    # because then this will just be the entire run log)
    if start_idx > 0:
      crash_details = '\n'.join(self._lines[start_idx:end_idx + 1])

    return crash_details

  def get_crash_symptom(self) -> str:
    """Get the crash symptom from the run log."""
    crash_symptom = ""

    pattern = re.compile(r"(?:^\s*\x1b\[[0-9;]*m)*==\d+==\s*(ERROR:.*)",
                         re.DOTALL)

    for line in self._lines:
      match = pattern.search(line)
      if match:
        crash_symptom = match.group(1)
        break

    return crash_symptom
  
  def get_formatted_stack_traces(self) -> dict[str, dict[str, str]]:
    """Get the formatted stack traces from the run log."""
    pattern = re.compile(r'^ {4}#\d+\s+.*$')
    stack_traces = {}

    for line in self._lines:
      match = pattern.search(line)
      if match:
        parts = line.strip().split(' ', 2)
        if len(parts) < 3:
          continue
        
        frame_num = parts[0]
        memory_addr = parts[1]
        remaining = parts[2]
        
        in_match = re.search(r'in (.+?) (/[^\s]+)', remaining)
        if not in_match:
          continue
          
        function_name = in_match.group(1)
        path = in_match.group(2)
        if '/src/' in path:
          url = get_source_url(path)
          if url == '':
            url = path
          stack_traces[frame_num] = {"url": url, "path": path, "function": function_name, "memory_address": memory_addr}

    return stack_traces
