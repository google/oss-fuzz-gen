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

from report.common import LogPart


def extract_project_from_coverage_path(file_path: str) -> str:
  """Extract the project name from coverage file paths."""
  if file_path.startswith('/src/'):
    path_parts = file_path.removeprefix('/src/').split('/')
    if path_parts:
      return path_parts[0]
  return ""


class LogsParser:
  """Parse the logs"""

  def __init__(self, logs: list[LogPart]):
    self._logs = logs

  def _parse_steps_from_logs(self, agent_logs: list[LogPart]) -> list[dict]:
    """Parse steps from agent logs, grouping by step number."""
    step_pattern = re.compile(r"Step #(\d+) - \"(.+?)\":")
    simple_step_pattern = re.compile(r"Step #(\d+)")

    steps_dict = {}
    current_step_number = None
    current_step_name = None

    for log_part in agent_logs:
      content = log_part.content.strip()
      if not content:
        continue

      lines = content.split('\n')

      step_header_found = False
      for line in lines:
        step_match = step_pattern.search(line)
        if not step_match:
          simple_match = simple_step_pattern.search(line)
          if simple_match:
            step_match = simple_match

        if step_match:
          step_header_found = True
          current_step_number = step_match.group(1)
          if len(step_match.groups()) > 1:
            current_step_name = step_match.group(2).strip()
          else:
            current_step_name = "agent-step"

          if current_step_number not in steps_dict:
            steps_dict[current_step_number] = {
                'number': current_step_number,
                'name': current_step_name,
                'type': 'Step',
                'log_parts': []
            }
          break

      if not step_header_found and current_step_number:
        steps_dict[current_step_number]['log_parts'].append(log_part)
      elif not step_header_found and not current_step_number and not steps_dict:
        steps_dict['0'] = {
            'number': None,
            'name': None,
            'type': 'Content',
            'log_parts': [log_part]
        }

    steps = []
    for step_num in sorted(steps_dict.keys(),
                           key=lambda x: int(x) if x.isdigit() else 999):
      steps.append(steps_dict[step_num])

    return steps

  def get_agent_sections(self) -> dict[str, list[LogPart]]:
    """Get the agent sections from the logs."""

    pattern = re.compile(r"\*{24}(.+?)\*{24}")
    agent_sections = {}
    current_agent = None
    agent_counters = {}

    for log_part in self._logs:
      lines = log_part.content.split('\n')
      agent_headers = []

      for i, line in enumerate(lines):
        match = re.search(pattern, line)
        if match:
          agent_name = match.group(1)
          # Handle repeated agents by creating unique keys
          if agent_name in agent_counters:
            agent_counters[agent_name] += 1
            unique_agent_name = f"{agent_name} ({agent_counters[agent_name]})"
          else:
            agent_counters[agent_name] = 1
            unique_agent_name = agent_name

          agent_headers.append((i, unique_agent_name))
          agent_sections[unique_agent_name] = []
          current_agent = unique_agent_name

      # If this LogPart has agent headers, split it up
      if agent_headers:
        for j, (line_idx, agent_name) in enumerate(agent_headers):
          next_line_idx = agent_headers[j + 1][0] if j + 1 < len(
              agent_headers) else len(lines)

          agent_content_lines = lines[line_idx + 1:next_line_idx]
          if agent_content_lines:
            content = '\n'.join(agent_content_lines)
            if content.strip():
              new_log_part = LogPart(content=content,
                                     chat_prompt=log_part.chat_prompt,
                                     chat_response=log_part.chat_response)
              agent_sections[agent_name].append(new_log_part)
      else:
        # This LogPart doesn't have agent headers, add it to current agent
        if current_agent and current_agent in agent_sections:
          agent_sections[current_agent].append(log_part)

    return agent_sections

  def get_agent_cycles(self) -> list[dict]:
    """Group agent sections into cycles based on cycle numbers."""
    agent_sections = self.get_agent_sections()

    cycles_dict = {}

    for agent_name, agent_logs in agent_sections.items():
      # Parse steps for this agent
      steps = self._parse_steps_from_logs(agent_logs)

      cycle_match = re.search(r'\(Cycle (\d+)\)', agent_name)
      if cycle_match:
        cycle_number = int(cycle_match.group(1))
        if cycle_number not in cycles_dict:
          cycles_dict[cycle_number] = {}
        cycles_dict[cycle_number][agent_name] = {
            'logs': agent_logs,
            'steps': steps
        }
      else:
        if 0 not in cycles_dict:
          cycles_dict[0] = {}
        cycles_dict[0][agent_name] = {'logs': agent_logs, 'steps': steps}

    return [cycles_dict[cycle] for cycle in sorted(cycles_dict.keys())]


class RunLogsParser:
  """Parse the run log."""

  def __init__(self,
               run_logs: str,
               benchmark_id: str,
               sample_id: str,
               coverage_report_path: str = ""):
    self._run_logs = run_logs
    self._lines = run_logs.split('\n')
    self._benchmark_id = benchmark_id
    self._sample_id = sample_id
    self._coverage_report_path = coverage_report_path

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

  def get_formatted_stack_traces(self,
                                 base_url: str) -> dict[str, dict[str, str]]:
    """Get the formatted stack traces from the run log."""
    pattern = re.compile(r'^ {4}#\d+\s+.*$')
    stack_traces = {}
    base_url = base_url.rstrip('/')

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
        if '/src/' in path and 'llvm-project' not in path:
          if self._benchmark_id and self._sample_id:
            path_parts = path.split(':')
            file_path = path_parts[0]
            line_number = path_parts[1] if len(path_parts) > 1 else None

            relative_path = file_path.lstrip('/')

            # If coverage_report_path is set, it's a local run
            # Otherwise it's cloud
            if self._coverage_report_path:
              url = f'{self._coverage_report_path}{relative_path}.html'
              url_line_number = f'{url}#L{line_number}' if line_number else url
            else:
              url = (f'{base_url}/results/{self._benchmark_id}/'
                     f'code-coverage-reports/{self._sample_id}.fuzz_target/'
                     f'report/linux/{relative_path}.html')
              url_line_number = f'{url}#L{line_number}' if line_number else url
            stack_traces[frame_num] = {
                "url": url_line_number,
                "path": path,
                "function": function_name,
                "memory_address": memory_addr
            }

    return stack_traces

  def get_crash_reproduction_path(self) -> str:
    """Get the crash reproduction path from the run log."""
    for line in self._lines:
      if "Test unit written to" in line:
        crash_match = re.search(r'Test unit written to (.+)', line)
        if crash_match:
          full_path = crash_match.group(1).strip()
          filename = full_path.split('/')[-1]
          return filename
    return ""

  def get_execution_stats(self) -> dict[str, str]:
    """Get the execution stats from the run log."""
    execution_stats = {}
    patterns = {
        'Executed units': r'stat::number_of_executed_units:\s*(\S+)',
        'Executions per sec': r'stat::average_exec_per_sec:\s*(\S+)',
        'Memory': r'stat::peak_rss_mb:\s*(\S+)',
        'New units added': r'stat::new_units_added:\s*(\S+)',
        'Slowest unit per time sec': r'stat::slowest_unit_time_sec:\s*(\S+)',
        'Edge coverage': r'Final cov:\s*(.*)',
        'Features': r'Final ft:\s*(.*)',
        'Engine': r'FUZZING_ENGINE=([a-zA-Z0-9_-]+)',
        'Corpus': r'INFO: seed corpus:\s*(.*)'
    }
    for line in self._lines:
      for key, pattern in patterns.items():
        if key in execution_stats:
          continue
        match = re.search(pattern, line)
        if match:
          execution_stats[key] = match.group(1).strip()
          break

    return execution_stats
