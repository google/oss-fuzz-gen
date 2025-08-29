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

import html
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

  def _extract_bash_commands(self, content: str) -> list[str]:
    """Extract and parse bash commands from content."""
    commands = []
    lines = content.split('\n')

    for i, line in enumerate(lines):
      line = line.strip()
      if line == '<bash>':
        command = self._process_bash_block(lines, i)
        if command and command not in commands:
          commands.append(command)

    return commands

  def _process_bash_block(self, lines: list[str], start_idx: int) -> str:
    """Process a single bash block and extract command summary."""
    for j in range(start_idx + 1, len(lines)):
      if lines[j].strip() == '</bash>':
        bash_content = '\n'.join(lines[start_idx + 1:j]).strip()
        if bash_content:
          return self._extract_command_from_content(bash_content)
        break
    return ""

  def _extract_command_from_content(self, bash_content: str) -> str:
    """Extract command summary from bash content."""
    first_line = bash_content.split('\n', 1)[0].strip()
    if not first_line:
      return ""

    # Skip comments and placeholder text
    if (first_line.startswith('#') or first_line.startswith('[The command') or
        first_line.startswith('No bash') or 'No bash' in first_line or
        len(first_line) < 3):
      return ""

    parts = first_line.split()
    if not parts:
      return ""

    cmd = parts[0]
    command_summary = self._build_command_summary(cmd, parts, first_line)

    if len(command_summary) > 40:
      command_summary = command_summary[:37] + '...'

    return command_summary

  def _build_command_summary(self, cmd: str, parts: list[str],
                             first_line: str) -> str:
    """Build command summary based on command type."""
    if cmd == 'grep':
      quoted_match = re.search(r"'([^']+)'", first_line)
      if quoted_match:
        search_term = quoted_match.group(1)
        return f"grep '{search_term}'"
      return self._extract_key_args(cmd, parts[1:], 1)
    return self._extract_key_args(cmd, parts[1:], 2)

  def _extract_key_args(self, cmd: str, parts: list[str], max_args: int) -> str:
    """Extract key arguments from command parts."""
    key_args = []
    for part in parts:
      if not part.startswith('-') and len(part) > 1:
        if len(part) > 20:
          part = part[:17] + '...'
        key_args.append(part)
        if len(key_args) >= max_args:
          break
    return f"{cmd} {' '.join(key_args)}".strip()

  def _extract_tool_names(self, content: str) -> list[str]:
    """Extract tool names from content."""
    tool_counts = {}
    lines = content.split('\n')

    # For step titles
    relevant_tool_tags = [
        '<bash>', '<conclusion>', '<stderr>', '<gdb>', '<gdb command>',
        '<gdb output>', '<solution>', '<system>', '<return_code>'
    ]

    for i, line in enumerate(lines):
      line = line.strip()
      if line in relevant_tool_tags and not line.startswith('</'):
        tool_name = line[1:-1].replace('_', ' ').title()
        tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
      elif line == '<stderr>':
        if i + 1 < len(lines) and lines[i + 1].strip():
          tool_counts['Stderr'] = tool_counts.get('Stderr', 0) + 1

    tool_names = []
    for tool_name in tool_counts:
      tool_names.append(tool_name)

    return tool_names

  def _parse_steps_from_logs(self, agent_logs: list[LogPart]) -> list[dict]:
    """Parse steps from agent logs, grouping by chat prompt/response pairs."""
    step_pattern = re.compile(r"Step #(\d+) - \"(.+?)\":")
    simple_step_pattern = re.compile(r"Step #(\d+)")

    steps_dict = {}
    current_step_number = None

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

          if current_step_number not in steps_dict:
            steps_dict[current_step_number] = {
                'number': current_step_number,
                'type': 'Step',
                'log_parts': []
            }
          break

      if not step_header_found and current_step_number:
        steps_dict[current_step_number]['log_parts'].append(log_part)
      elif not step_header_found and not current_step_number and not steps_dict:
        steps_dict['0'] = {
            'number': None,
            'type': 'Content',
            'log_parts': [log_part]
        }

    return self._parse_steps_by_chat_pairs(agent_logs)

  def _parse_steps_by_chat_pairs(self, agent_logs: list[LogPart]) -> list[dict]:
    """Parse steps from agent logs by grouping chat prompt/response pairs."""
    steps = []

    first_prompt_idx = -1
    for i, log_part in enumerate(agent_logs):
      if log_part.chat_prompt:
        first_prompt_idx = i
        break

    if first_prompt_idx == -1:
      return []

    steps.append({
        'number': '0 - System Instructions',
        'type': 'System Instructions',
        'log_parts': [agent_logs[first_prompt_idx]]
    })

    # Process logs after the system prompt to group into steps.
    logs_to_process = agent_logs[first_prompt_idx + 1:]
    step_counter = 1
    current_step_parts = []

    for log_part in logs_to_process:
      if "agent-step" in log_part.content or "Trial ID:" in log_part.content:
        continue

      # A chat_response marks the beginning of a new step.
      if log_part.chat_response:
        if current_step_parts:
          step_data = self._create_step_data(step_counter, current_step_parts)
          steps.append(step_data)
          step_counter += 1
        current_step_parts = [log_part]
      else:
        current_step_parts.append(log_part)

    # Append the last step.
    if current_step_parts:
      step_data = self._create_step_data(step_counter, current_step_parts)
      steps.append(step_data)

    return steps

  def _convert_newlines_outside_tags(self, content: str) -> str:
    """Convert \\n to <br> tags when they appear outside XML tags."""
    tag_pattern = r'&lt;/?[^&]*?&gt;'

    tag_matches = list(re.finditer(tag_pattern, content))

    if not tag_matches:
      return content.replace('\\n', '<br>')

    result = []
    last_end = 0

    for match in tag_matches:
      # Process text before this tag
      before_tag = content[last_end:match.start()]
      result.append(before_tag.replace('\\n', '<br>'))

      # Add the tag itself (unchanged)
      result.append(match.group())

      last_end = match.end()

    remaining = content[last_end:]
    result.append(remaining.replace('\\n', '<br>'))

    return ''.join(result)

  def syntax_highlight_content(self,
                               content: str,
                               default_language: str = "",
                               agent_name: str = "") -> str:
    """Syntax highlights content while preserving visible tags."""

    # Escape everything first so raw logs are safe to render in HTML
    escaped = html.escape(content)

    escaped = self._convert_newlines_outside_tags(escaped)

    def _sub(pattern: str, repl: str, text: str) -> str:
      return re.sub(pattern, repl, text, flags=re.DOTALL)

    def _normalize_lang(lang: str) -> str:
      if not lang:
        return 'cpp'
      lang = lang.strip().lower()
      if lang in ['c++', 'cpp', 'cxx']:
        return 'cpp'
      if lang in ['c']:
        return 'c'
      if lang in ['python', 'py']:
        return 'python'
      if lang in ['java']:
        return 'java'
      if lang in ['rust', 'rs']:
        return 'rust'
      if lang in ['go', 'golang']:
        return 'go'
      return 'cpp'

    lang_key = _normalize_lang(default_language)

    escaped = _sub(
        r'&lt;conclusion&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/conclusion&gt;',
        r'<span class="log-tag">&lt;conclusion&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto '
        r'reason-block">\1</pre>'
        r'<span class="log-tag">&lt;/conclusion&gt;</span>', escaped)
    escaped = _sub(
        r'&lt;reason&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/reason&gt;', r'<span class="log-tag">&lt;reason&gt;</span>'
        r'<div class="markdown-block whitespace-pre-wrap break-words '
        r'overflow-x-auto">\1</div>'
        r'<span class="log-tag">&lt;/reason&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;bash&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/bash&gt;', r'<span class="log-tag">&lt;bash&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/bash&gt;</span>', escaped)
    escaped = _sub(
        r'&lt;build_script&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/build_script&gt;',
        r'<span class="log-tag">&lt;build_script&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-cpp">\1</code></pre>'
        r'<span class="log-tag">&lt;/build_script&gt;</span>', escaped)
    escaped = _sub(
        r'&lt;fuzz target&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/fuzz target&gt;',
        rf'<span class="log-tag">&lt;fuzz target&gt;</span>'
        rf'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        rf'<code class="language-{lang_key}">\1</code></pre>'
        rf'<span class="log-tag">&lt;/fuzz target&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;stdout&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/stdout&gt;', r'<span class="log-tag">&lt;stdout&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/stdout&gt;</span>', escaped)
    escaped = _sub(
        r'&lt;stderr&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/stderr&gt;', r'<span class="log-tag">&lt;stderr&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/stderr&gt;</span>', escaped)
    escaped = _sub(
        r'&lt;return_code&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/return_code&gt;',
        r'<span class="log-tag">&lt;return_code&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code>\1</code></pre>'
        r'<span class="log-tag">&lt;/return_code&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;build script&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/build script&gt;',
        r'<span class="log-tag">&lt;build script&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/build script&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;gcb&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)&lt;/gcb&gt;',
        r'<span class="log-tag">&lt;gcb&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/gcb&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;gdb&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)&lt;/gdb&gt;',
        r'<span class="log-tag">&lt;gdb&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/gdb&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;gdb command&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/gdb command&gt;',
        r'<span class="log-tag">&lt;gdb command&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/gdb command&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;gdb output&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/gdb output&gt;',
        r'<span class="log-tag">&lt;gdb output&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        r'<code class="language-bash">\1</code></pre>'
        r'<span class="log-tag">&lt;/gdb output&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;code&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)&lt;/code&gt;',
        r'<span class="log-tag">&lt;code&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        rf'<code class="language-{lang_key}">\1</code></pre>'
        r'<span class="log-tag">&lt;/code&gt;</span>', escaped)

    escaped = _sub(
        r'&lt;solution&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/solution&gt;', r'<span class="log-tag">&lt;solution&gt;</span>'
        r'<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
        rf'<code class="language-{lang_key}">\1</code></pre>'
        r'<span class="log-tag">&lt;/solution&gt;</span>', escaped)

    def process_system_content(match):
      content = match.group(1)
      return (r'<span class="log-tag">&lt;system&gt;</span>'
              r'<div class="whitespace-pre-wrap break-words '
              r'overflow-x-auto">' + content +
              r'</div><span class="log-tag">&lt;/system&gt;</span>')

    escaped = re.sub(
        r'&lt;system&gt;(\s*[^\s].*?[^\s]\s*|(?:\s*[^\s].*?)?)'
        r'&lt;/system&gt;',
        process_system_content,
        escaped,
        flags=re.DOTALL)

    # Handle steps tag (usually opening only, no closing tag)
    escaped = _sub(r'&lt;steps&gt;',
                   r'<span class="log-tag">&lt;steps&gt;</span>', escaped)

    # Generic fallback for any remaining XML tags not explicitly handled above
    # This ensures all XML tags get the log-tag styling
    escaped = _sub(r'&lt;([^/&][^&]*?)&gt;',
                   r'<span class="log-tag">&lt;\1&gt;</span>', escaped)
    escaped = _sub(r'&lt;(/[^&]*?)&gt;',
                   r'<span class="log-tag">&lt;\1&gt;</span>', escaped)

    # Handle ExecutionStage-specific highlighting for fuzz target source
    if "ExecutionStage" in agent_name:
      escaped = self._highlight_execution_stage_content(escaped, lang_key)

    return escaped

  def _highlight_execution_stage_content(self, content: str,
                                         lang_key: str) -> str:
    """Add syntax highlighting for ExecutionStage-specific content patterns."""

    # Pattern to match "Fuzz target source:" followed by code until
    # "Build script source:"
    fuzz_target_pattern = (r'(Fuzz target source:)\s*\n'
                           r'(.*?)'
                           r'(?=Build script source:|$)')

    def replace_fuzz_target(match):
      header = match.group(1)
      code_content = match.group(2).strip()

      if code_content:
        return (
            f'<div class="font-medium text-blue-600 mb-2">{header}</div>'
            '<pre class="whitespace-pre-wrap break-words overflow-x-auto">'
            f'<code class="language-{lang_key}">{code_content}</code></pre>')
      return f'<div class="font-medium text-blue-600 mb-2">{header}</div>'

    content = re.sub(fuzz_target_pattern,
                     replace_fuzz_target,
                     content,
                     flags=re.DOTALL)

    return content

  def _create_step_data(self, step_number: int,
                        log_parts: list[LogPart]) -> dict:
    """Create step data from log parts."""
    step_data = {
        'number': str(step_number),
        'type': 'Step',
        'log_parts': log_parts
    }

    all_content = '\n'.join([part.content for part in log_parts])
    tool_names = self._extract_tool_names(all_content)
    bash_commands = self._extract_bash_commands(all_content)

    if tool_names:
      step_data['name'] = f"{', '.join(tool_names)}"
    if bash_commands:
      step_data['bash_commands'] = bash_commands

    return step_data

  def get_agent_sections(self) -> dict[str, list[LogPart]]:
    """Get the agent sections from the logs."""

    pattern = re.compile(r"\*{20,}([^*]+?)\*{20,}")
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
