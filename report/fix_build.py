# Copyright 2026 Google LLC
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
"""Generates a self-contained report for OSS-Fuzz project build repairs."""

import argparse
import html
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


def _read_text(path: Path) -> str:
  """Reads a text file without allowing one bad artifact to stop reporting."""
  try:
    return path.read_text(encoding='utf-8', errors='replace')
  except OSError as error:
    return f'Unable to read {path}: {error}'


def _read_remote_log(url: str) -> str:
  """Reads the original OSS-Fuzz log referenced by project metadata."""
  if not url.startswith(('http://', 'https://')):
    return ''
  try:
    with urllib.request.urlopen(url, timeout=20) as response:
      content = response.read(128 * 1024)
    return content.decode('utf-8', errors='replace')
  except (OSError, urllib.error.URLError):
    return ''


def _load_input(path: Path) -> dict[str, Any]:
  """Loads the project metadata written by the repair agent."""
  try:
    data = yaml.safe_load(_read_text(path)) or {}
  except yaml.YAMLError:
    return {}
  if isinstance(data, list):
    data = data[0] if data else {}
  return data if isinstance(data, dict) else {}


def _find_project_dirs(results_dir: Path) -> list[Path]:
  """Finds project result directories and ignores nested agent folders."""
  if not results_dir.is_dir():
    return []

  candidates: set[Path] = set()
  markers = {'input.yaml', 'result.txt', 'repair-trace.json'}
  for marker in markers:
    for artifact in results_dir.rglob(marker):
      # Agent artifacts can be nested below the project directory. Walk up
      # through known implementation folders before registering the project.
      project_dir = artifact.parent
      while project_dir.parent != results_dir and project_dir.name in {
          'repair', 'external-agent', 'fixed-files', 'process_fixed',
          'process_unfixed'
      }:
        project_dir = project_dir.parent
      if project_dir != results_dir:
        candidates.add(project_dir)
  return sorted(candidates)


def _first_file(project_dir: Path, name: str) -> Path | None:
  """Returns the project-level artifact, falling back to agent artifacts."""
  direct = project_dir / name
  if direct.is_file():
    return direct
  matches = sorted(project_dir.rglob(name))
  return matches[0] if matches else None


def _project_record(project_dir: Path) -> dict[str, Any]:
  """Collects metadata and repair artifacts for one project."""
  # The external agent writes metadata below ``repair/`` while the standard
  # report identifies the enclosing ``output-*`` directory as the project.
  # Search below that directory so fields such as ``fix_result`` and
  # ``software_repo_url`` are not silently lost.
  input_path = _first_file(project_dir, 'input.yaml')
  metadata = _load_input(input_path) if input_path else {}
  trace_path = _first_file(project_dir, 'repair-trace.json')
  result_path = _first_file(project_dir, 'result.txt')
  run_log_path = _first_file(project_dir, 'run.log')

  trace: dict[str, Any] = {}
  trace_error = ''
  if trace_path:
    try:
      value = json.loads(_read_text(trace_path))
      if not isinstance(value, dict):
        raise ValueError('top-level JSON value is not an object')
      trace = value
    except (OSError, ValueError, TypeError) as error:
      trace_error = f'{type(error).__name__}: {error}'
      trace = {}
  else:
    trace_error = 'repair-trace.json not found'

  nodes = trace.get('nodes', [])
  nodes = nodes if isinstance(nodes, list) else []
  patch_files = sorted(path for path in project_dir.rglob('*')
                       if path.is_file() and path.suffix == '.patch')
  fixed_files = sorted(path for path in project_dir.rglob('*')
                       if path.is_file() and 'fixed-files' in path.parts and
                       path.suffix != '.patch')

  result_text = _read_text(result_path) if result_path else ''
  root_location = _final_field(result_text, 'Root Cause Location').lower()
  try:
    root_cause, intermediate, root_status = _trace_summary(trace)
  except Exception as error:  # pylint: disable=broad-exception-caught
    trace_error = trace_error or f'{type(error).__name__}: {error}'
    root_cause, intermediate, root_status = '', '', '未验证'
  if root_location in ('true', 'yes', 'success'):
    root_status = '已定位'
  elif root_location in ('false', 'no', 'failure'):
    root_status = '未验证'
  root_cause_explanation = _root_cause_explanation(trace, root_cause)
  trace_reason = ''
  if not trace_error:
    try:
      trace_reason = _repair_reason(trace)
    except Exception as error:  # pylint: disable=broad-exception-caught
      trace_error = f'{type(error).__name__}: {error}'
  stats = _patch_stats([(str(path.relative_to(project_dir)), _read_text(path))
                        for path in patch_files])
  upstream_url = str(metadata.get('software_repo_url', ''))
  status = str(
      metadata.get('fix_result') or
      ('Success' if 'SUCCESS' in result_text.upper() else 'Unknown'))
  return {
      'project':
          metadata.get('project') or project_dir.name,
      'status':
          status,
      'metadata':
          metadata,
      'trace_error':
          trace_error,
      'rounds':
          len(nodes),
      'trace':
          trace,
      'result_text':
          result_text,
      'repair_summary': {
          'root_cause':
              root_cause,
          'root_status':
              root_status,
          'root_cause_explanation':
              root_cause_explanation,
          'intermediate':
              intermediate,
          'initial_errors':
              _key_build_errors(
                  _read_remote_log(
                      str(metadata.get('fuzzing_build_error_log', '')))),
          'reason':
              trace_reason or '修复理由未在账本中提供。',
      },
      'metrics': {
          'upstream_repo':
              _repo_name(upstream_url),
          'downstream_repo':
              'oss-fuzz',
          'files_changed':
              _final_field(result_text, 'Files Change') or stats['files'],
          'lines_changed':
              _final_field(result_text, 'Lines Change')
              or stats['added'] + stats['deleted'],
          'input_tokens':
              _final_field(result_text, 'Input Tokens') or '0',
          'output_tokens':
              _final_field(result_text, 'Output Tokens') or '0',
          'time_cost':
              _final_field(result_text, 'Time Cost') or 'unknown',
          'attempt_rounds':
              _final_field(result_text, 'Attempt Rounds') or '0',
          'repair_rounds':
              _final_field(result_text, 'Repair Rounds') or '0',
      },
      'run_log':
          _read_text(run_log_path) if run_log_path else '',
      'original_build_log':
          _read_remote_log(str(metadata.get('fuzzing_build_error_log', ''))),
      'patches': [(str(path.relative_to(project_dir)), _read_text(path))
                  for path in patch_files],
      'fixed_files': [(str(path.relative_to(project_dir)), _read_text(path))
                      for path in fixed_files],
      'source_dir':
          str(project_dir),
  }


def _pre(value: str) -> str:
  """Escapes text for a report preformatted block."""
  return html.escape(value or '(none)')


def _final_field(result_text: str, label: str) -> str:
  match = re.search(rf'^\s*-?\s*\[?{re.escape(label)}\]?\s*:\s*(.*?)\s*$',
                    result_text, re.MULTILINE | re.IGNORECASE)
  return match.group(1).strip() if match else ''


def _repo_name(url: str) -> str:
  path = urlparse(url).path.rstrip('/')
  return Path(path).name.removesuffix('.git') if path else 'unknown'


def _key_build_errors(log_text: str, limit: int = 3) -> list[str]:
  patterns = re.compile(
      r'(error:|fatal:|failed|failure|not recognized|undefined reference|'
      r'cannot |no such file|does not exist|linker)', re.IGNORECASE)
  lines = []
  for line in log_text.splitlines():
    clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
    if clean and patterns.search(clean) and clean not in lines:
      lines.append(clean)
  return lines[:limit]


def _trace_summary(trace: dict[str, Any]) -> tuple[str, str, str]:
  """Summarizes root-cause and intermediate evidence from the trace."""
  nodes = trace.get('nodes', [])
  nodes = nodes if isinstance(nodes, list) else []
  root_located = False
  root_cause = ''
  candidate_root_cause = ''
  intermediate = []
  for node in nodes:
    validation = node.get('validation', {}) if isinstance(node, dict) else {}
    action = node.get('action_and_intent', {}) if isinstance(node, dict) else {}
    action_root_commit = (action.get('root_cause_commit_sha') if isinstance(
        action, dict) else None)
    if isinstance(action, dict):
      if action_root_commit not in ('', 'N/A', None):
        root_located = True
        root_cause = str(action_root_commit)
      semantic_memory = node.get('semantic_memory', {})
      problem = (semantic_memory.get('unsolved_problems', '') if isinstance(
          semantic_memory, dict) else '')
      if problem and problem != 'N/A':
        if _is_build_evidence(str(problem)):
          intermediate.append(str(problem))
        if not candidate_root_cause and _is_build_evidence(str(problem)):
          candidate_root_cause = str(problem)
    if isinstance(validation, dict):
      report = validation.get('validation_report_after', {})
      if isinstance(report, dict) and any(
          str(value).startswith('pass') for value in report.values()):
        root_located = root_located or bool(
            action_root_commit not in ('', 'N/A', None))
  if not root_cause:
    root_cause = candidate_root_cause
  return (root_cause, ' → '.join(intermediate[-2:]),
          '已定位' if root_located else '候选（未验证）')


def _is_build_evidence(text: str) -> bool:
  """Returns whether trace text describes a build or validation problem."""
  excluded = ('git apply', 'patch.diff failed', 'patch application',
              'patch mismatch', 'context mismatch', 'orchestration',
              'no message in response', 'rollback', 'agent error')
  return bool(
      text.strip()) and not any(item in text.lower() for item in excluded)


def _root_cause_explanation(trace: dict[str, Any], root_cause: str) -> str:
  """Returns a short explanation based only on trace-provided evidence."""
  nodes = trace.get('nodes', [])
  if not isinstance(nodes, list):
    return root_cause
  explanations = []
  for node in reversed(nodes):
    if not isinstance(node, dict):
      continue
    memory = node.get('semantic_memory', {})
    if isinstance(memory, dict):
      reflection = str(memory.get('reflection_analysis', '')).strip()
      if reflection and reflection != 'N/A' and _is_build_evidence(reflection):
        explanations.append(reflection)
    action = node.get('action_and_intent', {})
    if isinstance(action, dict):
      strategy = str(action.get('repair_strategy', '')).strip()
      if 'Reasoning:' in strategy:
        reasoning = strategy.split('Reasoning:', 1)[1].strip()
        if _is_build_evidence(reasoning):
          explanations.append(reasoning)
    if explanations:
      break
  explanation = explanations[0] if explanations else root_cause
  sentences = re.split(r'(?<=[.!?])\s+', explanation)
  return ' '.join(sentences[:5]).strip() or '根因说明未提供。'


def _repair_reason(trace: dict[str, Any]) -> str:
  """Extracts a concise, evidence-backed repair rationale."""
  nodes = trace.get('nodes', [])
  if not isinstance(nodes, list):
    return ''
  for node in reversed(nodes):
    action = node.get('action_and_intent', {}) if isinstance(node, dict) else {}
    strategy = (action.get('repair_strategy', '')
                if isinstance(action, dict) else '')
    if strategy:
      reason = strategy.split('Reasoning:', 1)[-1].strip()
      return re.split(r'(?<=[.!?])\s+', reason, maxsplit=2)[0][:500]
  return ''


def _patch_stats(patches: list[tuple[str, str]]) -> dict[str, int]:
  """Counts changed patch files and added or deleted lines."""
  files = set()
  added = deleted = 0
  for name, content in patches:
    files.add(name)
    for line in content.splitlines():
      if line.startswith('+++') or line.startswith('---'):
        continue
      added += int(line.startswith('+'))
      deleted += int(line.startswith('-'))
  return {'files': len(files), 'added': added, 'deleted': deleted}


def _section(title: str, content: str, open_by_default: bool = False) -> str:
  """Returns a collapsible report section."""
  opened = ' open' if open_by_default else ''
  return (f'<details{opened}><summary>{html.escape(title)}</summary>'
          f'<pre>{_pre(content)}</pre></details>')


def _project_html(record: dict[str, Any]) -> str:
  """Renders the details for one repaired project."""
  metadata = record['metadata']
  source_log = metadata.get('fuzzing_build_error_log', '')
  source_link = (f'<a href="{html.escape(source_log)}" target="_blank">'
                 'Original build log</a>' if source_log else 'Unavailable')
  sections = [_section('Repair result', record['result_text'], True)]
  sections.append(
      _section('Original OSS-Fuzz build log', record['original_build_log']))
  sections.append(
      _section('Repair trace (JSON)', json.dumps(record['trace'], indent=2)))
  if record['trace_error']:
    sections.append(
        _section('Repair trace unavailable', record['trace_error'], True))
  sections.append(_section('Agent run log', record['run_log']))
  for name, content in record['patches']:
    sections.append(_section(f'Patch: {name}', content, True))
  for name, content in record['fixed_files']:
    sections.append(_section(f'Fixed file: {name}', content))
  details = ''.join(sections)
  return (f'<article><h2>{html.escape(record["project"])}: '
          f'<span class="status">{html.escape(record["status"])}</span></h2>'
          '<dl>'
          f'<dt>Repair rounds</dt><dd>{record["rounds"]}</dd>'
          f'<dt>Original build failure</dt><dd>{source_link}</dd>'
          '<dt>Project revision</dt><dd><code>'
          f'{_pre(str(metadata.get("software_sha", "")))}</code></dd>'
          '<dt>OSS-Fuzz revision</dt><dd><code>'
          f'{_pre(str(metadata.get("oss-fuzz_sha", "")))}</code></dd>'
          '</dl>' + details + '</article>')


def generate_report(results_dir: str, output_dir: str, model: str = '') -> None:
  """Generates index.html and index.json for a fix-build experiment."""
  root = Path(results_dir)
  records = [_project_record(path) for path in _find_project_dirs(root)]
  successful = sum(
      record['status'].lower() in ('success', 'fixed') for record in records)
  summary = {
      'total_projects': len(records),
      'successful_projects': successful,
      'projects': records,
  }
  output = Path(output_dir)
  output.mkdir(parents=True, exist_ok=True)
  (output / 'index.json').write_text(json.dumps(summary, indent=2),
                                     encoding='utf-8')
  cards = ''.join(_project_html(record) for record in records)
  if not records:
    cards = '<p>No fix-build results were found.</p>'
  document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSS-Fuzz Build Repair Report</title>
<style>
body {{ font: 16px system-ui, sans-serif; margin: 2rem auto; max-width: 1100px; color: #202124; }}
article {{ border: 1px solid #dadce0; border-radius: 8px; margin: 1.5rem 0; padding: 1rem 1.25rem; }}
summary {{ cursor: pointer; font-weight: 600; margin: .75rem 0; }}
pre {{ background: #f8f9fa; border: 1px solid #e8eaed; overflow: auto; padding: 1rem; white-space: pre-wrap; }}
dl {{ display: grid; grid-template-columns: 180px 1fr; gap: .4rem 1rem; }} dt {{ font-weight: 600; }}
.status {{ color: #137333; font-size: .8em; }} code {{ overflow-wrap: anywhere; }}
</style></head><body>
<h1>OSS-Fuzz Build Repair Report</h1>
<p>Model: {_pre(model or 'unknown')} | Projects: {len(records)} | Successful: {successful}</p>{cards}
</body></html>'''
  (output / 'index.html').write_text(document, encoding='utf-8')


def main() -> None:
  """Parses command-line arguments and generates the report."""
  parser = argparse.ArgumentParser()
  parser.add_argument('-r', '--results-dir', required=True)
  parser.add_argument('-o', '--output-dir', default='results-report')
  parser.add_argument('-m', '--model', default='')
  args = parser.parse_args()
  generate_report(args.results_dir, args.output_dir, args.model)


if __name__ == '__main__':
  main()
