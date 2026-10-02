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
    root_cause, intermediate, root_status = '', '', 'Unverified'
  if root_location in ('true', 'yes', 'success'):
    root_status = 'Verified'
  elif root_location in ('false', 'no', 'failure'):
    root_status = 'Unverified'
  root_cause_explanation = _root_cause_explanation(trace, root_cause)
  trace_reason = ''
  if not trace_error:
    try:
      trace_reason = _repair_reason(trace)
    except Exception as error:  # pylint: disable=broad-exception-caught
      trace_error = f'{type(error).__name__}: {error}'
  patches = [(str(path.relative_to(project_dir)), _read_text(path))
             for path in patch_files]
  stats = _patch_stats(patches)
  initial_errors = _key_build_errors(
      _read_remote_log(str(metadata.get('fuzzing_build_error_log', ''))))
  upstream_url = str(metadata.get('software_repo_url', ''))
  status = str(
      metadata.get('fix_result') or
      ('Success' if 'SUCCESS' in result_text.upper() else 'Unknown'))
  project = str(metadata.get('project') or project_dir.name)
  original_failure_cause = _original_failure_cause(trace, root_cause)
  record = {
      'project':
          project,
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
              initial_errors,
          'pr_summary':
              _pr_summary(project, status, original_failure_cause, trace),
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
      'patches':
          patches,
      'fixed_files': [(str(path.relative_to(project_dir)), _read_text(path))
                      for path in fixed_files],
      'source_dir':
          str(project_dir),
  }
  record['failure_chain_html'] = _failure_chain_html(record)
  record['patch_html'] = _patch_html(record)
  return record


def _pr_summary(project: str, status: str, root_cause: str,
                trace: dict[str, Any]) -> str:
  """Builds an evidence-backed, one-paragraph PR description summary."""
  if status.lower() not in ('success', 'fixed'):
    return ''
  method, reasoning = _repair_details(trace)
  sentences = [f"Resolves {project}'s OSS-Fuzz build failure."]
  if root_cause:
    sentences.append(_sentence_text(root_cause, 1))
  if method:
    method_sentences = _split_sentences(method)[:2]
    method_sentences[0] = f'The fix {_lowercase_first(method_sentences[0])}'
    sentences.extend(method_sentences)
  effect = _concise_build_evidence(reasoning)
  if effect and effect.lower() not in ' '.join(sentences).lower():
    sentences.append(_split_sentences(effect)[-1])
  return ' '.join(_ensure_period(sentence) for sentence in sentences[:5])


def _original_failure_cause(trace: dict[str, Any], fallback: str) -> str:
  """Extracts the original build cause from the earliest trace evidence."""
  nodes = trace.get('nodes', [])
  if not isinstance(nodes, list):
    return fallback
  for node in nodes:
    if not isinstance(node, dict):
      continue
    memory = node.get('semantic_memory', {})
    if not isinstance(memory, dict):
      continue
    reflection = _concise_build_evidence(
        str(memory.get('reflection_analysis', '')))
    if reflection:
      return _sentence_text(reflection, 2)
    problem = _concise_build_evidence(str(memory.get('unsolved_problems', '')))
    if problem:
      return _sentence_text(problem, 2)
  return fallback


def _repair_details(trace: dict[str, Any]) -> tuple[str, str]:
  """Extracts the final repair method and its evidence-backed rationale."""
  nodes = trace.get('nodes', [])
  if not isinstance(nodes, list):
    return '', ''
  for node in reversed(nodes):
    action = node.get('action_and_intent', {}) if isinstance(node, dict) else {}
    if not isinstance(action, dict):
      continue
    strategy = str(action.get('repair_strategy', '')).strip()
    if not strategy or strategy == 'N/A':
      continue
    parts = strategy.split('Reasoning:', 1)
    method = re.sub(r'^Method:\s*', '', parts[0], flags=re.IGNORECASE).strip()
    reasoning = parts[1].strip() if len(parts) == 2 else ''
    return _clean_prose(method), _clean_prose(reasoning)
  return '', ''


def _clean_prose(text: str) -> str:
  """Converts trace list formatting into compact prose."""
  text = text.replace('\\r\\n', ' ').replace('\\n', ' ')
  text = re.sub(r'(^|\n)\s*\d+[.)]\s*', r'\1', text)
  text = re.sub(r'(^|\s)[.]+(?=\s|$)', ' ', text)
  return re.sub(r'\s+', ' ', text).strip()


def _sentence_text(text: str, limit: int) -> str:
  """Returns at most ``limit`` non-empty sentences from trace evidence."""
  return ' '.join(_split_sentences(text)[:limit])


def _split_sentences(text: str) -> list[str]:
  """Splits prose into non-empty sentences while retaining punctuation."""
  return [
      part.strip() for part in re.split(r'(?<=[.!?])\s+', text) if part.strip()
  ]


def _ensure_period(text: str) -> str:
  """Ensures generated PR prose has sentence-ending punctuation."""
  text = text.strip()
  return text if not text or text[-1] in '.!?' else f'{text}.'


def _lowercase_first(text: str) -> str:
  """Lowercases the first prose character after an optional code marker."""
  return text[:1].lower() + text[1:] if text else text


def _failure_chain_text(record: dict[str, Any]) -> str:
  """Formats one project's build-failure evidence as plain text."""
  summary = record['repair_summary']
  initial = '\n'.join(f'- {_expand_escaped_newlines(error)}'
                      for error in summary['initial_errors'])
  initial = initial or 'Unavailable'
  intermediate = summary[
      'intermediate'] or 'No build-failure evolution recorded.'
  if summary['root_status'] == 'Verified':
    root = summary['root_cause_explanation'] or summary['root_cause']
    root = root or 'Verified, but no description was recorded.'
  else:
    root = 'Unverified'
  return (f"Project: {record['project']}\n\nInitial build error\n"
          f'{initial}\n\nBuild-failure evolution\n{intermediate}\n\n'
          f'Root cause\n{root}\n')


def _expand_escaped_newlines(text: str) -> str:
  """Expands escaped newlines found in archived Cloud Build log lines."""
  return text.replace('\\r\\n', '\n').replace('\\n', '\n')


def _evidence_document(title: str, content: str, code: bool = False) -> str:
  """Creates a minimal standalone HTML document preserving source layout."""
  white_space = 'pre' if code else 'pre-wrap'
  return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ margin: 0; padding: 2rem; background: #f8fafc;
           color: #0f172a; font: 14px/1.55 ui-monospace, monospace; }}
    main {{ max-width: 1100px; margin: auto; }}
    h1 {{ font: 600 1.35rem/1.3 system-ui, sans-serif; }}
    pre {{ overflow: auto; padding: 1.25rem; border: 1px solid #cbd5e1;
           border-radius: .5rem; background: #fff;
           white-space: {white_space}; overflow-wrap: anywhere; }}
  </style>
</head>
<body><main><h1>{html.escape(title)}</h1><pre><code>{html.escape(content)}</code></pre></main></body>
</html>'''


def _failure_chain_html(record: dict[str, Any]) -> str:
  """Formats a build failure chain as a readable standalone page."""
  return _evidence_document(f"{record['project']} build failure chain",
                            _failure_chain_text(record))


def _patch_html(record: dict[str, Any]) -> str:
  """Formats archived patches as syntax-preserving code blocks."""
  patches = record['patches']
  content = ('\n\n'.join(
      f'File: {name}\n\n{patch.rstrip()}' for name, patch in patches)
             if patches else 'Patch unavailable.')
  return _evidence_document(f"{record['project']} repair patch", content, True)


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
      if not _is_empty_evidence(action_root_commit):
        root_located = True
      semantic_memory = node.get('semantic_memory', {})
      problem = (semantic_memory.get('unsolved_problems', '') if isinstance(
          semantic_memory, dict) else '')
      if problem and problem != 'N/A':
        problem = _concise_build_evidence(str(problem))
        if problem:
          intermediate.append(problem)
          candidate_root_cause = candidate_root_cause or problem
      reflection = (semantic_memory.get('reflection_analysis', '')
                    if isinstance(semantic_memory, dict) else '')
      reflection = _concise_build_evidence(str(reflection))
      if reflection:
        intermediate.append(reflection)
        candidate_root_cause = candidate_root_cause or reflection
    if isinstance(validation, dict):
      report = validation.get('validation_report_after', {})
      if isinstance(report, dict) and any(
          str(value).startswith('pass') for value in report.values()):
        root_located = root_located or bool(
            not _is_empty_evidence(action_root_commit))
  if not root_cause:
    root_cause = candidate_root_cause
  intermediate = list(dict.fromkeys(intermediate))
  return (root_cause, ' '.join(intermediate[-3:]),
          'Verified' if root_located else 'Unverified')


def _is_empty_evidence(value: Any) -> bool:
  """Returns whether a trace field contains only a missing-value marker."""
  return value is None or str(value).strip().lower() in {
      '', 'n/a', 'none', 'null', 'unknown'
  }


def _is_build_evidence(text: str) -> bool:
  """Returns whether trace text describes a build or validation problem."""
  excluded = ('git apply', 'patch.diff failed', 'patch application',
              'patch-based repair', 'brittle patch', 'patch mismatch',
              'context mismatch', 'orchestration', 'no message in response',
              'rollback', 'agent error')
  normalized = text.lower().replace('`', '').replace('*', '')
  return bool(text.strip()) and not any(item in normalized for item in excluded)


def _concise_build_evidence(text: str) -> str:
  """Keeps concise causal build evidence and removes repair-process text."""
  if _is_empty_evidence(text):
    return ''
  sentences = []
  process_terms = ('previous repair attempt', 'repair direction', 'next round',
                   'self-validation', 'reflection indicates', 'must prioritize',
                   'close in on the goal')
  for sentence in re.split(r'(?<=[.!?])\s+', _clean_prose(text)):
    if (sentence and _is_build_evidence(sentence) and
        not any(term in sentence.lower() for term in process_terms)):
      sentences.append(sentence)
  return _ensure_period(' '.join(sentences[:2])) if sentences else ''


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
      reflection = _concise_build_evidence(reflection)
      if reflection:
        explanations.append(reflection)
    action = node.get('action_and_intent', {})
    if isinstance(action, dict):
      strategy = str(action.get('repair_strategy', '')).strip()
      if 'Reasoning:' in strategy:
        reasoning = strategy.split('Reasoning:', 1)[1].strip()
        reasoning = _concise_build_evidence(reasoning)
        if reasoning:
          explanations.append(reasoning)
    if explanations:
      break
  explanation = explanations[0] if explanations else root_cause
  sentences = re.split(r'(?<=[.!?])\s+', explanation)
  return ' '.join(sentences[:5]).strip()


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
