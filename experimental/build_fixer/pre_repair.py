#!/usr/bin/env python3
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
"""Acquire, reproduce, and validate recent OSS-Fuzz build-failure metadata.

This is the experiment-safe integration of ``fuzz_error_log_acquisition`` and
``reproduce_note_fuzz``.  It deliberately keeps all mutable state below the
experiment result directory.  The original downloaded logs are never renamed
or deleted: state-boundary filtering is performed on a copied tree.
"""

from __future__ import annotations

import calendar
import dataclasses
import datetime as dt
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

import yaml

LOG_ROOT_NAME = 'acquired_logs'
ACQUISITION_MODES = ('key', 'all')
KEY_RECENT_BUILD_COUNT = 7
BUILD_STATUS_URL = ('https://oss-fuzz-build-logs.storage.googleapis.com/'
                    'status.json')
BUILD_LOG_ROOT = 'https://oss-fuzz-build-logs.storage.googleapis.com'
OSS_FUZZ_UPSTREAM_URL = 'https://github.com/google/oss-fuzz.git'
LOGGER = logging.getLogger(__name__)
PRE_REPAIR_PROJECT_BLACKLIST = frozenset({
    'commons-validator',
    'libmediaart',
    'protoreflect',
    'tint',
})
BLACKLIST_REASON = 'project is blacklisted from pre-repair'
AUTO_BLACKLIST_REASON = 'latest build log is older than one calendar month'
BLACKLIST_SUGGESTIONS_FILE = 'pre_repair_blacklist.yaml'
OSS_FUZZ_SHA_FIELD = 'oss-fuzz_sha'
REQUIRED_METADATA = (OSS_FUZZ_SHA_FIELD, 'software_sha', 'base_image_digest',
                     'fuzzing_build_error_log', 'software_repo_url', 'engine',
                     'sanitizer', 'architecture')
METADATA_FIELD_ORDER = ('project', 'language', 'error_time', OSS_FUZZ_SHA_FIELD,
                        'fuzzing_build_error_log', 'software_repo_url',
                        'software_sha', 'engine', 'sanitizer', 'architecture',
                        'base_image_digest', 'error_category',
                        'root_cause_commit', 'root_cause_workspace',
                        'fixed_state')
LOG_NAME = re.compile(r'^(?P<year>\d{4})_(?P<month>\d{1,2})_(?P<day>\d{1,2})\s+'
                      r'(?P<status>success|error)$')
COMPILE_CONFIG = re.compile(
    r'compile-([a-zA-Z0-9+\-]+)-([a-zA-Z0-9+\-]+)-([a-zA-Z0-9_]+)')


class PreRepairError(RuntimeError):
  """A controlled predecessor failure recorded in the manifest."""

  def __init__(self,
               message: str,
               report: dict[str, Any] | None = None) -> None:
    super().__init__(message)
    self.report = report


@dataclasses.dataclass(frozen=True)
class LogFile:
  path: Path
  log_date: dt.date
  status: str


def subtract_calendar_months(today: dt.date, months: int = 3) -> dt.date:
  """Returns the calendar-month boundary, clamping to the target month end."""
  month_index = today.year * 12 + today.month - 1 - months
  year, month_index = divmod(month_index, 12)
  month = month_index + 1
  return dt.date(year, month, min(today.day,
                                  calendar.monthrange(year, month)[1]))


def parse_log_name(path: Path) -> LogFile | None:
  match = LOG_NAME.fullmatch(path.name.lstrip('+'))
  if not match:
    return None
  try:
    return LogFile(
        path, dt.date(int(match['year']), int(match['month']),
                      int(match['day'])), match['status'])
  except ValueError:
    return None


def select_boundary_logs(
    logs: Iterable[LogFile]) -> tuple[set[Path], list[str]]:
  """Implements fuzz-logs-total/keep_error_boundary_logs.py selection.

  A continuous error run retains its earliest error; a success run retains its
  first and last success.  Same-day success/error pairs are boundaries.
  """
  parsed = sorted(logs,
                  key=lambda item: (item.log_date, item.status, item.path.name))
  if not any(item.status == 'error' for item in parsed):
    return set(), []
  by_date: dict[dt.date, list[LogFile]] = defaultdict(list)
  for item in parsed:
    by_date[item.log_date].append(item)

  def select_segment(segment: list[LogFile]) -> set[Path]:
    keep: set[Path] = set()
    index = 0
    while index < len(segment):
      end = index + 1
      while end < len(segment) and segment[end].status == segment[index].status:
        end += 1
      run = segment[index:end]
      keep.add(run[0].path)
      if run[0].status == 'success':
        keep.add(run[-1].path)
      index = end
    return keep

  keep: set[Path] = set()
  collisions: list[str] = []
  segment: list[LogFile] = []
  for log_date in sorted(by_date):
    day_logs = by_date[log_date]
    if {item.status for item in day_logs} == {'success', 'error'}:
      keep.update(select_segment(segment))
      segment = []
      keep.update(item.path for item in day_logs)
      collisions.append(log_date.isoformat())
    else:
      segment.extend(day_logs)
  keep.update(select_segment(segment))
  return keep, collisions


def filter_log_tree(source: Path,
                    destination: Path,
                    projects: Iterable[str] | None = None) -> dict[str, Any]:
  """Copies state-boundary logs without applying a date-window filter."""
  destination.mkdir(parents=True, exist_ok=True)
  report: dict[str, Any] = {
      'projects': [],
      'copied_count': 0,
      'skipped_paths': [],
      'skipped_projects': {}
  }
  if not source.is_dir():
    raise PreRepairError(f'acquisition did not create log root: {source}')
  selected_projects = set(projects or [])
  blacklisted_projects = selected_projects & PRE_REPAIR_PROJECT_BLACKLIST
  selected_projects -= PRE_REPAIR_PROJECT_BLACKLIST
  available_projects = {
      project_dir.name
      for project_dir in source.iterdir()
      if project_dir.is_dir()
  }
  missing_projects = sorted(selected_projects - available_projects)
  for project_dir in sorted(source.iterdir()):
    if not project_dir.is_dir():
      report['skipped_paths'].append(str(project_dir))
      continue
    if selected_projects and project_dir.name not in selected_projects:
      continue
    if project_dir.name in PRE_REPAIR_PROJECT_BLACKLIST:
      report['skipped_projects'][project_dir.name] = BLACKLIST_REASON
      continue
    all_logs: list[LogFile] = []
    for child in sorted(project_dir.iterdir()):
      if not child.is_file():
        report['skipped_paths'].append(str(child))
        continue
      parsed = parse_log_name(child)
      if parsed is None:
        report['skipped_paths'].append(str(child))
      else:
        all_logs.append(parsed)
    # This is exactly the canonical boundary algorithm from fuzz-logs-total.
    # The commit-mapping window must not discard acquired logs.
    keep, collisions = select_boundary_logs(all_logs)
    chosen = [item for item in all_logs if item.path in keep]
    copied: list[str] = []
    for item in chosen:
      target = destination / project_dir.name / item.path.name
      target.parent.mkdir(parents=True, exist_ok=True)
      shutil.copy2(item.path, target)
      copied.append(item.path.name)
    report['projects'].append({
        'project': project_dir.name,
        'input_count': len(all_logs),
        'selected_files': copied,
        'collision_dates': collisions
    })
    report['copied_count'] += len(copied)
  if missing_projects:
    report['missing_projects'] = missing_projects
  for project in sorted(blacklisted_projects):
    report['skipped_projects'][project] = BLACKLIST_REASON
  return report


def _status_projects() -> list[dict[str, Any]]:
  """Loads the structured data consumed by the OSS-Fuzz status page."""
  request = urllib.request.Request(BUILD_STATUS_URL,
                                   headers={'User-Agent': 'oss-fuzz-gen'})
  try:
    with urllib.request.urlopen(request, timeout=60) as response:
      payload = json.loads(response.read())
  except Exception as error:
    raise PreRepairError(
        f'failed to load OSS-Fuzz status data: {error}') from error
  projects = payload.get('projects') if isinstance(payload, dict) else None
  if not isinstance(projects, list):
    raise PreRepairError('OSS-Fuzz status data has no projects list')
  return [item for item in projects if isinstance(item, dict)]


def _download(url: str, destination: Path) -> None:
  request = urllib.request.Request(url, headers={'User-Agent': 'oss-fuzz-gen'})
  try:
    with urllib.request.urlopen(request, timeout=60) as response:
      content = response.read()
  except Exception as error:  # urllib errors differ by platform.
    raise PreRepairError(f'failed to download {url}: {error}') from error
  destination.parent.mkdir(parents=True, exist_ok=True)
  destination.write_bytes(content)


def _is_key_project(statuses: Iterable[str]) -> bool:
  """Returns whether recent history identifies a newly failing project."""
  recent = list(statuses)[:KEY_RECENT_BUILD_COUNT]
  return 'success' in recent and 'error' in recent


def _latest_log_date(history: Iterable[Any]) -> dt.date | None:
  """Returns the newest valid build-log date present in status history."""
  dates = [
      dt.date.fromisoformat(entry['date'].replace('/', '-'))
      for index, record in enumerate(history)
      if (entry := _build_entry(record, index)) is not None
  ]
  return max(dates) if dates else None


def _build_entry(record: Any, index: int | str) -> dict[str, Any] | None:
  """Converts one status.json build record into a downloadable log entry."""
  if not isinstance(record, dict):
    return None
  build_id = str(record.get('build_id') or '')
  finish_time = str(record.get('finish_time') or '')
  if (not re.fullmatch(r'[A-Za-z0-9-]+', build_id) or len(finish_time) < 10):
    return None
  try:
    log_date = dt.date.fromisoformat(finish_time[:10])
  except ValueError:
    return None
  status = 'success' if record.get('success') else 'error'
  return {
      'index': index,
      'date': log_date.strftime('%Y/%m/%d'),
      'status': status,
      'url': f'{BUILD_LOG_ROOT}/log-{build_id}.txt'
  }


def _select_boundary_entries(
    entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
  """Selects status-boundary logs before their contents are downloaded.

  Error runs keep their earliest entry and success runs keep their first and
  last entries.  A day containing both statuses is retained in full and
  separates the runs on either side.  Multiple builds with the same date and
  status map to one output file, so only the first such entry is considered.
  """
  candidates = list(entries)
  if not any(entry['status'] == 'error' for entry in candidates):
    return []

  by_date: dict[str, dict[str, dict[str, Any]]] = {}
  for entry in candidates:
    log_date = str(entry['date'])
    status = str(entry['status'])
    by_date.setdefault(log_date, {}).setdefault(status, entry)

  selected: list[dict[str, Any]] = []
  segment: list[dict[str, Any]] = []

  def select_segment() -> None:
    index = 0
    while index < len(segment):
      end = index + 1
      while (end < len(segment) and
             segment[end]['status'] == segment[index]['status']):
        end += 1
      run = segment[index:end]
      selected.append(run[0])
      if run[0]['status'] == 'success' and len(run) > 1:
        selected.append(run[-1])
      index = end

  for log_date in sorted(by_date):
    day_entries = by_date[log_date]
    if set(day_entries) == {'success', 'error'}:
      select_segment()
      segment = []
      selected.extend(day_entries[status] for status in ('success', 'error'))
    else:
      segment.extend(day_entries.values())
  select_segment()
  return selected


def acquire_logs(raw_root: Path,
                 projects: Iterable[str] | None = None,
                 mode: str = 'key',
                 now: dt.date | None = None) -> dict[str, Any]:
  """Acquires either recent-transition (key) or all failed-project logs.

  Browser/page failures are collected per project and do not silently become
  metadata.  A total index failure is fatal because it produces no trustworthy
  input set.
  """
  if mode not in ACQUISITION_MODES:
    raise PreRepairError(
        f'unsupported acquisition mode {mode!r}; expected key or all')
  raw_root.mkdir(parents=True, exist_ok=True)
  today = now or dt.datetime.now(dt.timezone.utc).date()
  auto_blacklist_threshold = subtract_calendar_months(today, months=1)
  requested_projects = sorted(set(projects or []))
  if not requested_projects:
    LOGGER.warning(
        'No --pre-repair-project was supplied; scanning every currently '
        'failing project on the OSS-Fuzz status website.')
  status_projects = _status_projects()
  by_name = {
      str(item.get('name')): item
      for item in status_projects
      if item.get('name')
  }
  failure_projects = sorted(
      name for name, item in by_name.items()
      if isinstance(item.get('history'), list) and item['history'] and
      not bool(item['history'][0].get('success')))
  target_projects = requested_projects or failure_projects
  report: dict[str, Any] = {
      'mode':
          mode,
      'failure_project_count':
          len(failure_projects),
      'automatic_blacklist_threshold_date':
          auto_blacklist_threshold.isoformat(),
      'automatic_blacklist_candidates': [],
      'requested_projects':
          requested_projects,
      'selected_projects': [],
      'skipped_projects': {},
      'downloaded': [],
      'project_observations': {},
      'log_errors': [],
      'project_errors': {}
  }
  for project in target_projects:
    try:
      if project in PRE_REPAIR_PROJECT_BLACKLIST:
        report['skipped_projects'][project] = BLACKLIST_REASON
        continue
      project_status = by_name.get(project)
      if project_status is None:
        report['skipped_projects'][project] = 'not present in status.json'
        continue
      if project not in failure_projects:
        report['skipped_projects'][project] = 'project is not currently failing'
        continue
      raw_history = project_status.get('history')
      if not isinstance(raw_history, list):
        raise PreRepairError('project history is not a list')
      latest_log_date = _latest_log_date(raw_history)
      if latest_log_date and latest_log_date < auto_blacklist_threshold:
        report['automatic_blacklist_candidates'].append({
            'project': project,
            'latest_log_date': latest_log_date.isoformat(),
            'threshold_date': auto_blacklist_threshold.isoformat(),
        })
        report['skipped_projects'][project] = AUTO_BLACKLIST_REASON
        continue
      history = [
          entry for index, record in enumerate(raw_history)
          if (entry := _build_entry(record, index)) is not None
      ]
      statuses = [entry['status'] for entry in history]
      report['project_observations'][project] = {
          'raw_history_count': len(raw_history),
          'history_count': len(history),
          'history_statuses': statuses,
      }
      if mode == 'key' and not _is_key_project(statuses):
        report['skipped_projects'][project] = (
            'no success-to-error boundary in the latest seven build records')
        continue
      report['selected_projects'].append(project)
      entries: list[dict[str, Any]] = list(history)
      if mode == 'all':
        last_success = _build_entry(project_status.get('last_successful_build'),
                                    'last-success')
        if last_success:
          last_success['status'] = 'success'
          entries.insert(0, last_success)
      candidate_count = len(entries)
      entries = _select_boundary_entries(entries)
      report['project_observations'][project].update({
          'candidate_log_count': candidate_count,
          'selected_log_count': len(entries),
          'filtered_log_count': candidate_count - len(entries),
      })
      seen: set[tuple[str, str]] = set()
      for entry in entries:
        index = entry.get('index', 'last-success')
        status = entry['status']
        date_name = entry['date'].replace('/', '_') + ' ' + status
        url = entry['url']
        # File names intentionally remain compatible with the downstream
        # boundary selector, which accepts one state per project/day.
        identity = (project, date_name)
        if identity in seen:
          continue
        seen.add(identity)
        destination = raw_root / project / date_name
        try:
          _download(url, destination)
        except PreRepairError as error:
          report['log_errors'].append({
              'project': project,
              'file': date_name,
              'button_index': index,
              'url': url,
              'error': str(error)
          })
          continue
        report['downloaded'].append({
            'project': project,
            'file': date_name,
            'url': url,
            'button_index': index
        })
    except Exception as error:  # Keep independent project failures observable.
      report['project_errors'][project] = f'{type(error).__name__}: {error}'
  if not report['downloaded']:
    raise PreRepairError(
        f'{mode}-log acquisition downloaded no usable log files', report)
  return report


def _run(command: list[str],
         cwd: Path,
         timeout: int = 7200) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command,
                        cwd=cwd,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=timeout,
                        check=False)


def _metadata_from_log(log_path: Path) -> dict[str, Any]:
  """Ports reproduce_note_fuzz's deterministic log extraction."""
  srcmap: list[str] = []
  metadata: dict[str, Any] = {'dependencies': []}
  with log_path.open(encoding='utf-8', errors='ignore') as log:
    for line in log:
      if 'fuzzing_build_error_log' not in metadata:
        uuid = re.search(r'starting build "([a-f0-9-]+)"', line)
        if uuid:
          metadata['fuzzing_build_error_log'] = (
              f'{BUILD_LOG_ROOT}/log-{uuid.group(1)}.txt')
      if 'base_image_digest' not in metadata:
        digest = re.search(r'Digest: sha256:([a-f0-9]{64})', line)
        if digest:
          metadata['base_image_digest'] = digest.group(1)
      if 'engine' not in metadata and 'Starting Step #3 - "compile-' in line:
        match = COMPILE_CONFIG.search(line)
        if match:
          metadata.update(engine=match.group(1),
                          sanitizer=match.group(2),
                          architecture=match.group(3))
      if 'Step #2 - "srcmap"' in line:
        srcmap.append(line)
  project = log_path.parent.name
  target = f'/src/{project}'
  starts = [index for index, line in enumerate(srcmap) if target in line]
  candidates = (srcmap[starts[-1]:starts[-1] + 4] if starts else srcmap[-7:])
  url = next((match.group(1)
              for line in candidates
              if (match := re.search(r'"url":\s*["\']([^"\']+)', line))), '')
  sha = next((match.group(1)
              for line in candidates
              if (match := re.search(r'"rev":\s*["\']([^"\']+)', line))), '')
  if url:
    metadata['software_repo_url'] = url
  if sha:
    metadata['software_sha'] = sha
  dependencies: list[dict[str, str]] = []
  for index, line in enumerate(srcmap):
    url_match = re.search(r'"url":\s*["\']([^"\']+)', line)
    if not url_match:
      continue
    revision = ''
    for nearby in srcmap[max(0, index - 3):index + 4]:
      revision_match = re.search(r'"rev":\s*["\']([^"\']+)', nearby)
      if revision_match:
        revision = revision_match.group(1)
        break
    item = {'url': url_match.group(1), 'rev': revision}
    if revision and item not in dependencies:
      dependencies.append(item)
  metadata['dependencies'] = [
      item for item in dependencies
      if item['url'] != metadata.get('software_repo_url')
  ][:50]
  return metadata


def _ordered_metadata(entry: dict[str, Any],
                      include_last_success: bool = False) -> dict[str, Any]:
  """Returns only public metadata fields in the canonical schema order."""
  fields: list[str] = list(METADATA_FIELD_ORDER)
  if include_last_success:
    fields.insert(fields.index(OSS_FUZZ_SHA_FIELD), 'last_success_time')
  unexpected = set(entry) - set(fields) - {'dependencies'}
  if unexpected:
    raise PreRepairError('unsupported public metadata fields: ' +
                         ', '.join(sorted(unexpected)))
  return {field: entry[field] for field in fields if field in entry}


def _project_language(oss_fuzz: Path, project: str) -> str:
  project_yaml = oss_fuzz / 'projects' / project / 'project.yaml'
  if not project_yaml.is_file():
    return ''
  data = yaml.safe_load(project_yaml.read_text(encoding='utf-8')) or {}
  return str(data.get('language') or '')


def _parse_commit_lines(lines: str) -> list[dict[str, str]]:
  """Parses ``git log --format=%cI%x09%H`` output deterministically."""
  commits: list[dict[str, str]] = []
  for line in lines.splitlines():
    timestamp, separator, sha = line.partition('\t')
    if separator and timestamp and sha:
      commits.append({'timestamp_utc': timestamp, 'sha': sha})
  return commits


def build_commit_mapping(oss_fuzz_source: Path, workspace: Path, start: dt.date,
                         end: dt.date) -> list[dict[str, str]]:
  """Builds the dynamic three-calendar-month OSS-Fuzz SHA mapping.

  One commit immediately before the interval is retained as an anchor.  This
  preserves reproduce_note_fuzz's strict ``commit_date < error_date`` lookup
  without broadening the requested dynamic coverage window.
  """
  checkout = workspace / 'commit-mapping-oss-fuzz'
  _copy_oss_fuzz(oss_fuzz_source, checkout)
  remote = _run(['git', 'remote', 'set-url', 'origin', OSS_FUZZ_UPSTREAM_URL],
                checkout)
  if remote.returncode:
    raise PreRepairError('failed to configure official OSS-Fuzz remote: ' +
                         remote.stdout[-1000:])
  fetch = _run([
      'git', 'fetch', '--force',
      f'--shallow-since={start.isoformat()}T00:00:00Z', 'origin',
      '+refs/heads/master:refs/remotes/origin/master'
  ],
               checkout,
               timeout=1800)
  if fetch.returncode:
    raise PreRepairError('failed to fetch OSS-Fuzz commit window: ' +
                         fetch.stdout[-1000:])
  shallow = _run(['git', 'rev-parse', '--is-shallow-repository'], checkout)
  if shallow.returncode:
    raise PreRepairError('failed to inspect OSS-Fuzz checkout history: ' +
                         shallow.stdout[-1000:])
  if shallow.stdout.strip() == 'true':
    anchor_fetch = _run(['git', 'fetch', '--deepen=1', 'origin', 'master'],
                        checkout,
                        timeout=600)
    if anchor_fetch.returncode:
      raise PreRepairError('failed to fetch OSS-Fuzz mapping anchor: ' +
                           anchor_fetch.stdout[-1000:])
  range_result = _run([
      'git', 'log', '--format=%cI%x09%H',
      f'--since={start.isoformat()}T00:00:00Z',
      f'--until={end.isoformat()}T23:59:59Z', 'origin/master'
  ],
                      checkout,
                      timeout=300)
  if range_result.returncode:
    raise PreRepairError('failed to create OSS-Fuzz commit mapping: ' +
                         range_result.stdout[-1000:])
  anchor_result = _run([
      'git', 'log', '-1', '--format=%cI%x09%H',
      f'--before={start.isoformat()}T00:00:00Z', 'origin/master'
  ],
                       checkout,
                       timeout=120)
  if anchor_result.returncode:
    raise PreRepairError('failed to obtain OSS-Fuzz mapping anchor: ' +
                         anchor_result.stdout[-1000:])
  commits = _parse_commit_lines(anchor_result.stdout)
  commits.extend(_parse_commit_lines(range_result.stdout))
  commits.sort(key=lambda item: item['timestamp_utc'])
  if not commits:
    raise PreRepairError('dynamic OSS-Fuzz commit mapping is empty')
  return commits


def _commit_for_date(commit_mapping: Iterable[dict[str, str]],
                     error_date: dt.date) -> dict[str, str] | None:
  """Returns the latest mapped commit strictly before the log's error date."""
  candidates: list[dict[str, str]] = []
  for item in commit_mapping:
    try:
      commit_date = dt.datetime.fromisoformat(item['timestamp_utc'].replace(
          'Z', '+00:00')).date()
    except (KeyError, ValueError):
      continue
    if commit_date < error_date:
      candidates.append(item)
  return candidates[-1] if candidates else None


def _checkout_for_date(commit_mapping: Iterable[dict[str, str]],
                       error_date: dt.date) -> str:
  """Returns the SHA for the historical commit selected for an error date."""
  commit = _commit_for_date(commit_mapping, error_date)
  return commit['sha'] if commit else ''


def _copy_oss_fuzz(source: Path, destination: Path) -> None:
  """Copies the OSS-Fuzz checkout into an isolated working directory."""
  source = source.resolve()
  destination = destination.resolve()
  if destination.exists():
    shutil.rmtree(destination)
  destination.parent.mkdir(parents=True, exist_ok=True)
  result = _run(
      ['git', 'clone', '--no-hardlinks',
       str(source),
       str(destination)],
      destination.parent,
      timeout=1800)
  if result.returncode:
    raise PreRepairError(
        f'failed to create isolated oss-fuzz checkout: {result.stdout[-1000:]}')


def _tail(path: Path, count: int = 30) -> str:
  if not path.is_file():
    return ''
  with path.open(encoding='utf-8', errors='ignore') as data:
    return ''.join(deque(data, maxlen=count))


def _patch_reproduction_dockerfile(dockerfile: Path, digest: str,
                                   dependencies: list[dict[str, str]]) -> str:
  """Pins the image and clone revisions as reproduce_note_fuzz does.

  The returned text must be restored after each reproduction, even when the
  build fails, because the checkout remains archived as diagnostic evidence.
  """
  original = dockerfile.read_text(encoding='utf-8')
  changed = False
  patched_lines: list[str] = []
  for line in original.splitlines(keepends=True):
    stripped = line.strip()
    if stripped.startswith('FROM ') and 'oss-fuzz-base' in stripped:
      image = stripped.split()[1].split('@')[0]
      # A digest replaces a tag. This follows the original reproducer rather
      # than constructing an invalid tag@digest reference.
      image = image.rsplit(':', 1)[0] if ':' in image.rsplit('/',
                                                             1)[-1] else image
      line = f'FROM {image}@sha256:{digest}\n'
      changed = True
    elif stripped.startswith('RUN') and 'git clone' in stripped:
      for dependency in dependencies:
        normalized = dependency['url'].removeprefix('https://').removeprefix(
            'http://').removesuffix('.git')
        if normalized and normalized in line:
          target = dependency['url'].rstrip('/').split('/')[-1].removesuffix(
              '.git')
          line = line.replace('--depth 1', '').replace('--depth=1', '')
          suffix = ' \\\n' if line.rstrip().endswith('\\') else '\n'
          line = line.rstrip().rstrip('\\').rstrip()
          checkout = f' && cd {target} && git checkout {dependency["rev"]}'
          line += f'{checkout} && cd -{suffix}'
          changed = True
          break
    patched_lines.append(line)
  if not changed:
    raise PreRepairError(
        'Dockerfile had no patchable OSS-Fuzz base image or dependency')
  dockerfile.write_text(''.join(patched_lines), encoding='utf-8')
  return original


def _vertex_model_name(model: str) -> str:
  """Uses the same public model aliases as the full fix-build integration."""
  aliases = {
      'vertex_ai_gemini-pro': 'gemini-1.0-pro',
      'vertex_ai_gemini-2-flash': 'gemini-2.0-flash-001',
      'vertex_ai_gemini-2-5-flash': 'gemini-2.5-flash',
      'vertex_ai_gemini-2-5-pro': 'gemini-2.5-pro',
      'vertex_ai_gemini-3-flash': 'gemini-3-flash-preview',
      'vertex_ai_gemini-3-pro': 'gemini-3-pro-preview',
      'vertex_ai_gemini-3-1-pro': 'gemini-3.1-pro-preview',
  }
  return aliases.get(model.lower(),
                     model.removeprefix('vertex_ai/').replace('_', '-'))


def _vertex_match(model: str, original_tail: str,
                  reproduced_tail: str) -> dict[str, Any]:
  """Uses Vertex to decide whether reproduction errors are equivalent."""
  from google import genai
  from google.auth import default
  _, project_id = default()
  if not project_id:
    raise PreRepairError('Vertex ADC did not provide a Google Cloud project')
  location = (os.getenv('VERTEX_LOCATION') or
              os.getenv('VERTEX_AI_LOCATIONS', 'global').split(',')[0])
  client = genai.Client(vertexai=True, project=project_id, location=location)
  original_excerpt = original_tail[-12000:]
  reproduced_excerpt = reproduced_tail[-12000:]
  prompt = ('Compare these two OSS-Fuzz build failure tails. Reply only JSON '
            'with keys matches (boolean) and error_category (RC1..RC25). '
            'Treat incidental paths, timestamps, and line numbers as equal.\n'
            f'ORIGINAL:\n{original_excerpt}\nREPRODUCED:\n{reproduced_excerpt}')
  response = client.models.generate_content(model=_vertex_model_name(model),
                                            contents=prompt)
  text = response.text or ''
  match = re.search(r'\{.*\}', text, re.DOTALL)
  if not match:
    raise PreRepairError(
        'Vertex reproduction classifier returned non-JSON output')
  parsed = json.loads(match.group(0))
  if not isinstance(parsed.get('matches'), bool):
    raise PreRepairError(
        'Vertex reproduction classifier omitted boolean matches')
  category = str(parsed.get('error_category') or 'RC17')
  return {'matches': parsed['matches'], 'error_category': category}


def _vertex_classify(model: str, log_tail: str) -> str:
  """Classifies one original OSS-Fuzz failure without reproducing it."""
  from google import genai
  from google.auth import default
  _, project_id = default()
  if not project_id:
    raise PreRepairError('Vertex ADC did not provide a Google Cloud project')
  location = (os.getenv('VERTEX_LOCATION') or
              os.getenv('VERTEX_AI_LOCATIONS', 'global').split(',')[0])
  client = genai.Client(vertexai=True, project=project_id, location=location)
  prompt = ('Classify this OSS-Fuzz build failure. Reply only JSON with key '
            'error_category whose value is RC1..RC25.\n'
            f'BUILD FAILURE:\n{log_tail[-12000:]}')
  response = client.models.generate_content(model=_vertex_model_name(model),
                                            contents=prompt)
  match = re.search(r'\{.*\}', response.text or '', re.DOTALL)
  if not match:
    raise PreRepairError('Vertex error classifier returned non-JSON output')
  parsed = json.loads(match.group(0))
  return str(parsed.get('error_category') or 'RC17')


def _project_language_at_commit(oss_fuzz: Path, project: str, sha: str) -> str:
  """Reads a historical project language without changing the checkout."""
  result = _run(['git', 'show', f'{sha}:projects/{project}/project.yaml'],
                oss_fuzz)
  if result.returncode:
    return ''
  data = yaml.safe_load(result.stdout) or {}
  return str(data.get('language') or '')


def _extract_one(
    log_path: Path, oss_fuzz_source: Path, model: str,
    commit_mapping: Iterable[dict[str, str]]
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
  """Extracts complete repair metadata without rebuilding the project."""
  parsed = parse_log_name(log_path)
  assert parsed is not None
  project = log_path.parent.name
  evidence: dict[str, Any] = {
      'project': project,
      'log': str(log_path),
      'status': 'extracting'
  }
  try:
    metadata = _metadata_from_log(log_path)
    prior_success = ''
    for candidate in log_path.parent.glob('* success'):
      parsed_success = parse_log_name(candidate)
      if parsed_success and parsed_success.log_date < parsed.log_date:
        prior_success = max(prior_success, parsed_success.log_date.isoformat())
    selected_commit = _commit_for_date(commit_mapping, parsed.log_date)
    if not selected_commit:
      raise PreRepairError('no OSS-Fuzz commit in the dynamic mapping before '
                           f'{parsed.log_date}')
    oss_fuzz_sha = selected_commit['sha']
    language = _project_language_at_commit(oss_fuzz_source, project,
                                           oss_fuzz_sha)
    if not language:
      raise PreRepairError(
          f'project.yaml unavailable for {project} at {oss_fuzz_sha}')
    public_log_metadata = dict(metadata)
    public_log_metadata.pop('dependencies', None)
    evidence['original_metadata'] = _ordered_metadata(
        {
            'project': project,
            'language': language,
            'error_time': parsed.log_date.isoformat(),
            'last_success_time': prior_success,
            OSS_FUZZ_SHA_FIELD: oss_fuzz_sha,
            **public_log_metadata,
        },
        include_last_success=True)
    evidence.update(
        oss_fuzz_commit_timestamp_utc=selected_commit['timestamp_utc'],
        oss_fuzz_selection_rule='latest commit strictly before error date')
    try:
      error_category = _vertex_classify(model, _tail(log_path))
    except Exception as error:  # Classification is advisory in deployment.
      error_category = 'RC17'
      evidence['classification_error'] = f'{type(error).__name__}: {error}'
    final_metadata = dict(evidence['original_metadata'])
    final_metadata.pop('last_success_time', None)
    entry = _ordered_metadata({
        **final_metadata,
        'error_category': error_category,
        'fixed_state': 'no',
    })
    evidence['status'] = 'metadata_extracted'
    return entry, evidence
  except (PreRepairError, subprocess.TimeoutExpired) as error:
    evidence.update(status='error', error=f'{type(error).__name__}: {error}')
    return None, evidence


def _reproduce_one(
    log_path: Path, oss_fuzz_source: Path, workspace: Path, model: str,
    commit_mapping: Iterable[dict[str, str]]
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
  """Runs the full reproduction sequence from reproduce_note_fuzz.

  The original project cloned source, checked out the historical commits,
  patched the base image/dependencies and built fuzzers.  This function keeps
  those side effects in a per-log directory.  Vertex comparison is retained
  as diagnostic evidence but does not gate otherwise complete metadata.
  """
  parsed = parse_log_name(log_path)
  assert parsed is not None
  project = log_path.parent.name
  evidence: dict[str, Any] = {
      'project': project,
      'log': str(log_path),
      'status': 'started'
  }
  metadata = _metadata_from_log(log_path)
  prior_success = ''
  for candidate in log_path.parent.glob('* success'):
    parsed_success = parse_log_name(candidate)
    if parsed_success and parsed_success.log_date < parsed.log_date:
      prior_success = max(prior_success, parsed_success.log_date.isoformat())
  public_log_metadata = dict(metadata)
  public_log_metadata.pop('dependencies', None)
  evidence['original_metadata'] = _ordered_metadata(
      {
          'project': project,
          'error_time': parsed.log_date.isoformat(),
          'last_success_time': prior_success,
          **public_log_metadata,
      },
      include_last_success=True)
  isolated = workspace / project / parsed.log_date.isoformat() / 'oss-fuzz'
  try:
    _copy_oss_fuzz(oss_fuzz_source, isolated)
    selected_commit = _commit_for_date(commit_mapping, parsed.log_date)
    if not selected_commit:
      raise PreRepairError('no OSS-Fuzz commit in the dynamic mapping before '
                           f'{parsed.log_date}')
    oss_fuzz_sha = selected_commit['sha']
    checkout = _run(['git', 'checkout', '--detach', oss_fuzz_sha],
                    isolated,
                    timeout=300)
    if checkout.returncode:
      raise PreRepairError(
          f'cannot checkout {oss_fuzz_sha}: {checkout.stdout[-1000:]}')
    language = _project_language(isolated, project)
    if not language:
      raise PreRepairError(
          f'project.yaml unavailable for {project} at {oss_fuzz_sha}')
    evidence['original_metadata'] = _ordered_metadata(
        {
            **evidence['original_metadata'],
            'language': language,
            OSS_FUZZ_SHA_FIELD: oss_fuzz_sha,
        },
        include_last_success=True)
    evidence.update(
        oss_fuzz_commit_timestamp_utc=selected_commit['timestamp_utc'],
        oss_fuzz_selection_rule='latest commit strictly before error date')
    repo_url = str(metadata.get('software_repo_url') or '')
    source_sha = str(metadata.get('software_sha') or '')
    source_dir = workspace / project / parsed.log_date.isoformat() / 'source'
    clone = _run(
        ['git', 'clone', repo_url, str(source_dir)], workspace, timeout=1800)
    if clone.returncode:
      raise PreRepairError(f'upstream clone failed: {clone.stdout[-1000:]}')
    source_checkout = _run(['git', 'checkout', '--detach', source_sha],
                           source_dir,
                           timeout=600)
    if source_checkout.returncode:
      raise PreRepairError(
          f'upstream checkout failed: {source_checkout.stdout[-1000:]}')
    # Lock the base image and source-map dependency clones exactly as
    # reproduce_note_fuzz.patch_project_dockerfile does.
    dockerfile = isolated / 'projects' / project / 'Dockerfile'
    if not dockerfile.is_file():
      raise PreRepairError('project Dockerfile unavailable')
    digest = str(metadata.get('base_image_digest') or '')
    original_dockerfile = _patch_reproduction_dockerfile(
        dockerfile, digest, list(metadata.get('dependencies') or []))
    log_file = workspace / project / parsed.log_date.isoformat(
    ) / 'reproduce.log'
    try:
      image = _run(
          ['python3', 'infra/helper.py', 'build_image', '--no-pull', project],
          isolated)
      fuzz = _run([
          'python3', 'infra/helper.py', 'build_fuzzers', project,
          str(source_dir), '--sanitizer',
          str(metadata.get('sanitizer', '')), '--engine',
          str(metadata.get('engine', '')), '--architecture',
          str(metadata.get('architecture', ''))
      ], isolated)
      log_file.parent.mkdir(parents=True, exist_ok=True)
      log_file.write_text(image.stdout + '\n' + fuzz.stdout, encoding='utf-8')
    finally:
      # Always restore before the temporary checkout is retained as evidence.
      dockerfile.write_text(original_dockerfile, encoding='utf-8')
    verdict = _vertex_match(model, _tail(log_path), _tail(log_file))
    evidence.update(status='reproduced',
                    build_return_code=fuzz.returncode,
                    vertex_verdict=verdict,
                    reproduce_log=str(log_file))
    extracted_metadata = {}
    for key in REQUIRED_METADATA:
      if key != OSS_FUZZ_SHA_FIELD:
        extracted_metadata[key] = metadata.get(key, '')
    entry = _ordered_metadata({
        'project': project,
        'language': language,
        'error_time': parsed.log_date.isoformat(),
        OSS_FUZZ_SHA_FIELD: oss_fuzz_sha,
        **extracted_metadata, 'error_category': verdict['error_category'],
        'fixed_state': 'no'
    })
    evidence['status'] = ('verified' if verdict['matches'] else
                          'accepted_with_reproduction_mismatch')
    return entry, evidence
  except (PreRepairError, subprocess.TimeoutExpired) as error:
    evidence.update(status='error', error=f'{type(error).__name__}: {error}')
    return None, evidence


def _valid_entry(entry: dict[str, Any]) -> list[str]:
  return [
      field for field in REQUIRED_METADATA
      if not str(entry.get(field) or '').strip()
  ]


def _pre_repair_root(work_dir: str) -> Path:
  root = Path(work_dir) / 'pre_repair'
  root.mkdir(parents=True, exist_ok=True)
  return root


def _write_manifest(root: Path, manifest: dict[str, Any]) -> None:
  (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n',
                                      encoding='utf-8')


def _write_blacklist_suggestions(root: Path, acquisition: dict[str,
                                                               Any]) -> None:
  """Writes run-local candidates for a deliberate static-blacklist update.

  The acquisition path skips stale projects immediately, but the repository's
  static blacklist remains a reviewed source change.  This artifact makes that
  distinction explicit and remains available even if every requested project
  was skipped, causing acquisition to fail for lack of downloadable logs.
  """
  payload = {
      'manual_git_commit_required': True,
      'rule': ('latest valid OSS-Fuzz build-log date is strictly older than '
               'one calendar month before the acquisition date'),
      'threshold_date': acquisition.get('automatic_blacklist_threshold_date'),
      'projects': acquisition.get('automatic_blacklist_candidates', []),
  }
  (root / BLACKLIST_SUGGESTIONS_FILE).write_text(yaml.safe_dump(
      payload, sort_keys=False),
                                                 encoding='utf-8')


def run_log_acquisition(work_dir: str,
                        projects: Iterable[str] | None = None,
                        mode: str = 'key',
                        now: dt.date | None = None) -> Path:
  """Acquires OSS-Fuzz logs and returns the durable acquired-log directory."""
  root = _pre_repair_root(work_dir)
  raw = root / LOG_ROOT_NAME
  if raw.exists():
    shutil.rmtree(raw)
  manifest: dict[str, Any] = {'status': 'acquiring', 'errors': []}
  try:
    manifest['acquisition'] = acquire_logs(raw, projects, mode, now)
    manifest['status'] = 'acquired'
    return raw
  except PreRepairError as error:
    if error.report is not None:
      manifest['acquisition'] = error.report
    manifest.update(status='failed',
                    errors=[f'{type(error).__name__}: {error}'])
    raise
  except Exception as error:
    manifest.update(status='failed',
                    errors=[f'{type(error).__name__}: {error}'])
    raise
  finally:
    acquisition = manifest.get('acquisition')
    if isinstance(acquisition, dict):
      _write_blacklist_suggestions(root, acquisition)
    _write_manifest(root, manifest)


def run_reproduction_and_extraction(work_dir: str,
                                    oss_fuzz_source: str,
                                    model: str,
                                    log_directory: str,
                                    projects: Iterable[str] | None = None,
                                    now: dt.date | None = None,
                                    verify_reproduction: bool = False) -> Path:
  """Extracts metadata, optionally reproducing historical build failures."""
  today = now or dt.datetime.now(dt.timezone.utc).date()
  start = subtract_calendar_months(today)
  root = _pre_repair_root(work_dir)
  raw = Path(log_directory)
  if not raw.is_dir():
    raise PreRepairError(f'pre-repair log directory does not exist: {raw}')
  filtered_logs = root / 'selected_logs'
  previous_manifest: dict[str, Any] = {}
  manifest_path = root / 'manifest.json'
  if manifest_path.is_file():
    try:
      previous_manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
      # A corrupt prior manifest must not prevent a fresh extraction, but the
      # new manifest records only artifacts produced by this invocation.
      previous_manifest = {}
  for output_path in (filtered_logs, root / 'metadata', root / 'benchmarks',
                      root / 'reproduction_workspace'):
    if output_path.exists():
      shutil.rmtree(output_path)
  manifest: dict[str, Any] = {
      'status': 'extracting',
      'log_directory': str(raw),
      'requested_projects': sorted(set(projects or [])),
      'commit_mapping_window_start': start.isoformat(),
      'commit_mapping_window_end': today.isoformat(),
      'errors': []
  }
  if 'acquisition' in previous_manifest:
    manifest['acquisition'] = previous_manifest['acquisition']
  try:
    selection = filter_log_tree(raw, filtered_logs, projects)
    manifest['selection'] = selection
    if selection.get('missing_projects'):
      manifest['unavailable_requested_projects'] = selection['missing_projects']
      LOGGER.warning(
          'Requested projects absent from the acquired log input; continuing '
          'with available projects: %s',
          ', '.join(selection['missing_projects']))
    if not selection['copied_count']:
      raise PreRepairError('log selection produced no eligible error logs')
    entries: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix='oss-fuzz-gen-pre-repair-') as temp:
      mapping_workspace = Path(temp)
      commit_mapping = build_commit_mapping(Path(oss_fuzz_source),
                                            mapping_workspace, start, today)
      prepared_oss_fuzz = mapping_workspace / 'commit-mapping-oss-fuzz'
      (root / 'oss_fuzz_commit_mapping.json').write_text(json.dumps(
          {
              'window_start': start.isoformat(),
              'window_end': today.isoformat(),
              'commits': commit_mapping,
          },
          indent=2) + '\n',
                                                         encoding='utf-8')
      manifest['commit_mapping_entry_count'] = len(commit_mapping)
      manifest['reproduction_verification_enabled'] = verify_reproduction
      for log_path in sorted(filtered_logs.glob('*/* error')):
        if verify_reproduction:
          entry, detail = _reproduce_one(log_path, prepared_oss_fuzz,
                                         mapping_workspace, model,
                                         commit_mapping)
        else:
          entry, detail = _extract_one(log_path, prepared_oss_fuzz, model,
                                       commit_mapping)
        evidence.append(detail)
        if entry is None:
          rejected.append({
              'project': log_path.parent.name,
              'log': str(log_path),
              'reason': detail.get('error', detail['status'])
          })
          continue
        missing = _valid_entry(entry)
        if missing:
          rejected.append({
              'project': entry.get('project', ''),
              'reason': 'missing required metadata',
              'missing': missing,
              'entry': entry
          })
          continue
        entries.append(entry)
    (root / 'metadata').mkdir()
    original_entries = [
        _ordered_metadata(item['original_metadata'], include_last_success=True)
        for item in evidence
        if 'original_metadata' in item
    ]
    (root / 'metadata' / 'original.yaml').write_text(yaml.safe_dump(
        original_entries, sort_keys=False),
                                                     encoding='utf-8')
    # last_success_time is intentionally never constructed in the final schema.
    (root / 'metadata' / 'filtered.yaml').write_text(yaml.safe_dump(
        entries, sort_keys=False),
                                                     encoding='utf-8')
    (root / 'metadata' / 'rejected.yaml').write_text(yaml.safe_dump(
        rejected, sort_keys=False),
                                                     encoding='utf-8')
    evidence_name = ('reproduction-evidence.json'
                     if verify_reproduction else 'extraction-evidence.json')
    (root / evidence_name).write_text(json.dumps(evidence, indent=2) + '\n',
                                      encoding='utf-8')
    benchmark_dir = root / 'benchmarks'
    benchmark_dir.mkdir()
    for entry in entries:
      (benchmark_dir / f"{entry['project']}.yaml").write_text(yaml.safe_dump(
          entry, sort_keys=False),
                                                              encoding='utf-8')
    if not entries:
      raise PreRepairError('no acquired project passed metadata validation')
    manifest.update(
        status='completed',
        accepted_projects=len(entries),
        metadata_extracted_projects=len(entries),
        rejected_projects=len(rejected),
        benchmark_directory=str(benchmark_dir),
        evidence_path=str(root / evidence_name),
        reproduction_verification_status=('completed' if verify_reproduction
                                          else 'not_requested'))
    if verify_reproduction:
      manifest['verified_projects'] = sum(
          detail.get('vertex_verdict', {}).get('matches') is True
          for detail in evidence)
  except Exception as error:  # The manifest remains useful for failed runs.
    manifest.update(status='failed',
                    errors=[f'{type(error).__name__}: {error}'])
    raise
  finally:
    _write_manifest(root, manifest)
  return benchmark_dir


def run_pre_repair(work_dir: str,
                   oss_fuzz_source: str,
                   model: str,
                   projects: Iterable[str] | None = None,
                   now: dt.date | None = None) -> Path:
  """Compatibility wrapper for the original acquire-then-extract workflow."""
  acquired_logs = run_log_acquisition(work_dir, projects)
  return run_reproduction_and_extraction(work_dir, oss_fuzz_source, model,
                                         str(acquired_logs), projects, now)
