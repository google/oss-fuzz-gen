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
"""Unit tests for the deterministic pre-repair safety boundary."""

import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from experimental.build_fixer import pre_repair


class PreRepairSelectionTest(unittest.TestCase):

  def test_key_project_requires_success_and_error_in_latest_seven(self):
    self.assertTrue(
        pre_repair._is_key_project(['error', 'error', 'success', 'error']))
    self.assertFalse(pre_repair._is_key_project(['error'] * 7 + ['success']))
    self.assertFalse(pre_repair._is_key_project(['success'] * 7))

  def test_acquisition_rejects_unknown_mode_before_browser_access(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      with self.assertRaisesRegex(pre_repair.PreRepairError,
                                  'unsupported acquisition mode'):
        pre_repair.acquire_logs(Path(temp_dir), ['cups-filters'], 'unknown')

  def test_zero_download_error_preserves_acquisition_diagnostics(self):
    status = {'name': 'airflow', 'history': [{}]}
    with tempfile.TemporaryDirectory() as temp_dir:
      with mock.patch.object(pre_repair,
                             '_status_projects',
                             return_value=[status]), self.assertRaises(
                                 pre_repair.PreRepairError) as raised:
        pre_repair.acquire_logs(Path(temp_dir), ['airflow'], 'all')
    report = raised.exception.report
    self.assertIsNotNone(report)
    assert report is not None
    self.assertEqual(report['selected_projects'], ['airflow'])
    self.assertEqual(report['downloaded'], [])
    self.assertEqual(report['project_observations']['airflow']['history_count'],
                     0)

  def test_all_mode_builds_log_urls_directly_from_status_data(self):
    status = {
        'name': 'airflow',
        'history': [{
            'build_id': 'failure-id',
            'finish_time': '2026-09-21T06:20:11Z',
            'success': False
        }],
        'last_successful_build': {
            'build_id': 'success-id',
            'finish_time': '2026-03-23T07:11:41Z'
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects',
        return_value=[status]), mock.patch.object(pre_repair,
                                                  '_download') as download:
      report = pre_repair.acquire_logs(Path(temp_dir), ['airflow'], 'all')
    self.assertEqual(len(report['downloaded']), 2)
    self.assertEqual(report['failure_project_count'], 1)
    self.assertNotIn('failure_projects', report)
    self.assertEqual({call.args[0] for call in download.call_args_list}, {
        pre_repair.BUILD_LOG_ROOT + '/log-failure-id.txt',
        pre_repair.BUILD_LOG_ROOT + '/log-success-id.txt'
    })

  def test_acquisition_skips_blacklisted_project_and_continues(self):
    failure = {
        'history': [{
            'build_id': 'failure-id',
            'finish_time': '2026-09-21T06:20:11Z',
            'success': False
        }]
    }
    statuses = [{'name': 'tint', **failure}, {'name': 'airflow', **failure}]
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects',
        return_value=statuses), mock.patch.object(pre_repair,
                                                  '_download') as download:
      report = pre_repair.acquire_logs(Path(temp_dir), ['tint', 'airflow'],
                                       'all')

    self.assertEqual(report['skipped_projects']['tint'],
                     pre_repair.BLACKLIST_REASON)
    self.assertEqual(report['selected_projects'], ['airflow'])
    self.assertEqual(download.call_count, 1)

  def test_acquisition_auto_blacklists_stale_project_and_continues(self):
    statuses = [{
        'name':
            'stale-project',
        'history': [{
            'build_id': 'stale-failure',
            'finish_time': '2026-08-22T06:20:11Z',
            'success': False,
        }],
    }, {
        'name':
            'airflow',
        'history': [{
            'build_id': 'fresh-failure',
            'finish_time': '2026-09-22T06:20:11Z',
            'success': False,
        }],
    }]
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects',
        return_value=statuses), mock.patch.object(pre_repair,
                                                  '_download') as download:
      report = pre_repair.acquire_logs(Path(temp_dir),
                                       ['stale-project', 'airflow'],
                                       'all',
                                       now=dt.date(2026, 9, 23))

    self.assertEqual(report['skipped_projects']['stale-project'],
                     pre_repair.AUTO_BLACKLIST_REASON)
    self.assertEqual(report['automatic_blacklist_candidates'], [{
        'project': 'stale-project',
        'latest_log_date': '2026-08-22',
        'threshold_date': '2026-08-23',
    }])
    self.assertEqual(report['selected_projects'], ['airflow'])
    self.assertEqual(download.call_count, 1)

  def test_auto_blacklist_keeps_exact_one_calendar_month_boundary(self):
    status = {
        'name':
            'airflow',
        'history': [{
            'build_id': 'boundary-failure',
            'finish_time': '2026-08-23T06:20:11Z',
            'success': False,
        }],
    }
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects',
        return_value=[status]), mock.patch.object(pre_repair, '_download'):
      report = pre_repair.acquire_logs(Path(temp_dir), ['airflow'],
                                       'all',
                                       now=dt.date(2026, 9, 23))

    self.assertEqual(report['automatic_blacklist_candidates'], [])
    self.assertEqual(report['selected_projects'], ['airflow'])

  def test_acquisition_writes_blacklist_suggestions_when_all_stale(self):
    status = {
        'name':
            'stale-project',
        'history': [{
            'build_id': 'stale-failure',
            'finish_time': '2026-08-22T06:20:11Z',
            'success': False,
        }],
    }
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects', return_value=[status]):
      with self.assertRaises(pre_repair.PreRepairError):
        pre_repair.run_log_acquisition(temp_dir, ['stale-project'],
                                       'all',
                                       now=dt.date(2026, 9, 23))
      suggestions = yaml.safe_load(
          (Path(temp_dir) / 'pre_repair' /
           pre_repair.BLACKLIST_SUGGESTIONS_FILE).read_text(encoding='utf-8'))

    self.assertTrue(suggestions['manual_git_commit_required'])
    self.assertEqual(suggestions['threshold_date'], '2026-08-23')
    self.assertEqual(suggestions['projects'][0]['project'], 'stale-project')

  def test_all_mode_filters_continuous_errors_before_download(self):
    history = [{
        'build_id': f'failure-{day}',
        'finish_time': f'2026-09-{day:02d}T06:20:11Z',
        'success': False
    } for day in range(21, 14, -1)]
    status = {
        'name': 'airflow',
        'history': history,
        'last_successful_build': {
            'build_id': 'success-id',
            'finish_time': '2026-03-23T07:11:41Z',
            'success': True
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects',
        return_value=[status]), mock.patch.object(pre_repair,
                                                  '_download') as download:
      report = pre_repair.acquire_logs(Path(temp_dir), ['airflow'], 'all')

    self.assertEqual([item['file'] for item in report['downloaded']],
                     ['2026_03_23 success', '2026_09_15 error'])
    self.assertEqual(download.call_count, 2)
    observation = report['project_observations']['airflow']
    self.assertEqual(observation['candidate_log_count'], 8)
    self.assertEqual(observation['selected_log_count'], 2)
    self.assertEqual(observation['filtered_log_count'], 6)

  def test_pre_download_filter_keeps_success_edges_and_day_collision(self):

    def entry(day, status):
      return {'date': f'2026/09/{day:02d}', 'status': status}

    candidates = [
        entry(10, 'success'),
        entry(11, 'success'),
        entry(12, 'error'),
        entry(12, 'success'),
        entry(13, 'success'),
        entry(14, 'success'),
    ]
    selected = pre_repair._select_boundary_entries(candidates)
    self.assertEqual([(item['date'], item['status']) for item in selected], [
        ('2026/09/10', 'success'),
        ('2026/09/11', 'success'),
        ('2026/09/12', 'success'),
        ('2026/09/12', 'error'),
        ('2026/09/13', 'success'),
        ('2026/09/14', 'success'),
    ])

  def test_pre_download_filter_drops_project_with_only_successes(self):
    candidates = [
        {
            'date': '2026/09/10',
            'status': 'success'
        },
        {
            'date': '2026/09/11',
            'status': 'success'
        },
    ]
    self.assertEqual(pre_repair._select_boundary_entries(candidates), [])

  def test_pre_download_filter_discovers_multiple_dynamic_runs(self):
    candidates = [
        {
            'date': '2026/01/03',
            'status': 'error'
        },
        {
            'date': '2026/01/08',
            'status': 'error'
        },
        {
            'date': '2026/02/14',
            'status': 'success'
        },
        {
            'date': '2026/04/01',
            'status': 'success'
        },
        {
            'date': '2026/07/19',
            'status': 'error'
        },
        {
            'date': '2026/08/30',
            'status': 'error'
        },
    ]
    selected = pre_repair._select_boundary_entries(reversed(candidates))
    self.assertEqual([(item['date'], item['status']) for item in selected], [
        ('2026/01/03', 'error'),
        ('2026/02/14', 'success'),
        ('2026/04/01', 'success'),
        ('2026/07/19', 'error'),
    ])

  def test_calendar_window_matches_requested_example(self):
    self.assertEqual(pre_repair.subtract_calendar_months(dt.date(2026, 9, 20)),
                     dt.date(2026, 6, 20))
    self.assertEqual(pre_repair.subtract_calendar_months(dt.date(2026, 5, 31)),
                     dt.date(2026, 2, 28))

  def test_continuous_error_keeps_earliest_and_success_keeps_boundaries(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      names = [
          '2026_6_20 success', '2026_6_21 success', '2026_6_22 error',
          '2026_6_23 error', '2026_6_24 success', '2026_6_25 success'
      ]
      logs = []
      for name in names:
        path = root / name
        path.touch()
        logs.append(pre_repair.parse_log_name(path))
      kept, collisions = pre_repair.select_boundary_logs(logs)
      self.assertEqual(collisions, [])
      self.assertEqual({path.name for path in kept}, {
          '2026_6_20 success', '2026_6_21 success', '2026_6_22 error',
          '2026_6_24 success', '2026_6_25 success'
      })

  def test_same_day_conflict_is_preserved(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      names = ['2026_6_20 error', '2026_6_20 success', '2026_6_21 error']
      logs = []
      for name in names:
        path = root / name
        path.touch()
        logs.append(pre_repair.parse_log_name(path))
      kept, collisions = pre_repair.select_boundary_logs(logs)
      self.assertEqual(collisions, ['2026-06-20'])
      self.assertEqual({path.name for path in kept}, set(names))

  def test_project_filter_limits_selected_log_tree(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      source = root / 'source'
      destination = root / 'destination'
      for project in ('cups-filters', 'qemu'):
        project_dir = source / project
        project_dir.mkdir(parents=True)
        (project_dir / '2026_6_20 error').touch()
      report = pre_repair.filter_log_tree(source, destination, ['cups-filters'])
      self.assertTrue(
          (destination / 'cups-filters' / '2026_6_20 error').is_file())
      self.assertFalse((destination / 'qemu').exists())
      self.assertEqual(report['copied_count'], 1)

  def test_log_filter_skips_blacklisted_project(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      source = root / 'source'
      for project in ('tint', 'cups-filters'):
        project_dir = source / project
        project_dir.mkdir(parents=True)
        (project_dir / '2026_6_20 error').touch()

      report = pre_repair.filter_log_tree(source, root / 'destination')

    self.assertEqual(report['copied_count'], 1)
    self.assertEqual(report['skipped_projects']['tint'],
                     pre_repair.BLACKLIST_REASON)

  def test_project_filter_reports_missing_requested_projects(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      source = root / 'source'
      (source / 'cups-filters').mkdir(parents=True)
      (source / 'cups-filters' / '2026_6_20 error').touch()
      report = pre_repair.filter_log_tree(root / 'source', root / 'destination',
                                          ['qemu'])
      self.assertEqual(report['missing_projects'], ['qemu'])
      self.assertEqual(report['copied_count'], 0)

  def test_extraction_continues_when_one_requested_project_has_no_logs(self):
    entry = {
        'project': 'kea',
        'language': 'c++',
        'error_time': '2026-09-18',
        'oss-fuzz_sha': 'oss-fuzz-sha',
        'fuzzing_build_error_log': 'https://example.test/log.txt',
        'software_repo_url': 'https://example.test/kea.git',
        'software_sha': 'source-sha',
        'engine': 'libfuzzer',
        'sanitizer': 'address',
        'architecture': 'x86_64',
        'base_image_digest': 'digest',
        'error_category': 'RC1',
        'fixed_state': 'no',
    }
    evidence = {'status': 'metadata_extracted', 'original_metadata': entry}
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      log = root / 'logs' / 'kea' / '2026_09_18 error'
      log.parent.mkdir(parents=True)
      log.touch()
      mapping = [{
          'timestamp_utc': '2026-09-17T00:00:00+00:00',
          'sha': 'oss-fuzz-sha'
      }]
      with mock.patch.object(pre_repair,
                             'build_commit_mapping',
                             return_value=mapping), mock.patch.object(
                                 pre_repair,
                                 '_extract_one',
                                 return_value=(entry, evidence)):
        benchmark_dir = pre_repair.run_reproduction_and_extraction(
            str(root), str(root / 'oss-fuzz'), 'vertex_ai_gemini-3-1-pro',
            str(root / 'logs'), ['fwupd', 'kea'], dt.date(2026, 9, 23))

      manifest = json.loads(
          (root / 'pre_repair' / 'manifest.json').read_text(encoding='utf-8'))

      self.assertTrue((benchmark_dir / 'kea.yaml').is_file())
      self.assertEqual(manifest['status'], 'completed')
      self.assertEqual(manifest['unavailable_requested_projects'], ['fwupd'])

  def test_metadata_streams_compile_config_beyond_first_thousand_lines(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      project_dir = Path(temp_dir) / 'thrift-cpp'
      project_dir.mkdir()
      log = project_dir / '2026_09_16 error'
      lines = [
          'starting build "build-id"\n',
          'Digest: sha256:' + ('a' * 64) + '\n',
          *['padding\n'] * 1500,
          'Starting Step #3 - "compile-afl-address-x86_64"\n',
      ]
      log.write_text(''.join(lines), encoding='utf-8')

      metadata = pre_repair._metadata_from_log(log)

      self.assertEqual(metadata['engine'], 'afl')
      self.assertEqual(metadata['sanitizer'], 'address')
      self.assertEqual(metadata['architecture'], 'x86_64')

  def test_public_metadata_has_canonical_order_without_dependencies(self):
    entry = {
        'dependencies': [{
            'repo': 'internal-only'
        }],
        'fixed_state': 'no',
        'base_image_digest': 'digest',
        'project': 'fwupd',
        'last_success_time': '2026-09-18',
        'language': 'c',
        'error_time': '2026-09-19',
        'oss-fuzz_sha': 'oss-fuzz-sha',
    }

    ordered = pre_repair._ordered_metadata(entry, include_last_success=True)

    self.assertEqual(list(ordered), [
        'project', 'language', 'error_time', 'last_success_time',
        'oss-fuzz_sha', 'base_image_digest', 'fixed_state'
    ])
    self.assertNotIn('dependencies', ordered)

  def test_public_metadata_rejects_unknown_field_alias(self):
    with self.assertRaisesRegex(pre_repair.PreRepairError, 'oss_fuzz_sha'):
      pre_repair._ordered_metadata({'oss_fuzz_sha': 'wrong-alias'})

  def test_reproduction_mismatch_does_not_reject_complete_metadata(self):
    metadata = {
        'fuzzing_build_error_log': 'https://example.test/log.txt',
        'base_image_digest': 'digest',
        'engine': 'libfuzzer',
        'sanitizer': 'address',
        'architecture': 'x86_64',
        'software_repo_url': 'https://example.test/project.git',
        'software_sha': 'source-sha',
        'dependencies': [],
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      log = root / 'logs' / 'fwupd' / '2026_09_19 error'
      log.parent.mkdir(parents=True)
      log.write_text('original failure', encoding='utf-8')
      workspace = root / 'workspace'
      workspace.mkdir()

      def copy_checkout(_source, destination):
        dockerfile = destination / 'projects' / 'fwupd' / 'Dockerfile'
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text('FROM base@sha256:old\n', encoding='utf-8')

      completed = mock.Mock(returncode=0, stdout='reproduced failure')
      with mock.patch.object(
          pre_repair, '_metadata_from_log',
          return_value=metadata), mock.patch.object(
              pre_repair, '_copy_oss_fuzz',
              side_effect=copy_checkout), mock.patch.object(
                  pre_repair, '_project_language',
                  return_value='c'), mock.patch.object(
                      pre_repair, '_run',
                      return_value=completed), mock.patch.object(
                          pre_repair,
                          '_patch_reproduction_dockerfile',
                          return_value='FROM base\n'), mock.patch.object(
                              pre_repair,
                              '_vertex_match',
                              return_value={
                                  'matches': False,
                                  'error_category': 'RC13'
                              }):
        entry, evidence = pre_repair._reproduce_one(
            log, root / 'oss-fuzz', workspace, 'vertex_ai_gemini-3-1-pro', [{
                'timestamp_utc': '2026-09-18T00:00:00+00:00',
                'sha': 'oss-fuzz-sha'
            }])

    self.assertIsNotNone(entry)
    assert entry is not None
    self.assertEqual(entry['project'], 'fwupd')
    self.assertEqual(entry['oss-fuzz_sha'], 'oss-fuzz-sha')
    self.assertEqual(entry['error_category'], 'RC13')
    self.assertEqual(evidence['status'], 'accepted_with_reproduction_mismatch')

  def test_fast_extraction_accepts_metadata_without_build_reproduction(self):
    metadata = {
        'fuzzing_build_error_log': 'https://example.test/log.txt',
        'base_image_digest': 'digest',
        'engine': 'libfuzzer',
        'sanitizer': 'address',
        'architecture': 'x86_64',
        'software_repo_url': 'https://example.test/project.git',
        'software_sha': 'source-sha',
        'dependencies': [],
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      log = root / 'logs' / 'fwupd' / '2026_09_19 error'
      log.parent.mkdir(parents=True)
      log.write_text('original failure', encoding='utf-8')
      with mock.patch.object(pre_repair,
                             '_metadata_from_log',
                             return_value=metadata), mock.patch.object(
                                 pre_repair,
                                 '_project_language_at_commit',
                                 return_value='c'), mock.patch.object(
                                     pre_repair,
                                     '_vertex_classify',
                                     side_effect=RuntimeError('unavailable')):
        entry, evidence = pre_repair._extract_one(
            log, root / 'oss-fuzz', 'vertex_ai_gemini-3-1-pro', [{
                'timestamp_utc': '2026-09-18T00:00:00+00:00',
                'sha': 'oss-fuzz-sha'
            }])

    self.assertIsNotNone(entry)
    assert entry is not None
    self.assertEqual(entry['project'], 'fwupd')
    self.assertEqual(entry['oss-fuzz_sha'], 'oss-fuzz-sha')
    self.assertEqual(entry['error_category'], 'RC17')
    self.assertEqual(evidence['status'], 'metadata_extracted')
    self.assertEqual(evidence['oss_fuzz_commit_timestamp_utc'],
                     '2026-09-18T00:00:00+00:00')
    self.assertEqual(evidence['oss_fuzz_selection_rule'],
                     'latest commit strictly before error date')
    self.assertIn('RuntimeError: unavailable', evidence['classification_error'])

  def test_required_metadata_rejects_empty_values(self):
    entry = {field: 'set' for field in pre_repair.REQUIRED_METADATA}
    entry['engine'] = ''
    self.assertEqual(pre_repair._valid_entry(entry), ['engine'])

  def test_vertex_alias_matches_full_fixer_alias(self):
    self.assertEqual(pre_repair._vertex_model_name('vertex_ai_gemini-3-1-pro'),
                     'gemini-3.1-pro-preview')

  def test_commit_mapping_uses_latest_commit_strictly_before_error_date(self):
    mapping = [{
        'timestamp_utc': '2026-06-19T23:00:00+00:00',
        'sha': 'anchor'
    }, {
        'timestamp_utc': '2026-06-20T12:00:00+00:00',
        'sha': 'inside-window'
    }]
    self.assertEqual(
        pre_repair._checkout_for_date(mapping, dt.date(2026, 6, 20)), 'anchor')
    self.assertEqual(
        pre_repair._checkout_for_date(mapping, dt.date(2026, 6, 21)),
        'inside-window')
    self.assertEqual(pre_repair._commit_for_date(mapping, dt.date(2026, 6, 21)),
                     mapping[1])

  def test_commit_mapping_fetches_official_window_and_anchor(self):

    def completed(stdout=''):
      return mock.Mock(returncode=0, stdout=stdout)

    def run(command, _cwd, timeout=7200):
      del timeout
      if command[:4] == ['git', 'remote', 'set-url', 'origin']:
        self.assertEqual(command[4], pre_repair.OSS_FUZZ_UPSTREAM_URL)
        return completed()
      if '--shallow-since=2026-06-22T00:00:00Z' in command:
        return completed()
      if command == ['git', 'rev-parse', '--is-shallow-repository']:
        return completed('true\n')
      if '--deepen=1' in command:
        return completed()
      if any(item.startswith('--since=') for item in command):
        return completed('2026-09-16T01:00:00+00:00\tinside\n')
      if any(item.startswith('--before=') for item in command):
        return completed('2026-06-21T23:00:00+00:00\tanchor\n')
      self.fail(f'unexpected command: {command}')

    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_copy_oss_fuzz'), mock.patch.object(pre_repair,
                                                         '_run',
                                                         side_effect=run):
      mapping = pre_repair.build_commit_mapping(
          Path(temp_dir) / 'source',
          Path(temp_dir) / 'workspace', dt.date(2026, 6, 22),
          dt.date(2026, 9, 22))

    self.assertEqual([item['sha'] for item in mapping], ['anchor', 'inside'])

  def test_copy_oss_fuzz_creates_nested_destination_parent(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      absolute_destination = root / 'missing' / 'nested' / 'oss-fuzz'
      destination = Path(os.path.relpath(absolute_destination, Path.cwd()))
      completed = mock.Mock(returncode=0, stdout='false\n')
      with mock.patch.object(pre_repair, '_run', return_value=completed) as run:
        pre_repair._copy_oss_fuzz(root / 'source', destination)

      self.assertTrue(absolute_destination.parent.is_dir())
      clone_command, clone_cwd = run.call_args_list[0].args[:2]
      self.assertEqual(Path(clone_command[-1]), absolute_destination)
      self.assertEqual(clone_cwd, absolute_destination.parent)

  def test_reproduction_workspace_is_temporary_and_cleaned_on_failure(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      log_root = root / 'logs' / 'thrift-cpp'
      log_root.mkdir(parents=True)
      (log_root / '2026_09_16 error').touch()
      observed_workspace = None

      def fail_mapping(_source, workspace, _start, _end):
        nonlocal observed_workspace
        observed_workspace = workspace
        self.assertFalse(str(workspace).startswith(str(root / 'pre_repair')))
        raise pre_repair.PreRepairError('mapping failed')

      with mock.patch.object(pre_repair,
                             'build_commit_mapping',
                             side_effect=fail_mapping), self.assertRaises(
                                 pre_repair.PreRepairError):
        pre_repair.run_reproduction_and_extraction(str(root),
                                                   str(root / 'oss-fuzz'),
                                                   'vertex_ai_gemini-3-1-pro',
                                                   str(root / 'logs'),
                                                   ['thrift-cpp'],
                                                   dt.date(2026, 9, 22))

      self.assertIsNotNone(observed_workspace)
      assert observed_workspace is not None
      self.assertFalse(observed_workspace.exists())
      self.assertFalse(
          (root / 'pre_repair' / 'reproduction_workspace').exists())


if __name__ == '__main__':
  unittest.main()
