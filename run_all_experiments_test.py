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
"""Tests for experiment-level result organization."""

import os
import sys
import unittest
from unittest import mock

from run_all_experiments import _model_result_family, parse_args


class ModelResultFamilyTest(unittest.TestCase):
  """Tests model-family result directory selection."""

  def test_uses_requested_model_not_stale_deepseek_environment(self):
    """Uses the requested model despite a stale environment variable."""
    old_model = os.environ.get('DEEPSEEK_MODEL')
    try:
      os.environ['DEEPSEEK_MODEL'] = 'deepseek-chat'
      self.assertEqual(_model_result_family('vertex_ai_gemini-2-5-flash'),
                       'gemini')
      self.assertEqual(_model_result_family('gpt-4o'), 'gpt-4o')
    finally:
      if old_model is None:
        os.environ.pop('DEEPSEEK_MODEL', None)
      else:
        os.environ['DEEPSEEK_MODEL'] = old_model

  def test_openai_compatible_and_deepseek_use_deepseek_family(self):
    """Maps compatible and DeepSeek models to the DeepSeek result family."""
    self.assertEqual(_model_result_family('openai_compatible'), 'deepseek')
    self.assertEqual(_model_result_family('deepseek-chat'), 'deepseek')

  def test_pre_repair_requires_full_vertex_build_repair(self):
    with mock.patch.object(sys, 'argv', [
        'run_all_experiments.py', '--benchmarks-directory', 'unused',
        '--fix-build-agent', '--full-fix-build-agent',
        '--fix-build-acquire-and-extract', '--model', 'vertex_ai_gemini-3-1-pro'
    ]):
      args = parse_args()
    self.assertTrue(args.fix_build_acquire_and_extract)

  def test_acquire_logs_is_a_standalone_pre_repair_phase(self):
    with mock.patch.object(sys, 'argv', [
        'run_all_experiments.py', '--fix-build-acquire-logs',
        '--pre-repair-project', 'cups-filters', '--pre-repair-project', 'qemu'
    ]):
      args = parse_args()
    self.assertTrue(args.fix_build_acquire_logs)
    self.assertEqual(args.pre_repair_project, ['cups-filters', 'qemu'])
    self.assertEqual(args.pre_repair_acquisition_mode, 'key')

  def test_all_log_acquisition_mode(self):
    with mock.patch.object(sys, 'argv', [
        'run_all_experiments.py', '--fix-build-acquire-logs',
        '--pre-repair-acquisition-mode', 'all'
    ]):
      args = parse_args()
    self.assertEqual(args.pre_repair_acquisition_mode, 'all')

  def test_acquisition_mode_requires_acquisition_phase(self):
    with mock.patch.object(sys, 'argv', [
        'run_all_experiments.py', '--pre-repair-acquisition-mode', 'all',
        '--benchmarks-directory', 'unused'
    ]):
      with self.assertRaises(AssertionError):
        parse_args()

  def test_reproduction_requires_an_explicit_log_directory(self):
    with mock.patch.object(sys, 'argv', [
        'run_all_experiments.py', '--fix-build-reproduce-and-extract',
        '--model', 'vertex_ai_gemini-3-1-pro'
    ]):
      with self.assertRaises(AssertionError):
        parse_args()

  def test_reproduction_accepts_external_log_directory(self):
    with mock.patch.object(sys, 'argv', [
        'run_all_experiments.py', '--fix-build-reproduce-and-extract',
        '--pre-repair-log-dir', '/tmp/acquired_logs', '--model',
        'vertex_ai_gemini-3-1-pro'
    ]):
      args = parse_args()
    self.assertEqual(args.pre_repair_log_dir, '/tmp/acquired_logs')

  def test_acquisition_cannot_start_repair_without_repair_input(self):
    with mock.patch.object(sys, 'argv', [
        'run_all_experiments.py', '--fix-build-acquire-logs',
        '--fix-build-agent'
    ]):
      with self.assertRaises(AssertionError):
        parse_args()


if __name__ == '__main__':
  unittest.main()
