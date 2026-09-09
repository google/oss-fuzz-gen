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
import unittest

from run_all_experiments import _model_result_family


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


if __name__ == '__main__':
  unittest.main()
