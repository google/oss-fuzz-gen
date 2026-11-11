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
"""Offline tests for full fix-build-agent provider configuration."""

import unittest

from experimental.build_fixer.build_fix import _fix_build_agent_model_config
from llm_toolkit import compatible_api


class FixBuildAgentModelConfigTest(unittest.TestCase):
  """Tests model configuration for the build-fix agent."""

  def test_sdk_and_agent_share_gateway_configuration(self):
    for model, expected in (('deepseek-chat', 'deepseek/deepseek-chat'),
                            ('deepseek/deepseek-chat',
                             'deepseek/deepseek-chat'),
                            ('qwen3.6-35b-a3b', 'openai/qwen3.6-35b-a3b'),
                            ('openai/qwen3.6-35b-a3b',
                             'openai/qwen3.6-35b-a3b')):
      with self.subTest(model=model):
        env = {
            'OPENAI_COMPATIBLE_MODEL': model,
            'OPENAI_COMPATIBLE_BASE_URL': 'http://localhost:8000/v1',
            'OPENAI_COMPATIBLE_API_KEY': 'local-key',
            'FIX_BUILD_AGENT_MODEL': 'stale-model',
            'API_KEY': 'stale-key',
        }
        config = compatible_api.resolve_config(env)
        agent = _fix_build_agent_model_config('openai_compatible', env)
        self.assertEqual(agent['model'], expected)
        self.assertEqual(config['api_model'], expected.split('/', 1)[1])
        self.assertEqual(agent['api_base'], config['api_base'])
        self.assertEqual(agent['api_key'], 'local-key')

  def test_legacy_deepseek_environment_still_supported(self):
    config = compatible_api.resolve_config({
        'DEEPSEEK_MODEL': 'deepseek-chat',
        'DEEPSEEK_BASE_URL': 'https://api.deepseek.com',
        'DEEPSEEK_API_KEY': 'legacy-key',
    })
    self.assertEqual(config['model'], 'deepseek/deepseek-chat')
    self.assertEqual(config['api_model'], 'deepseek-chat')
    self.assertEqual(config['api_key'], 'legacy-key')

  def test_deepseek_uses_openai_compatible_settings(self):
    """Maps DeepSeek to OpenAI-compatible settings."""
    config = _fix_build_agent_model_config(
        'openai_compatible', {
            'OPENAI_COMPATIBLE_MODEL': 'deepseek-chat',
            'OPENAI_COMPATIBLE_BASE_URL': 'https://api.deepseek.com',
            'OPENAI_COMPATIBLE_API_KEY': 'deepseek-test-key',
        })
    self.assertEqual(config['model'], 'deepseek/deepseek-chat')
    self.assertEqual(config['api_base'], 'https://api.deepseek.com')
    self.assertEqual(config['api_key'], 'deepseek-test-key')

  def test_openai_uses_openai_credentials(self):
    config = _fix_build_agent_model_config(
        'gpt-4o', {'OPENAI_API_KEY': 'openai-test-key'})
    self.assertEqual(config['model'], 'openai/gpt-4o')
    self.assertEqual(config['api_key'], 'openai-test-key')

  def test_qwen_preserves_openai_provider(self):
    for model in ('qwen3.6-35b-a3b', 'openai/qwen3.6-35b-a3b'):
      config = _fix_build_agent_model_config(
          'openai_compatible', {
              'OPENAI_COMPATIBLE_MODEL': model,
              'OPENAI_COMPATIBLE_BASE_URL': 'https://gateway.example/v1',
              'OPENAI_COMPATIBLE_API_KEY': 'test-key',
          })
      self.assertEqual(config['model'], 'openai/qwen3.6-35b-a3b')
      self.assertEqual(config['api_base'], 'https://gateway.example/v1')

  def test_azure_requires_deployment_and_maps_endpoint(self):
    """Requires Azure deployment settings and maps the endpoint."""
    with self.assertRaisesRegex(ValueError, 'Azure OpenAI requires'):
      _fix_build_agent_model_config('gpt-4o-azure', {})
    config = _fix_build_agent_model_config(
        'gpt-4o-azure', {
            'AZURE_OPENAI_DEPLOYMENT_NAME': 'repair-gpt4o',
            'AZURE_OPENAI_ENDPOINT': 'https://example.openai.azure.com',
            'AZURE_OPENAI_API_KEY': 'azure-test-key',
        })
    self.assertEqual(config['model'], 'azure/repair-gpt4o')
    self.assertEqual(config['api_key'], 'azure-test-key')

  def test_vertex_gemini_uses_adc_without_api_key(self):
    config = _fix_build_agent_model_config('vertex_ai_gemini-2-5-flash', {})
    self.assertEqual(config['model'], 'vertex_ai/gemini-2.5-flash')
    self.assertEqual(config['auth'], 'adc')
    self.assertEqual(config['api_key'], '')

  def test_claude_vertex_uses_adc_without_api_key(self):
    config = _fix_build_agent_model_config('vertex_ai_claude-3-5-sonnet', {})
    self.assertEqual(config['model'], 'vertex_ai/claude-3-5-sonnet@20240620')
    self.assertEqual(config['auth'], 'adc')

  def test_gemini_api_key_is_distinct_from_vertex(self):
    config = _fix_build_agent_model_config(
        'gemini_api_key_2_5_flash', {'GEMINI_API_KEY': 'gemini-test-key'})
    self.assertEqual(config['model'], 'gemini/gemini-2.5-flash')
    self.assertEqual(config['api_key'], 'gemini-test-key')


if __name__ == '__main__':
  unittest.main()
