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
"""Shared configuration for OpenAI-compatible gateways and DeepSeek."""

import os
from typing import Mapping


def resolve_config(environ: Mapping[str, str] | None = None) -> dict[str, str]:
  """Resolves one endpoint/model/key tuple without contacting the provider.

  Generic gateway settings take priority, with legacy repair/DeepSeek aliases
  as fallbacks. Provider prefixes are used by LiteLLM, not the wire API.
  """
  env = os.environ if environ is None else environ

  def first(*names: str, default: str = '') -> str:
    return next(
        (env[name].strip() for name in names if env.get(name, '').strip()),
        default)

  model = first('OPENAI_COMPATIBLE_MODEL',
                'FIX_BUILD_AGENT_MODEL',
                'DEEPSEEK_MODEL',
                default='deepseek-chat')
  api_model = model
  for prefix in ('openai/', 'deepseek/'):
    if model.startswith(prefix):
      api_model = model[len(prefix):]
      break
  if model.startswith(('openai/', 'deepseek/')):
    litellm_model = model
  else:
    provider = 'deepseek' if model.startswith('deepseek') else 'openai'
    litellm_model = f'{provider}/{model}'
  return {
      'model':
          litellm_model,
      'api_model':
          api_model,
      'api_base':
          first('OPENAI_COMPATIBLE_BASE_URL',
                'FIX_BUILD_AGENT_API_BASE',
                'DEEPSEEK_BASE_URL',
                default='https://api.deepseek.com'),
      'api_key':
          first('OPENAI_COMPATIBLE_API_KEY', 'API_KEY', 'DEEPSEEK_API_KEY'),
      'auth':
          'api_key',
  }
