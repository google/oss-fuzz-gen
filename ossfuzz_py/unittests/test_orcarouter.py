#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Tests for the OrcaRouter provider and its model catalog."""

# The catalog helpers are exercised directly; they are module-private on purpose
# so that only the small public surface is offered to callers.
# pylint: disable=protected-access

import http.server
import json
import os
import threading
import unittest
from unittest import mock

import httpx
import openai

from llm_toolkit import models, orcarouter

FAKE_KEY = 'sk-orca-test-0000000000000000000000000000'


def _chat_model(model_id, modalities=('text',), endpoints=('openai',)):
  return {
      'id': model_id,
      'object': 'model',
      'name': model_id,
      'supported_endpoint_types': list(endpoints),
      'architecture': {
          'input_modalities': list(modalities)
      },
  }


CATALOG_FIXTURE = {
    'object':
        'list',
    'data': [
        _chat_model('openai/gpt-5.5',
                    modalities=('file', 'image', 'text'),
                    endpoints=('openai', 'openai-response')),
        _chat_model('deepseek/deepseek-v4-pro', modalities=('text',)),
        _chat_model('anthropic/claude-opus-4.8',
                    modalities=('text', 'image', 'file'),
                    endpoints=('anthropic', 'openai')),
        _chat_model('google/gemini-3.5-flash',
                    modalities=('text', 'image', 'video', 'file', 'audio'),
                    endpoints=('openai', 'gemini')),
        {
            'id': 'openai/text-embedding-3-large',
            'supported_endpoint_types': ['embeddings'],
            'architecture': {
                'input_modalities': ['text']
            },
        },
        {
            'id': 'openai/gpt-image-1',
            'supported_endpoint_types': ['image-generation', 'openai'],
            'architecture': {
                'input_modalities': ['text']
            },
        },
        {
            'id': 'kling/kling-v3',
            'supported_endpoint_types': ['openai-video'],
        },
        {
            'id': 'jina/jina-reranker-v3',
            'supported_endpoint_types': ['jina-rerank'],
        },
        {
            'id': 'vendor/no-endpoints',
        },
    ],
}


class CatalogServer:
  """Serves one canned catalog response over loopback HTTP."""

  def __init__(self, body: bytes, status: int = 200):
    self.body = body
    self.status = status
    self.requests: list[str] = []
    handler = self._build_handler()
    self.server = http.server.HTTPServer(('127.0.0.1', 0), handler)
    self.port = self.server.server_address[1]
    self.thread = threading.Thread(target=self.server.serve_forever,
                                   daemon=True)

  def _build_handler(self):
    """Builds the request handler for this server."""
    outer = self

    class Handler(http.server.BaseHTTPRequestHandler):
      """Serves the canned catalog response to every GET."""

      def do_GET(self):  # pylint: disable=invalid-name
        """Serves the canned response."""
        outer.requests.append(self.path)
        self.send_response(outer.status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(outer.body)))
        self.end_headers()
        self.wfile.write(outer.body)

      def log_message(self, *args):  # pylint: disable=arguments-differ
        del args

    return Handler

  def __enter__(self):
    """Starts the server."""
    self.thread.start()
    return self

  def __exit__(self, *exc_info):
    """Stops the server."""
    self.server.shutdown()
    self.server.server_close()


class BaseUrlsTest(unittest.TestCase):
  """Origins are explicit and never derived from one another."""

  def test_default_origins(self):
    """Public defaults use distinct auth and inference origins."""
    with mock.patch.dict(os.environ, {}, clear=True):
      self.assertEqual(orcarouter.resolve_api_base_url(),
                       'https://api.orcarouter.ai/v1')
      self.assertEqual(orcarouter.resolve_auth_base_url(),
                       'https://www.orcarouter.ai')

  def test_shared_self_hosted_base(self):
    """A shared self-hosted base feeds both origins."""
    with mock.patch.dict(os.environ,
                         {'ORCA_BASE_URL': 'https://orca.internal'}):
      self.assertEqual(orcarouter.resolve_api_base_url(),
                       'https://orca.internal/v1')
      self.assertEqual(orcarouter.resolve_auth_base_url(),
                       'https://orca.internal')

  def test_explicit_overrides_win(self):
    """Explicit overrides take precedence over the shared base."""
    env = {
        'ORCA_BASE_URL': 'https://shared.internal',
        'ORCA_API_BASE_URL': 'https://relay.internal/v1',
        'ORCA_AUTH_BASE_URL': 'https://login.internal',
    }
    with mock.patch.dict(os.environ, env):
      self.assertEqual(orcarouter.resolve_api_base_url(),
                       'https://relay.internal/v1')
      self.assertEqual(orcarouter.resolve_auth_base_url(),
                       'https://login.internal')

  def test_plain_http_allowed_only_for_loopback(self):
    """Plain http is limited to loopback."""
    for host in ('http://localhost:8080', 'http://127.0.0.1:8080'):
      with mock.patch.dict(os.environ, {'ORCA_API_BASE_URL': host + '/v1'}):
        self.assertEqual(orcarouter.resolve_api_base_url(), host + '/v1')

    with mock.patch.dict(os.environ,
                         {'ORCA_API_BASE_URL': 'http://orca.internal/v1'}):
      with self.assertRaises(ValueError):
        orcarouter.resolve_api_base_url()

  def test_userinfo_rejected(self):
    """Credentials embedded in a base URL are refused."""
    with mock.patch.dict(
        os.environ, {'ORCA_AUTH_BASE_URL': 'https://user:pw@orca.internal'}):
      with self.assertRaises(ValueError):
        orcarouter.resolve_auth_base_url()

  def test_auth_and_api_paths_are_distinct(self):
    """The auth paths never collide with the relay."""
    self.assertEqual(orcarouter.AUTHORIZE_PATH, '/auth')
    self.assertEqual(orcarouter.API_KEY_EXCHANGE_PATH, '/api/v1/auth/keys')
    self.assertTrue(orcarouter.DEFAULT_API_BASE_URL.endswith('/v1'))
    self.assertNotIn('/v1', orcarouter.DEFAULT_AUTH_BASE_URL)


class CredentialsTest(unittest.TestCase):
  """The key is read from the environment and never rendered in full."""

  def test_reads_primary_env_var(self):
    """The documented environment variable is honoured."""
    provider = orcarouter.EnvCredentialProvider({'ORCA_KEY': FAKE_KEY})
    credentials = provider.resolve()
    self.assertEqual(credentials.api_key, FAKE_KEY)
    self.assertEqual(credentials.source, 'ORCA_KEY')

  def test_reads_alias_env_var(self):
    """The compatibility alias is honoured."""
    provider = orcarouter.EnvCredentialProvider(
        {'ORCAROUTER_API_KEY': FAKE_KEY})
    self.assertEqual(provider.resolve().api_key, FAKE_KEY)

  def test_missing_key_is_actionable_and_secret_free(self):
    """A missing key produces an actionable error."""
    provider = orcarouter.EnvCredentialProvider({})
    with self.assertRaises(orcarouter.OrcaRouterAuthError) as raised:
      provider.resolve()
    message = str(raised.exception)
    self.assertIn('ORCA_KEY', message)
    self.assertIn(orcarouter.KEY_DASHBOARD_URL, message)

  def test_rendering_redacts_the_key(self):
    """Credentials never render the raw key."""
    credentials = orcarouter.OrcaRouterCredentials(FAKE_KEY, 'ORCA_KEY')
    self.assertNotIn(FAKE_KEY, str(credentials))
    self.assertNotIn(FAKE_KEY, repr(credentials))
    self.assertIn('sk-orca-', credentials.redacted)

  def test_generation_scoped_rejection(self):
    """Rejection is scoped to one credential generation."""
    provider = orcarouter.EnvCredentialProvider({'ORCA_KEY': FAKE_KEY})
    first = provider.resolve()
    provider.mark_rejected(first)
    self.assertTrue(provider.needs_reauth(first))

    provider.rotate_generation()
    second = provider.resolve()
    self.assertNotEqual(first.generation, second.generation)
    self.assertFalse(provider.needs_reauth(second),
                     'A stale rejection must not poison a new credential.')


class CatalogParserTest(unittest.TestCase):
  """Catalog records are parsed and filtered without guessing."""

  def setUp(self):
    orcarouter.clear_catalog_cache()
    self.addCleanup(orcarouter.clear_catalog_cache)

  def test_parsing_and_capability_filters(self):
    """Each capability selects only matching models."""
    models_ = [orcarouter._parse_model(raw) for raw in CATALOG_FIXTURE['data']]
    models_ = [model for model in models_ if model]

    chat = orcarouter.filter_models(models_, capability='chat')
    chat_ids = {model.model_id for model in chat}
    self.assertIn('openai/gpt-5.5', chat_ids)
    self.assertIn('anthropic/claude-opus-4.8', chat_ids)
    self.assertNotIn('openai/gpt-image-1', chat_ids)
    self.assertNotIn('kling/kling-v3', chat_ids)
    self.assertNotIn('jina/jina-reranker-v3', chat_ids)
    self.assertNotIn('openai/text-embedding-3-large', chat_ids)
    self.assertNotIn('vendor/no-endpoints', chat_ids)

    embedding = orcarouter.filter_models(models_, capability='embedding')
    self.assertEqual([model.model_id for model in embedding],
                     ['openai/text-embedding-3-large'])

    image = orcarouter.filter_models(models_, capability='image')
    self.assertEqual([model.model_id for model in image],
                     ['openai/gpt-image-1'])

    video = orcarouter.filter_models(models_, capability='video')
    self.assertEqual([model.model_id for model in video], ['kling/kling-v3'])

    rerank = orcarouter.filter_models(models_, capability='rerank')
    self.assertEqual([model.model_id for model in rerank],
                     ['jina/jina-reranker-v3'])

  def test_multimodal_fails_closed(self):
    """Undeclared modalities are excluded, not assumed."""
    models_ = [orcarouter._parse_model(raw) for raw in CATALOG_FIXTURE['data']]
    models_ = [model for model in models_ if model]

    with_image = orcarouter.filter_models(models_,
                                          capability='chat',
                                          input_modalities=['image'])
    image_ids = [model.model_id for model in with_image]
    self.assertIn('openai/gpt-5.5', image_ids)
    self.assertNotIn('deepseek/deepseek-v4-pro', image_ids,
                     'A text-only chat model must be excluded.')

    with_audio = orcarouter.filter_models(models_,
                                          capability='chat',
                                          input_modalities=['audio'])
    self.assertEqual([model.model_id for model in with_audio],
                     ['google/gemini-3.5-flash'])

    with_unknown = orcarouter.filter_models(models_,
                                            capability='chat',
                                            input_modalities=['hologram'])
    self.assertEqual(with_unknown, ())

  def test_unknown_capability_is_rejected(self):
    """An unknown capability is an error."""
    with self.assertRaises(ValueError):
      orcarouter.filter_models((), capability='telepathy')

  def test_verified_metadata_survives_live_discovery(self):
    """Discovery cannot erase verified metadata."""
    parsed = orcarouter._parse_model(
        _chat_model('openai/gpt-5.5', modalities=('text', 'image')))
    assert parsed is not None
    live = orcarouter._with_verified_metadata(parsed)
    self.assertEqual(live.reasoning_efforts, ('low', 'medium', 'high', 'xhigh'))
    self.assertEqual(live.max_completion_tokens, 128000)
    self.assertEqual(live.input_modalities, ('text', 'image'),
                     'Live discovery must not be overwritten.')

  def test_model_registry_names(self):
    """Registry names map to catalog ids."""
    self.assertEqual(orcarouter.registry_name('openai/gpt-5.5'),
                     'orcarouter/openai/gpt-5.5')
    self.assertEqual(orcarouter.registry_name('orcarouter/fusion'),
                     'orcarouter/fusion')
    self.assertEqual(orcarouter.api_id_candidates('orcarouter/fusion'),
                     ('fusion', 'orcarouter/fusion'))
    self.assertEqual(orcarouter.api_id_candidates('gpt-4o'), ())


class CatalogFetchTest(unittest.TestCase):
  """Catalog reading is bounded, authoritative and degrades to the seed."""

  def setUp(self):
    orcarouter.clear_catalog_cache()
    self.addCleanup(orcarouter.clear_catalog_cache)

  def test_live_catalog_is_authoritative(self):
    """A live read never mixes in seed models."""
    body = json.dumps(CATALOG_FIXTURE).encode()
    with CatalogServer(body) as server:
      base = f'http://127.0.0.1:{server.port}/v1'
      with mock.patch.dict(os.environ, {'ORCA_API_BASE_URL': base}):
        catalog = orcarouter.load_catalog(use_cache=False)

    self.assertEqual(catalog.source, 'live')
    ids = {model.model_id for model in catalog.models}
    self.assertIn('openai/gpt-5.5', ids)
    self.assertNotIn('orcarouter/fusion', ids,
                     'Seed models must not be mixed into a live catalog.')

  def test_capability_query_parameter(self):
    """Capability is passed to the catalog endpoint."""
    body = json.dumps(CATALOG_FIXTURE).encode()
    with CatalogServer(body) as server:
      base = f'http://127.0.0.1:{server.port}/v1'
      with mock.patch.dict(os.environ, {'ORCA_API_BASE_URL': base}):
        orcarouter.load_catalog(capability='chat', use_cache=False)
      self.assertEqual(server.requests, ['/v1/models?capability=chat'])

  def test_network_failure_falls_back_to_verified_seed(self):
    """An unreachable catalog degrades to the seed."""
    with mock.patch.dict(os.environ,
                         {'ORCA_API_BASE_URL': 'http://127.0.0.1:1/v1'}):
      catalog = orcarouter.load_catalog(use_cache=False)

    self.assertEqual(catalog.source, 'seed')
    self.assertTrue(catalog.degraded)
    gpt55 = next(
        model for model in catalog.models if model.model_id == 'openai/gpt-5.5')
    self.assertEqual(gpt55.reasoning_efforts,
                     ('low', 'medium', 'high', 'xhigh'))
    self.assertIn('image', gpt55.input_modalities)

  def test_http_error_falls_back_to_seed(self):
    """An HTTP error degrades to the seed."""
    with CatalogServer(b'{}', status=500) as server:
      base = f'http://127.0.0.1:{server.port}/v1'
      with mock.patch.dict(os.environ, {'ORCA_API_BASE_URL': base}):
        catalog = orcarouter.load_catalog(use_cache=False)
    self.assertEqual(catalog.source, 'seed')
    self.assertIn('500', catalog.error)

  def test_oversized_response_is_rejected(self):
    """Oversized catalog responses are refused."""
    body = json.dumps({'data': [_chat_model('a/b')]}).encode()
    with CatalogServer(body) as server:
      base = f'http://127.0.0.1:{server.port}/v1'
      with self.assertRaises(orcarouter.OrcaRouterCatalogError):
        orcarouter.fetch_models(api_base_url=base, max_bytes=10)

  def test_malformed_response_is_rejected(self):
    """Non-JSON catalog responses are refused."""
    with CatalogServer(b'not json') as server:
      base = f'http://127.0.0.1:{server.port}/v1'
      with self.assertRaises(orcarouter.OrcaRouterCatalogError):
        orcarouter.fetch_models(api_base_url=base)

  def test_model_count_is_bounded(self):
    """The number of accepted models is bounded."""
    records = [_chat_model(f'vendor/model-{index}') for index in range(50)]
    body = json.dumps({'data': records}).encode()
    with CatalogServer(body) as server:
      base = f'http://127.0.0.1:{server.port}/v1'
      fetched = orcarouter.fetch_models(api_base_url=base, max_models=5)
    self.assertEqual(len(fetched), 5)

  def test_malformed_records_are_skipped(self):
    """Unusable records are skipped."""
    body = json.dumps({
        'data': [_chat_model('good/model'), {
            'no_id': True
        }, 'nonsense', {}]
    }).encode()
    with CatalogServer(body) as server:
      base = f'http://127.0.0.1:{server.port}/v1'
      fetched = orcarouter.fetch_models(api_base_url=base)
    self.assertEqual([model.model_id for model in fetched], ['good/model'])

  def test_default_model_prefers_cyber_when_advertised(self):
    """The cyber model is preferred when available."""
    live = orcarouter.ModelCatalog(models=(orcarouter.ModelInfo(
        model_id=orcarouter.CYBER_MODEL_ID,
        supported_endpoint_types=('openai',)),),
                                   source='live')
    self.assertEqual(orcarouter.default_model_id(live),
                     orcarouter.CYBER_MODEL_ID)

    seed = orcarouter._seed_catalog()
    self.assertEqual(orcarouter.default_model_id(seed),
                     orcarouter.FALLBACK_MODEL_ID)


class ProviderTest(unittest.TestCase):
  """The provider is registered, routed and fails closed on bad credentials."""

  def setUp(self):
    orcarouter.clear_catalog_cache()
    self.addCleanup(orcarouter.clear_catalog_cache)

  def test_registered_in_model_registry(self):
    """The provider appears in the model registry."""
    self.assertIn('orcarouter/fusion', models.LLM.all_llm_names())
    self.assertIn('orcarouter/orcacyber-zero', models.LLM.all_llm_names())

  def test_setup_resolves_static_models(self):
    """Seed models resolve through LLM.setup."""
    model = models.LLM.setup(ai_binary='', name='orcarouter/fusion')
    self.assertIsInstance(model, orcarouter.OrcaRouterModel)
    self.assertEqual(model.api_model_name, 'orcarouter/fusion')

    cyber = models.LLM.setup(ai_binary='', name='orcarouter/orcacyber-zero')
    self.assertEqual(cyber.api_model_name, orcarouter.CYBER_MODEL_ID)

  def test_setup_resolves_catalog_model(self):
    """Catalog models resolve through LLM.setup."""
    with mock.patch.object(orcarouter,
                           'load_catalog',
                           return_value=orcarouter._seed_catalog()):
      model = models.LLM.setup(ai_binary='', name='orcarouter/openai/gpt-5.5')
    self.assertEqual(model.api_model_name, 'openai/gpt-5.5')

  def test_unknown_orcarouter_model_is_rejected_with_options(self):
    """Unknown models list the alternatives."""
    with mock.patch.object(orcarouter,
                           'load_catalog',
                           return_value=orcarouter._seed_catalog()):
      with self.assertRaises(ValueError) as raised:
        models.LLM.setup(ai_binary='', name='orcarouter/not-a-model')
    message = str(raised.exception)
    self.assertIn('orcarouter/openai/gpt-5.5', message)
    self.assertIn('list-models', message)

  def test_non_orcarouter_names_are_ignored_by_the_factory(self):
    """Other providers keep their own names."""
    self.assertIsNone(orcarouter.create_model('gpt-4o', ai_binary=''))

  def test_client_targets_inference_origin_with_bearer_key(self):
    """The client uses the inference origin and key."""
    provider = orcarouter.EnvCredentialProvider({'ORCA_KEY': FAKE_KEY})
    model = orcarouter.OrcaRouterModel(ai_binary='',
                                       credential_provider=provider,
                                       api_base_url='https://relay.example/v1')
    with mock.patch.object(orcarouter.openai, 'OpenAI') as constructor:
      model._get_client()  # pylint: disable=protected-access
    constructor.assert_called_once_with(base_url='https://relay.example/v1',
                                        api_key=FAKE_KEY)

  def test_401_is_terminal_and_names_the_generation(self):
    """A rejected key fails once and is actionable."""
    provider = orcarouter.EnvCredentialProvider({'ORCA_KEY': FAKE_KEY})
    model = orcarouter.OrcaRouterModel(ai_binary='',
                                       credential_provider=provider,
                                       api_base_url='http://127.0.0.1:1/v1')
    request = httpx.Request('POST', 'http://127.0.0.1:1/v1/chat/completions')
    response = httpx.Response(401, request=request)
    error = openai.AuthenticationError('bad key', response=response, body=None)

    calls = []

    def reject(**kwargs):
      del kwargs
      calls.append(1)
      raise error

    stub = mock.Mock()
    stub.chat.completions.create.side_effect = reject

    prompt = mock.Mock()
    prompt.get.return_value = [{'role': 'user', 'content': 'hi'}]

    with mock.patch.object(orcarouter.openai, 'OpenAI', return_value=stub):
      with self.assertRaises(orcarouter.OrcaRouterAuthError) as raised:
        model.ask_llm(prompt)

    self.assertEqual(len(calls), 1, 'A rejected key must not be retried.')
    message = str(raised.exception)
    self.assertIn(orcarouter.KEY_DASHBOARD_URL, message)
    self.assertNotIn(FAKE_KEY, message)
    self.assertTrue(provider.needs_reauth(provider.resolve()))

  def test_403_points_at_verified_access(self):
    """A workspace denial points at verified access."""
    provider = orcarouter.EnvCredentialProvider({'ORCA_KEY': FAKE_KEY})
    model = orcarouter.OrcaRouterModel(ai_binary='',
                                       api_model=orcarouter.CYBER_MODEL_ID,
                                       credential_provider=provider,
                                       api_base_url='http://127.0.0.1:1/v1')
    request = httpx.Request('POST', 'http://127.0.0.1:1/v1/chat/completions')
    response = httpx.Response(403, request=request)
    error = openai.PermissionDeniedError('no access',
                                         response=response,
                                         body=None)

    stub = mock.Mock()
    stub.chat.completions.create.side_effect = error

    prompt = mock.Mock()
    prompt.get.return_value = [{'role': 'user', 'content': 'hi'}]

    with mock.patch.object(orcarouter.openai, 'OpenAI', return_value=stub):
      with self.assertRaises(orcarouter.OrcaRouterAuthError) as raised:
        model.ask_llm(prompt)

    message = str(raised.exception)
    self.assertIn('verified access', message)
    self.assertIn('list-models', message)
    self.assertNotIn(FAKE_KEY, message)

  def test_403_model_scope_denial_is_explained(self):
    """A key-scope denial is explained separately."""
    provider = orcarouter.EnvCredentialProvider({'ORCA_KEY': FAKE_KEY})
    model = orcarouter.OrcaRouterModel(ai_binary='',
                                       credential_provider=provider,
                                       api_base_url='http://127.0.0.1:1/v1')
    request = httpx.Request('POST', 'http://127.0.0.1:1/v1/chat/completions')
    response = httpx.Response(
        403,
        request=request,
        json={
            'error': {
                'code': 'model_access_denied',
                'message': 'key is not scoped to this model',
            }
        })
    error = openai.PermissionDeniedError(
        'denied',
        response=response,
        body={'error': {
            'code': 'model_access_denied'
        }})

    stub = mock.Mock()
    stub.chat.completions.create.side_effect = error

    prompt = mock.Mock()
    prompt.get.return_value = [{'role': 'user', 'content': 'hi'}]

    with mock.patch.object(orcarouter.openai, 'OpenAI', return_value=stub):
      with self.assertRaises(orcarouter.OrcaRouterAuthError) as raised:
        model.ask_llm(prompt)

    message = str(raised.exception)
    self.assertIn('not scoped', message)
    self.assertIn(
        orcarouter.KEY_DASHBOARD_URL.rsplit('/api-keys', 1)[0], message)
    self.assertNotIn(FAKE_KEY, message)

  def test_requests_carry_the_catalog_model_id(self):
    """Requests send the catalog model id."""
    provider = orcarouter.EnvCredentialProvider({'ORCA_KEY': FAKE_KEY})
    model = orcarouter.OrcaRouterModel(ai_binary='',
                                       api_model='openai/gpt-5.5',
                                       credential_provider=provider)
    captured = {}

    completion = mock.Mock()
    completion.choices = [mock.Mock()]
    completion.choices[0].message.content = 'ok'

    stub = mock.Mock()
    stub.chat.completions.create.side_effect = (
        lambda **kwargs: captured.update(kwargs) or completion)

    prompt = mock.Mock()
    prompt.get.return_value = [{'role': 'user', 'content': 'hi'}]
    with mock.patch.object(orcarouter.openai, 'OpenAI', return_value=stub):
      result = model.ask_llm(prompt)

    self.assertEqual(result, 'ok')
    self.assertEqual(captured['model'], 'openai/gpt-5.5')

  def test_list_models_json_reports_source(self):
    """Discovery output is machine readable."""
    with mock.patch.object(orcarouter,
                           'load_catalog',
                           return_value=orcarouter._seed_catalog()):
      rendered = orcarouter.list_models(as_json=True)
    payload = json.loads(rendered)
    self.assertIn(payload['source'], ('live', 'seed'))
    self.assertTrue(payload['models'])
    for model in payload['models']:
      self.assertTrue(
          set(model['supported_endpoint_types']) &
          set(orcarouter.TEXT_ENDPOINT_TYPES))
      self.assertFalse(
          set(model['supported_endpoint_types']) &
          set(orcarouter.NON_TEXT_ENDPOINT_TYPES))


def _live_api_key() -> str:
  for name in orcarouter.API_KEY_ENV_VARS:
    if os.getenv(name):
      return name
  return ''


class LiveOrcaRouterTest(unittest.TestCase):
  """End-to-end checks against the gateway.

  These run only when a real key is configured; they never print or store it.
  """

  @unittest.skipUnless(_live_api_key(), 'no OrcaRouter API key configured')
  def test_live_catalog_and_inference(self):
    """A real catalog and request work end to end."""
    orcarouter.clear_catalog_cache()
    self.addCleanup(orcarouter.clear_catalog_cache)

    catalog = orcarouter.load_catalog(use_cache=False)
    self.assertEqual(catalog.source, 'live', catalog.error)
    chat = orcarouter.filter_models(catalog.models, capability='chat')
    self.assertTrue(chat, 'The live catalog advertised no chat models.')

    preferred = orcarouter.default_model_id(catalog)
    # Upstream vendor models are listed after the gateway's own entries; try
    # every advertised chat model, bounded, until one answers.
    candidates = [preferred]
    for model in chat:
      if model.model_id != preferred:
        candidates.append(model.model_id)

    prompt = mock.Mock()
    prompt.get.return_value = [{
        'role': 'user',
        'content': 'Reply with the single word: ready'
    }]

    # A key can be scoped to a subset of the catalog, so the check walks the
    # advertised chat models until one answers through the provider path.
    denied = []
    response = ''
    for model_id in candidates[:25]:
      model = models.LLM.setup(ai_binary='',
                               name=orcarouter.registry_name(model_id))
      try:
        response = model.ask_llm(prompt)
      except orcarouter.OrcaRouterAuthError as error:
        denied.append(f'{model_id}: {error}')
        continue
      if response and response.strip():
        break

    self.assertTrue(
        response and response.strip(),
        'No advertised chat model accepted the request. ' + '; '.join(denied))


if __name__ == '__main__':
  unittest.main()
