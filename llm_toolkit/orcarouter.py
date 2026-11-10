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
"""OrcaRouter: an OpenAI-compatible gateway exposed as a first-class provider.

The provider is registered in :mod:`llm_toolkit.models` under the
``orcarouter/<model-id>`` namespace, so every AI entry point that resolves a
model through ``LLM.setup()`` can route through it.

Credentials follow this repository's existing convention for providers: the key
is read from an environment variable (``ORCA_KEY``, with ``ORCAROUTER_API_KEY``
accepted as an alias). Keys are never written to logs, error messages or the
command line.

The model list is discovered from the gateway's own catalog endpoint rather
than hardcoded. A small, live-verified seed keeps a fresh installation usable
when the catalog is unreachable.
"""

import abc
import argparse
import contextlib
import dataclasses
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable, Iterator, Optional

import openai

from llm_toolkit import models

logger = logging.getLogger(__name__)

PROVIDER_NAME = 'orcarouter'
MODEL_PREFIX = PROVIDER_NAME + '/'

# Inference and authentication deliberately live on different public origins.
DEFAULT_API_BASE_URL = 'https://api.orcarouter.ai/v1'
DEFAULT_AUTH_BASE_URL = 'https://www.orcarouter.ai'
AUTHORIZE_PATH = '/auth'
API_KEY_EXCHANGE_PATH = '/api/v1/auth/keys'
MODELS_PATH = '/models'

API_BASE_URL_ENV = 'ORCA_API_BASE_URL'
AUTH_BASE_URL_ENV = 'ORCA_AUTH_BASE_URL'
SHARED_BASE_URL_ENV = 'ORCA_BASE_URL'
API_KEY_ENV_VARS = ('ORCA_KEY', 'ORCAROUTER_API_KEY')
API_KEY_PREFIX = 'sk-orca-'
KEY_DASHBOARD_URL = 'https://www.orcarouter.ai/console/api-keys'

_LOOPBACK_HOSTS = frozenset({'localhost', '127.0.0.1', '::1'})

# Endpoint types a text chat request can be sent over.
TEXT_ENDPOINT_TYPES = frozenset(
    {'openai', 'anthropic', 'gemini', 'openai-response'})
# Endpoint types that mark a model as specialised for non-text work.
NON_TEXT_ENDPOINT_TYPES = frozenset(
    {'image-generation', 'openai-video', 'jina-rerank'})
EMBEDDING_ENDPOINT_TYPES = frozenset({'embeddings'})
IMAGE_ENDPOINT_TYPES = frozenset({'image-generation'})
VIDEO_ENDPOINT_TYPES = frozenset({'openai-video'})
RERANK_ENDPOINT_TYPES = frozenset({'jina-rerank'})

CAPABILITIES = ('chat', 'embedding', 'image', 'video', 'rerank')
MODALITIES = ('text', 'image', 'audio', 'video', 'file')

# Catalog responses are bounded so a hostile or broken endpoint cannot exhaust
# memory.
DEFAULT_CATALOG_TIMEOUT = 10.0
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_CATALOG_MODELS = 1000
CATALOG_CACHE_TTL = 600.0

CYBER_MODEL_ID = 'orcacyber-zero'
FALLBACK_MODEL_ID = 'orcarouter/fusion'

# Metadata verified against the live catalog on 2026-10-22. It is re-applied to
# live results so discovery can never erase a verified capability.
_VERIFIED_METADATA = {
    'openai/gpt-5.5': {
        'context_length': None,
        'max_completion_tokens': 128000,
        'input_modalities': ('file', 'image', 'text'),
        'reasoning_efforts': ('low', 'medium', 'high', 'xhigh'),
    },
    'anthropic/claude-opus-4.8': {
        'context_length': 1000000,
        'max_completion_tokens': 128000,
        'input_modalities': ('text', 'image', 'file'),
    },
    'google/gemini-3.5-flash': {
        'context_length': 1048576,
        'max_completion_tokens': 65536,
        'input_modalities': ('text', 'image', 'video', 'file', 'audio'),
    },
    'deepseek/deepseek-v4-pro': {
        'context_length': 1048576,
        'max_completion_tokens': 384000,
        'input_modalities': ('text',),
    },
    'orcarouter/fusion': {
        'context_length': 1000000,
        'input_modalities': ('text',),
    },
}

# Offline seed. Every entry was checked against the live catalog on 2026-10-22.
# `orcarouter/auto` (from the generic guidance) is intentionally absent: the
# live catalog does not advertise it, and a seed entry that the gateway would
# reject is worse than no entry.


class OrcaRouterError(RuntimeError):
  """Base error for the OrcaRouter provider."""


class OrcaRouterAuthError(OrcaRouterError):
  """The gateway rejected the configured credential."""


class OrcaRouterCatalogError(OrcaRouterError):
  """The model catalog could not be read."""


def redact(secret: str) -> str:
  """Returns a log-safe representation of |secret|."""
  if not secret:
    return '<unset>'
  if len(secret) <= 12:
    return '***'
  return f'{secret[:8]}...{secret[-4:]}'


def _validate_base_url(url: str, env_name: str) -> str:
  """Validates a configured base URL. Never derives one origin from another."""
  parsed = urllib.parse.urlsplit(url)
  if parsed.scheme not in ('http', 'https'):
    raise ValueError(f'{env_name} must be an http(s) URL, got {url!r}.')
  if not parsed.hostname:
    raise ValueError(f'{env_name} must contain a host, got {url!r}.')
  if parsed.username or parsed.password:
    raise ValueError(f'{env_name} must not contain user information.')
  if parsed.scheme == 'http' and parsed.hostname not in _LOOPBACK_HOSTS:
    raise ValueError(
        f'{env_name} must use https outside loopback, got {url!r}.')
  return url.rstrip('/')


def resolve_api_base_url() -> str:
  """Returns the inference base URL (always includes the ``/v1`` suffix)."""
  explicit = os.getenv(API_BASE_URL_ENV)
  if explicit:
    return _validate_base_url(explicit, API_BASE_URL_ENV)

  shared = os.getenv(SHARED_BASE_URL_ENV)
  if shared:
    return _validate_base_url(shared, SHARED_BASE_URL_ENV) + '/v1'

  return DEFAULT_API_BASE_URL


def resolve_auth_base_url() -> str:
  """Returns the authentication origin (never used for inference)."""
  explicit = os.getenv(AUTH_BASE_URL_ENV)
  if explicit:
    return _validate_base_url(explicit, AUTH_BASE_URL_ENV)

  shared = os.getenv(SHARED_BASE_URL_ENV)
  if shared:
    return _validate_base_url(shared, SHARED_BASE_URL_ENV)

  return DEFAULT_AUTH_BASE_URL


@dataclasses.dataclass(frozen=True)
class ModelInfo:
  """One model advertised by the OrcaRouter catalog."""

  model_id: str
  display_name: str = ''
  context_length: Optional[int] = None
  max_completion_tokens: Optional[int] = None
  input_modalities: tuple[str, ...] = ()
  supported_endpoint_types: tuple[str, ...] = ()
  reasoning_efforts: tuple[str, ...] = ()
  requires_verified_access: bool = False


@dataclasses.dataclass(frozen=True)
class ModelCatalog:
  """A catalog snapshot and where it came from."""

  models: tuple[ModelInfo, ...]
  source: str  # 'live' or 'seed'
  error: str = ''

  @property
  def degraded(self) -> bool:
    """True when the authoritative catalog could not be read."""
    return self.source != 'live'

  def has(self, model_id: str) -> bool:
    """Returns whether |model_id| is advertised."""
    return any(model.model_id == model_id for model in self.models)


def _as_tuple(value) -> tuple:
  if not isinstance(value, list):
    return ()
  return tuple(item for item in value if isinstance(item, str))


def _as_optional_int(value) -> Optional[int]:
  if isinstance(value, bool):
    return None
  if isinstance(value, int) and value > 0:
    return value
  return None


def _parse_model(raw: object) -> Optional[ModelInfo]:
  """Converts one catalog record into a |ModelInfo|, or None if unusable."""
  if not isinstance(raw, dict):
    return None
  model_id = raw.get('id')
  if not isinstance(model_id, str) or not model_id.strip():
    return None

  architecture = raw.get('architecture')
  input_modalities = ()
  if isinstance(architecture, dict):
    input_modalities = _as_tuple(architecture.get('input_modalities'))

  top_provider = raw.get('top_provider')
  raw_context = raw.get('context_length')
  if raw_context is None and isinstance(top_provider, dict):
    raw_context = top_provider.get('context_length')

  display_name = raw.get('name')
  return ModelInfo(
      model_id=model_id.strip(),
      display_name=display_name if isinstance(display_name, str) else '',
      context_length=_as_optional_int(raw_context),
      max_completion_tokens=_as_optional_int(raw.get('max_completion_tokens')),
      input_modalities=input_modalities,
      supported_endpoint_types=_as_tuple(raw.get('supported_endpoint_types')),
  )


def _with_verified_metadata(model: ModelInfo) -> ModelInfo:
  """Backfills verified metadata without dropping anything discovery found."""
  verified = _VERIFIED_METADATA.get(model.model_id)
  if not verified:
    return model

  def pick(field: str):
    current = getattr(model, field)
    if current:
      return current
    return verified.get(field, current)

  return dataclasses.replace(
      model,
      context_length=pick('context_length'),
      max_completion_tokens=pick('max_completion_tokens'),
      input_modalities=pick('input_modalities'),
      reasoning_efforts=pick('reasoning_efforts'),
  )


def _seed_catalog() -> ModelCatalog:
  """Returns the bounded, offline-verified seed catalog."""
  seed = (
      ModelInfo(model_id='openai/gpt-5.5',
                display_name='OpenAI: GPT-5.5',
                supported_endpoint_types=('openai', 'openai-response'),
                **_VERIFIED_METADATA['openai/gpt-5.5']),
      ModelInfo(model_id='anthropic/claude-opus-4.8',
                display_name='Anthropic: Claude Opus 4.8',
                supported_endpoint_types=('anthropic', 'openai',
                                          'openai-response'),
                **_VERIFIED_METADATA['anthropic/claude-opus-4.8']),
      ModelInfo(model_id='google/gemini-3.5-flash',
                display_name='Google: Gemini 3.5 Flash',
                supported_endpoint_types=('openai', 'gemini'),
                **_VERIFIED_METADATA['google/gemini-3.5-flash']),
      ModelInfo(model_id='deepseek/deepseek-v4-pro',
                display_name='DeepSeek: V4 Pro',
                supported_endpoint_types=('openai', 'openai-response'),
                **_VERIFIED_METADATA['deepseek/deepseek-v4-pro']),
      ModelInfo(model_id=FALLBACK_MODEL_ID,
                display_name='OrcaRouter: Fusion',
                supported_endpoint_types=('openai', 'openai-response',
                                          'anthropic', 'gemini'),
                **_VERIFIED_METADATA[FALLBACK_MODEL_ID]),
      ModelInfo(model_id=CYBER_MODEL_ID,
                display_name='OrcaCyber Zero',
                supported_endpoint_types=('openai',),
                input_modalities=('text',),
                requires_verified_access=True),
  )
  return ModelCatalog(models=seed, source='seed')


_CATALOG_CACHE: dict[tuple[str, Optional[str]], tuple[float, ModelCatalog]] = {}


def _resolve_api_key(api_key: Optional[str]) -> Optional[str]:
  if api_key:
    return api_key
  provider = EnvCredentialProvider()
  try:
    return provider.resolve().api_key
  except OrcaRouterAuthError:
    # The catalog itself is public; an anonymous read is allowed.
    return None


def fetch_models(api_key: Optional[str] = None,
                 api_base_url: Optional[str] = None,
                 capability: Optional[str] = None,
                 timeout: float = DEFAULT_CATALOG_TIMEOUT,
                 max_bytes: int = MAX_CATALOG_BYTES,
                 max_models: int = MAX_CATALOG_MODELS) -> tuple[ModelInfo, ...]:
  """Reads the model catalog from the configured gateway.

  Raises:
    OrcaRouterCatalogError: if the response is unusable.
  """
  if capability is not None and capability not in CAPABILITIES:
    raise ValueError(f'Unsupported capability {capability!r}.')

  base_url = _validate_base_url(api_base_url or resolve_api_base_url(),
                                API_BASE_URL_ENV)
  url = base_url + MODELS_PATH
  if capability:
    url += '?' + urllib.parse.urlencode({'capability': capability})

  headers = {'Accept': 'application/json'}
  key = _resolve_api_key(api_key)
  if key:
    headers['Authorization'] = f'Bearer {key}'

  request = urllib.request.Request(url, headers=headers, method='GET')
  try:
    with urllib.request.urlopen(request, timeout=timeout) as response:
      payload = response.read(max_bytes + 1)
  except urllib.error.HTTPError as error:
    # The error body is deliberately not included: it may echo request data.
    raise OrcaRouterCatalogError(
        f'OrcaRouter model catalog returned HTTP {error.code} '
        f'({url}).') from None
  except (urllib.error.URLError, TimeoutError, OSError) as error:
    raise OrcaRouterCatalogError(
        f'Could not reach the OrcaRouter model catalog at {url}: '
        f'{type(error).__name__}.') from None

  if len(payload) > max_bytes:
    raise OrcaRouterCatalogError(
        f'OrcaRouter model catalog exceeded {max_bytes} bytes.')

  try:
    document = json.loads(payload.decode('utf-8'))
  except (UnicodeDecodeError, json.JSONDecodeError):
    raise OrcaRouterCatalogError(
        'OrcaRouter model catalog was not valid JSON.') from None

  records = document.get('data') if isinstance(document, dict) else None
  if not isinstance(records, list):
    raise OrcaRouterCatalogError(
        'OrcaRouter model catalog did not contain a "data" list.')

  parsed: list[ModelInfo] = []
  for raw in records[:max_models]:
    model = _parse_model(raw)
    if model is not None:
      parsed.append(_with_verified_metadata(model))
  return tuple(parsed)


def load_catalog(api_key: Optional[str] = None,
                 capability: Optional[str] = None,
                 use_cache: bool = True) -> ModelCatalog:
  """Returns the live catalog, falling back to the verified seed.

  A successful live read is authoritative: seed-only models are never mixed
  into it. A failed read is reported as a degraded catalog so callers can
  surface the outage instead of appearing to support no models.
  """
  base_url = resolve_api_base_url()
  cache_key = (base_url, capability)
  now = time.monotonic()
  if use_cache:
    cached = _CATALOG_CACHE.get(cache_key)
    if cached and now - cached[0] < CATALOG_CACHE_TTL:
      return cached[1]

  try:
    live = fetch_models(api_key=api_key,
                        api_base_url=base_url,
                        capability=capability)
  except (OrcaRouterCatalogError, ValueError) as error:
    logger.warning(
        'OrcaRouter model discovery failed, using the verified '
        'seed catalog: %s', error)
    return dataclasses.replace(_seed_catalog(), error=str(error))

  if not live:
    logger.warning('OrcaRouter model catalog was empty, using the verified '
                   'seed catalog.')
    return dataclasses.replace(_seed_catalog(),
                               error='catalog returned no usable models')

  catalog = ModelCatalog(models=live, source='live')
  _CATALOG_CACHE[cache_key] = (now, catalog)
  return catalog


def clear_catalog_cache() -> None:
  """Forgets cached catalogs (used by tests and by explicit refresh)."""
  _CATALOG_CACHE.clear()


def supports_text_chat(model: ModelInfo) -> bool:
  """Returns whether a text chat request can be sent to |model|."""
  endpoint_types = set(model.supported_endpoint_types)
  if endpoint_types & NON_TEXT_ENDPOINT_TYPES:
    return False
  return bool(endpoint_types & TEXT_ENDPOINT_TYPES)


def supports_input_modalities(model: ModelInfo,
                              modalities: Iterable[str]) -> bool:
  """Returns whether |model| explicitly declares every requested modality."""
  declared = set(model.input_modalities)
  return all(modality in declared for modality in modalities)


def filter_models(
    models_: Iterable[ModelInfo],
    capability: str = 'chat',
    input_modalities: Iterable[str] = ()
) -> tuple[ModelInfo, ...]:
  """Filters a catalog for one entry point's capability.

  Nothing is inferred from a model name: a model that does not advertise the
  required endpoint type or input modality is excluded (fail closed).
  """
  if capability not in CAPABILITIES:
    raise ValueError(f'Unsupported capability {capability!r}.')

  required_endpoints = {
      'embedding': EMBEDDING_ENDPOINT_TYPES,
      'image': IMAGE_ENDPOINT_TYPES,
      'video': VIDEO_ENDPOINT_TYPES,
      'rerank': RERANK_ENDPOINT_TYPES,
  }.get(capability)

  selected: list[ModelInfo] = []
  for model in models_:
    endpoint_types = set(model.supported_endpoint_types)
    if required_endpoints is not None:
      if not endpoint_types & required_endpoints:
        continue
    elif not supports_text_chat(model):
      continue

    if capability == 'chat' and input_modalities:
      if not supports_input_modalities(model, input_modalities):
        continue
    selected.append(model)
  return tuple(selected)


def default_model_id(catalog: ModelCatalog) -> str:
  """Returns the recommended model id for |catalog|.

  OrcaCyber Zero is recommended for this project's security workload, but it
  requires a workspace with verified access. When the live catalog does not
  advertise it the provider falls back to the general default.
  """
  if catalog.source == 'live' and catalog.has(CYBER_MODEL_ID):
    return CYBER_MODEL_ID
  return FALLBACK_MODEL_ID


def configured_model_ids(catalog: ModelCatalog) -> tuple[str, ...]:
  """Returns registry names (``orcarouter/...``) for |catalog|."""
  return tuple(registry_name(model.model_id) for model in catalog.models)


def registry_name(model_id: str) -> str:
  """Returns the model-registry name for an OrcaRouter |model_id|."""
  if model_id.startswith(MODEL_PREFIX):
    return model_id
  return MODEL_PREFIX + model_id


def api_id_candidates(name: str) -> tuple[str, ...]:
  """Returns the catalog ids a registry |name| may refer to.

  OrcaRouter owns models under its own prefix (``orcarouter/fusion``) while
  upstream models keep their vendor namespace (``openai/gpt-5.5``), so a
  registry name has two possible catalog spellings. The catalog resolves it.
  """
  if not name.startswith(MODEL_PREFIX):
    return ()
  tail = name[len(MODEL_PREFIX):]
  if not tail:
    return ()
  return (tail, MODEL_PREFIX + tail)


class OrcaRouterCredentials:
  """A resolved OrcaRouter API key and the generation it belongs to."""

  def __init__(self, api_key: str, source: str, generation: int = 1):
    self.api_key = api_key
    self.source = source
    self.generation = generation

  @property
  def redacted(self) -> str:
    """Log-safe rendering of the key."""
    return redact(self.api_key)

  def __str__(self) -> str:
    return (f'OrcaRouterCredentials(source={self.source}, '
            f'generation={self.generation}, key={self.redacted})')

  def __repr__(self) -> str:
    return self.__str__()


class OrcaRouterCredentialProvider(abc.ABC):
  """Supplies the credential the provider sends to the gateway.

  Both plain API keys and (in a host that has such a seam) an interactive
  login would implement this interface; the inference client never cares which
  one produced the key.
  """

  @abc.abstractmethod
  def resolve(self) -> OrcaRouterCredentials:
    """Returns a usable credential or raises |OrcaRouterAuthError|."""

  def rotate_generation(self) -> int:
    """Marks the current credential as replaced; returns the new generation."""
    raise NotImplementedError

  def mark_rejected(self, credentials: OrcaRouterCredentials) -> None:
    """Records that |credentials| were rejected by the gateway."""

  def needs_reauth(self, credentials: OrcaRouterCredentials) -> bool:
    """True when |credentials| need to be replaced before use."""
    del credentials
    return False


class EnvCredentialProvider(OrcaRouterCredentialProvider):
  """Reads the API key from the environment, as other providers do."""

  def __init__(self, environ: Optional[dict[str, str]] = None):
    self._environ = environ if environ is not None else os.environ
    self._generation = 1
    self.rejected_generation = 0

  def resolve(self) -> OrcaRouterCredentials:
    for name in API_KEY_ENV_VARS:
      value = (self._environ.get(name) or '').strip()
      if not value:
        continue
      if not value.startswith(API_KEY_PREFIX):
        logger.warning(
            '%s does not look like an OrcaRouter key (expected '
            'the %s prefix); using it anyway.', name, API_KEY_PREFIX)
      return OrcaRouterCredentials(value, name, self._generation)

    raise OrcaRouterAuthError(
        f'No OrcaRouter API key found. Set {API_KEY_ENV_VARS[0]} (or '
        f'{API_KEY_ENV_VARS[1]}) to a key from {KEY_DASHBOARD_URL}.')

  def rotate_generation(self) -> int:
    self._generation += 1
    return self._generation

  def mark_rejected(self, credentials: OrcaRouterCredentials) -> None:
    """Records the exact generation the gateway rejected."""
    self.rejected_generation = credentials.generation

  def needs_reauth(self, credentials: OrcaRouterCredentials) -> bool:
    """True when |credentials| are the generation the gateway rejected."""
    return credentials.generation == self.rejected_generation


def _is_model_scope_denial(err: Exception) -> bool:
  """True when a 403 means the key's model allow-list, not workspace access."""
  payloads = [getattr(err, 'body', None)]
  response = getattr(err, 'response', None)
  if response is not None:
    try:
      payloads.append(response.json())
    except (ValueError, TypeError):
      pass

  for payload in payloads:
    if not isinstance(payload, dict):
      continue
    error = payload.get('error')
    if not isinstance(error, dict):
      continue
    if error.get('code') == 'model_access_denied':
      return True
    metadata = error.get('metadata')
    if isinstance(metadata,
                  dict) and metadata.get('reason') == 'block_key_scope':
      return True
  return False


def _describe_model_options(catalog: ModelCatalog,
                            capability: str = 'chat') -> str:
  """Summarises a few model options for an error message."""
  available = filter_models(catalog.models, capability=capability)
  names = [registry_name(model.model_id) for model in available[:20]]
  suffix = '' if len(available) <= 20 else f', ... ({len(available)} total)'
  return ', '.join(names) + suffix


class OrcaRouterModel(models.GPT):
  """OrcaRouter's OpenAI-compatible chat models.

  As with `models.GPT`, this class is itself a registered model: it backs the
  default `orcarouter/fusion` entry and is the base for the other entries.
  """

  name = FALLBACK_MODEL_ID
  _api_model = FALLBACK_MODEL_ID
  context_window = 1000000
  MAX_INPUT_TOKEN = 128000

  def __init__(
      self,
      ai_binary: str,
      max_tokens: int = models.MAX_TOKENS,
      num_samples: int = models.NUM_SAMPLES,
      temperature: float = models.TEMPERATURE,
      temperature_list: Optional[list[float]] = None,
      api_model: Optional[str] = None,
      api_base_url: Optional[str] = None,
      credential_provider: Optional[OrcaRouterCredentialProvider] = None,
      context_length: Optional[int] = None):
    super().__init__(ai_binary, max_tokens, num_samples, temperature,
                     temperature_list)
    self.api_model = api_model or self._api_model or self.name
    self._api_base_url = api_base_url or resolve_api_base_url()
    self._credential_provider = (credential_provider or EnvCredentialProvider())
    self._last_credentials: Optional[OrcaRouterCredentials] = None
    if context_length:
      self.context_window = context_length
      self.MAX_INPUT_TOKEN = context_length  # pylint: disable=invalid-name

  @property
  def api_model_name(self) -> str:
    """The model id sent to the gateway."""
    return self.api_model

  def _get_client(self):
    """Returns an OpenAI client pointed at the OrcaRouter gateway."""
    credentials = self._credential_provider.resolve()
    self._last_credentials = credentials
    return openai.OpenAI(base_url=self._api_base_url,
                         api_key=credentials.api_key)

  def _is_retryable_error(self, err: Exception,
                          api_errors: list[type[Exception]], tb) -> bool:
    # A rejected credential is terminal: retrying it only delays the message
    # the user needs. Rate limits and transport errors stay retryable.
    if isinstance(err,
                  (openai.AuthenticationError, openai.PermissionDeniedError)):
      return False
    return super()._is_retryable_error(err, api_errors, tb)

  @contextlib.contextmanager
  def _translate_auth_errors(self) -> Iterator[None]:
    """Turns gateway credential failures into actionable provider errors."""
    try:
      yield
    except (openai.AuthenticationError, openai.PermissionDeniedError) as err:
      credentials = self._last_credentials
      generation = credentials.generation if credentials else 0
      if credentials is not None:
        self._credential_provider.mark_rejected(credentials)
      status = getattr(err, 'status_code', None)
      if isinstance(err, openai.PermissionDeniedError) or status == 403:
        if _is_model_scope_denial(err):
          raise OrcaRouterAuthError(
              f'The OrcaRouter API key is not scoped to model '
              f'{self.api_model!r} (HTTP 403). Pick another model from '
              f'`python -m llm_toolkit.orcarouter list-models`, or grant this '
              f'key access to the model at '
              f'https://www.orcarouter.ai/console/token.') from None
        raise OrcaRouterAuthError(
            f'OrcaRouter denied access to model {self.api_model!r} '
            f'(HTTP 403) with credential generation {generation}. '
            f'{CYBER_MODEL_ID} requires a workspace with verified access; '
            f'otherwise choose a model the key can reach with '
            f'`python -m llm_toolkit.orcarouter list-models`.') from None
      raise OrcaRouterAuthError(
          f'OrcaRouter rejected the API key (HTTP 401) with credential '
          f'generation {generation}. Update the key at {KEY_DASHBOARD_URL} '
          f'and rerun.') from None

  def ask_llm(self, prompt) -> str:
    with self._translate_auth_errors():
      return super().ask_llm(prompt)

  def query_llm(self, prompt, response_dir: str) -> None:
    with self._translate_auth_errors():
      super().query_llm(prompt, response_dir)

  def chat_llm(self, client, prompt) -> str:
    with self._translate_auth_errors():
      return super().chat_llm(client, prompt)

  def chat_llm_with_tools(self, client, prompt, tools):
    with self._translate_auth_errors():
      return super().chat_llm_with_tools(client, prompt, tools)


class OrcaCyberZero(OrcaRouterModel):
  """OrcaRouter's security model, for workspaces with verified access."""

  name = MODEL_PREFIX + CYBER_MODEL_ID
  _api_model = CYBER_MODEL_ID


class OrcaRouterGpt55(OrcaRouterModel):
  """OpenAI GPT-5.5 through OrcaRouter."""

  name = MODEL_PREFIX + 'openai/gpt-5.5'
  _api_model = 'openai/gpt-5.5'


class OrcaRouterClaudeOpus48(OrcaRouterModel):
  """Anthropic Claude Opus 4.8 through OrcaRouter."""

  name = MODEL_PREFIX + 'anthropic/claude-opus-4.8'
  _api_model = 'anthropic/claude-opus-4.8'


class OrcaRouterGemini35Flash(OrcaRouterModel):
  """Google Gemini 3.5 Flash through OrcaRouter."""

  name = MODEL_PREFIX + 'google/gemini-3.5-flash'
  _api_model = 'google/gemini-3.5-flash'


class OrcaRouterDeepSeekV4Pro(OrcaRouterModel):
  """DeepSeek V4 Pro through OrcaRouter."""

  name = MODEL_PREFIX + 'deepseek/deepseek-v4-pro'
  _api_model = 'deepseek/deepseek-v4-pro'


def create_model(
    name: str,
    ai_binary: str,
    max_tokens: int = models.MAX_TOKENS,
    num_samples: int = models.NUM_SAMPLES,
    temperature: float = models.TEMPERATURE,
    temperature_list: Optional[list[float]] = None
) -> Optional[OrcaRouterModel]:
  """Creates an OrcaRouter model for a discovered model id.

  Returns None when |name| does not belong to the OrcaRouter namespace. Any
  OrcaRouter name is validated against the catalog (or the verified seed) and
  rejected with the available options when unknown.
  """
  candidates = api_id_candidates(name)
  if not candidates:
    return None

  catalog = load_catalog()
  known = {model.model_id for model in catalog.models}
  model_id = next((candidate for candidate in candidates if candidate in known),
                  None)
  if model_id is None:
    raise ValueError(
        f'Unknown OrcaRouter model {name!r}. Available models: '
        f'{_describe_model_options(catalog)}. List the live catalog with '
        f'`python -m llm_toolkit.orcarouter list-models`.')

  model_info = next(
      model for model in catalog.models if model.model_id == model_id)
  return OrcaRouterModel(ai_binary,
                         max_tokens,
                         num_samples,
                         temperature,
                         temperature_list,
                         api_model=model_id,
                         context_length=model_info.context_length)


def _format_model_row(model: ModelInfo, source: str) -> str:
  """Renders one catalog row for the CLI."""
  context = model.context_length or 0
  modalities = ','.join(model.input_modalities) or '-'
  reasoning = '/'.join(model.reasoning_efforts) or '-'
  notes = ''
  if model.requires_verified_access:
    notes = ' (verified access required)'
  return (f'{registry_name(model.model_id):<52} {source:<5} '
          f'{context:>9} {modalities:<28} {reasoning}{notes}')


def list_models(capability: str = 'chat',
                input_modalities: Iterable[str] = (),
                as_json: bool = False) -> str:
  """Returns the catalog filtered for |capability| as text or JSON."""
  catalog = load_catalog(capability=capability)
  selected = filter_models(catalog.models,
                           capability=capability,
                           input_modalities=input_modalities)
  if as_json:
    payload = {
        'source': catalog.source,
        'degraded': catalog.degraded,
        'error': catalog.error,
        'capability': capability,
        'models': [dataclasses.asdict(model) for model in selected],
    }
    return json.dumps(payload, indent=2)

  lines = [
      f'OrcaRouter models for capability "{capability}" '
      f'(source: {catalog.source})'
  ]
  if catalog.degraded:
    lines.append(f'DEGRADED: {catalog.error}')
  lines.append(f'{"model":<52} {"src":<5} {"context":>9} '
               f'{"input modalities":<28} reasoning')
  lines.extend(_format_model_row(model, catalog.source) for model in selected)
  if not selected:
    lines.append('No compatible models were advertised by the catalog.')
  return '\n'.join(lines)


def main(argv: Optional[list[str]] = None) -> int:
  """Command line entry point for catalog discovery."""
  parser = argparse.ArgumentParser(
      prog='python -m llm_toolkit.orcarouter',
      description='Inspect the OrcaRouter model catalog.')
  subparsers = parser.add_subparsers(dest='command', required=True)

  list_parser = subparsers.add_parser(
      'list-models', help='List models offered by the configured gateway.')
  list_parser.add_argument('--capability',
                           choices=CAPABILITIES,
                           default='chat',
                           help='Capability the model list is filtered for.')
  list_parser.add_argument(
      '--modality',
      action='append',
      choices=MODALITIES,
      default=[],
      help='Require an input modality (repeatable, chat only).')
  list_parser.add_argument('--json',
                           action='store_true',
                           help='Emit machine-readable JSON.')

  args = parser.parse_args(argv)
  if args.command != 'list-models':
    return 2

  try:
    print(
        list_models(capability=args.capability,
                    input_modalities=args.modality,
                    as_json=args.json))
  except ValueError as error:
    print(error, file=sys.stderr)
    return 2
  return 0


if __name__ == '__main__':
  sys.exit(main())
