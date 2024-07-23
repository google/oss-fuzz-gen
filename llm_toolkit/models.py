# Copyright 2024 Google LLC
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
"""
LLM models and their functions.
"""

import logging
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import traceback
from abc import abstractmethod
from typing import Any, Callable, Optional, Type

import openai
import tiktoken
import vertexai
from google.api_core.exceptions import GoogleAPICallError
from vertexai import generative_models
from vertexai.preview.generative_models import GenerativeModel
from vertexai.preview.language_models import CodeGenerationModel

from llm_toolkit import prompts

logger = logging.getLogger(__name__)

# Model hyper-parameters.
MAX_TOKENS: int = 2000
NUM_SAMPLES: int = 1
TEMPERATURE: float = 0.4


class LLM:
  """Base LLM."""

  # Should be set by the subclass.
  name: str
  # TODO(mihaimaruseac): Should this be MAX_TOKENS or a different global?
  context_window: int = 2000  # Default token size.

  _max_attempts = 5  # Maximum number of attempts to get prediction response

  def __init__(
      self,
      ai_binary: str,
      max_tokens: int = MAX_TOKENS,
      num_samples: int = NUM_SAMPLES,
      temperature: float = TEMPERATURE,
      temperature_list: Optional[list[float]] = None,
  ):
    self.ai_binary = ai_binary

    # Model parameters.
    self.max_tokens = max_tokens
    self.num_samples = num_samples
    self.temperature = temperature
    self.temperature_list = temperature_list

  def cloud_setup(self):
    """Runs Cloud specific-setup."""
    # Only a subset of models need a cloud specific set up, so
    # we can pass for the remainder of the models as they don't
    # need to implement specific handling of this.

  @classmethod
  def setup(
      cls,
      ai_binary: str,
      name: str,
      max_tokens: int = MAX_TOKENS,
      num_samples: int = NUM_SAMPLES,
      temperature: float = TEMPERATURE,
      temperature_list: Optional[list[float]] = None,
  ):
    """Prepares the LLM for fuzz target generation."""
    if ai_binary:
      return AIBinaryModel(name, ai_binary, max_tokens, num_samples,
                           temperature)

    for subcls in cls.all_llm_subclasses():
      if getattr(subcls, 'name', None) == name:
        return subcls(
            ai_binary,
            max_tokens,
            num_samples,
            temperature,
            temperature_list,
        )

    raise ValueError(f'Bad model type {name}')

  @classmethod
  def all_llm_subclasses(cls):
    """All subclasses."""
    yield cls
    for subcls in cls.__subclasses__():
      for subsubcls in subcls.all_llm_subclasses():
        yield subsubcls

  @classmethod
  def all_llm_names(cls):
    """Returns the current model name and all child model names."""
    names = []
    for subcls in cls.all_llm_subclasses():
      if hasattr(subcls, 'name') and subcls.name != AIBinaryModel.name:
        names.append(subcls.name)
    return names

  @abstractmethod
  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""

  # ============================== Generation ============================== #
  @abstractmethod
  def query_llm(self,
                prompt: prompts.Prompt,
                response_dir: str,
                log_output: bool = False) -> None:
    """Queries the LLM and stores responses in |response_dir|."""

  @abstractmethod
  def prompt_type(self) -> type[prompts.Prompt]:
    """Returns the expected prompt type."""

  def _delay_for_retry(self, attempt_count: int) -> None:
    """Sleeps for a while based on the |attempt_count|."""
    # Exponentially increase from 5 to 80 seconds + some random to jitter.
    delay = 5 * 2**attempt_count + random.randint(1, 5)
    logging.warning('Retry in %d seconds...', delay)
    time.sleep(delay)

  def _is_retryable_error(self, err: Exception, api_error: Type[Exception],
                          tb: traceback.StackSummary) -> bool:
    """Validates if |err| is worth retrying."""
    if isinstance(err, api_error):
      return True

    # A known case from vertex package, no content due to mismatch roles.
    if (isinstance(err, ValueError) and
        'Content roles do not match' in str(err) and tb[-1].filename.endswith(
            'vertexai/generative_models/_generative_models.py')):
      return True

    # A known case from vertex package, content blocked by safety filters.
    if (isinstance(err, ValueError) and
        'blocked by the safety filters' in str(err) and
        tb[-1].filename.endswith(
            'vertexai/generative_models/_generative_models.py')):
      return True

    return False

  def with_retry_on_error(self, func: Callable,
                          api_err: Type[Exception]) -> Any:
    """
    Retry when the function returns an expected error with exponential backoff.
    """
    for attempt in range(1, self._max_attempts + 1):
      try:
        return func()
      except Exception as err:
        logging.warning('LLM API Error when responding (attempt %d): %s',
                        attempt, err)
        tb = traceback.extract_tb(err.__traceback__)
        if (not self._is_retryable_error(err, api_err, tb) or
            attempt == self._max_attempts):
          logging.warning(
              'LLM API cannot fix error when responding (attempt %d) %s: %s',
              attempt, err, traceback.format_exc())
          raise err
        self._delay_for_retry(attempt_count=attempt)
    return None

  def _save_output(self, index: int, content: str, response_dir: str) -> None:
    """Saves the raw |content| from the model ouput."""
    sample_id = index + 1
    raw_output_path = os.path.join(response_dir, f'{sample_id:02}.rawoutput')
    with open(raw_output_path, 'w+') as output_file:
      output_file.write(content)


class GPT(LLM):
  """OpenAI's GPT model encapsulator."""

  name = 'gpt-3.5-turbo'

  # ================================ Prompt ================================ #
  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""
    # https://cookbook.openai.com/examples/how_to_count_tokens_with_tiktoken
    try:
      encoder = tiktoken.encoding_for_model(self.name)
    except KeyError:
      logger.info(f'Could not get a tiktoken encoding for {self.name}.')
      encoder = tiktoken.get_encoding('cl100k_base')

    num_tokens = 0
    for message in text:
      num_tokens += 3
      for key, value in message.items():
        num_tokens += len(encoder.encode(value))
        if key == 'name':
          num_tokens += 1
    num_tokens += 3
    return num_tokens

  def prompt_type(self) -> type[prompts.Prompt]:
    """Returns the expected prompt type."""
    return prompts.OpenAIPrompt

  # ============================== Generation ============================== #
  def query_llm(self,
                prompt: prompts.Prompt,
                response_dir: str,
                log_output: bool = False) -> None:
    """Queries OpenAI's API and stores response in |response_dir|."""
    if self.ai_binary:
      logger.info(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info(
          f'OpenAI does not allow temperature list: {self.temperature_list}')

    client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(messages=prompt.get(),
                                               model=self.name,
                                               n=self.num_samples,
                                               temperature=self.temperature),
        openai.OpenAIError)
    # TODO: Add a default value for completion.
    if log_output:
      logger.info(completion)
    for index, choice in enumerate(completion.choices):  # type: ignore
      content = choice.message.content
      self._save_output(index, content, response_dir)


class GPT4(GPT):
  """OpenAI's GPTi-4 model."""

  name = 'gpt-4'


class GPT4o(GPT):
  """OpenAI's GPTi-4 model."""

  name = 'gpt-4o'


class GoogleModel(LLM):
  """Generic Google model."""

  def prompt_type(self) -> type[prompts.Prompt]:
    """Returns the expected prompt type."""
    return prompts.TextPrompt

  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""
    # Roughly 1.5 tokens per word:
    return int(len(re.split('[^a-zA-Z0-9]+', text)) * 1.5 + 0.5)

  # ============================== Generation ============================== #
  def query_llm(self,
                prompt: prompts.Prompt,
                response_dir: str,
                log_output: bool = False) -> None:
    """Queries a Google LLM and stores results in |response_dir|."""
    if not self.ai_binary:
      logger.info(
          f'Error: This model requires a local AI binary: {self.ai_binary}')
      sys.exit(1)
    if self.temperature_list:
      logger.info('AI Binary does not implement temperature list: '
                  f'{self.temperature_list}')

    with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
      f.write(prompt.get())
      prompt_path = f.name

    try:
      command = [
          self.ai_binary,
          f'-model={self.name}',
          f'-prompt={prompt_path}',
          f'-response={response_dir}',
          f'-max-tokens={self.max_tokens}',
          f'-expected-samples={self.num_samples}',
          f'-temperature={self.temperature}',
          f'-log-output={log_output}',
      ]

      proc = subprocess.Popen(
          command,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE,
          stdin=subprocess.DEVNULL,
      )
      stdout, stderr = proc.communicate()

      if proc.returncode != 0:
        logger.info(f'Failed to generate targets with prompt {prompt.get()}')
        logger.info(f'stdout: {stdout}')
        logger.info(f'stderr: {stderr}')
    finally:
      os.unlink(prompt_path)


class VertexAIModel(GoogleModel):
  """Vertex AI model."""

  _vertex_ai_model = ''
  _max_output_tokens = 2048

  def cloud_setup(self):
    """Sets Vertex AI cloud location."""
    vertex_ai_locations = os.getenv('VERTEX_AI_LOCATIONS',
                                    'us-central1').split(',')
    location = random.sample(vertex_ai_locations, 1)[0]

    logging.info('Using location %s for Vertex AI', location)
    vertexai.init(location=location,)

  def get_model(self) -> Any:
    return CodeGenerationModel.from_pretrained(self._vertex_ai_model)

  def do_generate(self, model: Any, prompt: str, config: dict[str, Any]) -> Any:
    return model.predict(prefix=prompt, **config).text

  def _prepare_parameters(self) -> list[dict]:
    """Prepares the parameter dictionary for LLM query."""
    return [{
        'temperature':
            self.temperature_list[index % len(self.temperature_list)] if
            (self.temperature_list and
             len(self.temperature_list) > index) else self.temperature,
        'max_output_tokens':
            self._max_output_tokens
    } for index in range(self.num_samples)]

  def query_llm(self,
                prompt: prompts.Prompt,
                response_dir: str,
                log_output: bool = False) -> None:
    del log_output
    if self.ai_binary:
      logger.info(f'VertexAI does not use local AI binary: {self.ai_binary}')

    model = self.get_model()
    parameters_list = self._prepare_parameters()

    for i in range(self.num_samples):
      response = self.with_retry_on_error(
          lambda i=i: self.do_generate(model, prompt.get(), parameters_list[i]),
          GoogleAPICallError) or ''
      self._save_output(i, response, response_dir)


class GeminiModel(VertexAIModel):
  """Gemini models."""

  def get_model(self) -> Any:
    return GenerativeModel(self._vertex_ai_model)

  def do_generate(self, model: Any, prompt: str, config: dict[str, Any]) -> Any:
    # Loosen inapplicable restrictions just in case.
    safety_config = [
        generative_models.SafetySetting(
            category=generative_models.HarmCategory.
            HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
        generative_models.SafetySetting(
            category=generative_models.HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
        generative_models.SafetySetting(
            category=generative_models.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
        generative_models.SafetySetting(
            category=generative_models.HarmCategory.
            HARM_CATEGORY_SEXUALLY_EXPLICIT,
            threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
        ),
    ]
    return model.generate_content(prompt,
                                  generation_config=config,
                                  safety_settings=safety_config).text


class VertexAICodeBisonModel(VertexAIModel):
  """code-bison."""

  name = 'vertex_ai_code-bison'
  _vertex_ai_model = 'code-bison'


class VertexAICodeBison32KModel(VertexAIModel):
  """code-bison-32k."""

  _max_output_tokens = 8192
  context_window = 32000

  name = 'vertex_ai_code-bison-32k'
  _vertex_ai_model = 'code-bison-32k'


class GeminiPro(GeminiModel):
  """Gemini Pro."""

  _max_output_tokens = 8192
  context_window = 32760

  name = 'vertex_ai_gemini-pro'
  _vertex_ai_model = 'gemini-1.0-pro'


class GeminiUltra(GeminiModel):
  """Gemini Ultra."""

  _max_output_tokens = 2048
  context_window = 32760  # TODO(dongge): Confirm this later.

  name = 'vertex_ai_gemini-ultra'
  _vertex_ai_model = 'gemini-ultra'


class GeminiExperimental(GeminiModel):
  """Gemini Experimental."""

  _max_output_tokens = 8192
  context_window = 32760  # TODO(dongge): Confirm this later.

  name = 'vertex_ai_gemini-experimental'
  _vertex_ai_model = 'gemini-experimental'


class GeminiV1D5(GeminiModel):
  """Gemini 1.5."""

  _max_output_tokens = 8192
  context_window = 2000000

  name = 'vertex_ai_gemini-1-5'
  _vertex_ai_model = 'gemini-1.5-pro-001'


class AIBinaryModel(GoogleModel):
  """A customized model hosted internally."""

  name = 'ai_binary_model'

  def __init__(self, name: str, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.name = name


DefaultModel = GeminiV1D5
