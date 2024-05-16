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
from typing import Any, Callable, Type

import openai
import tiktoken
import vertexai
from google.api_core.exceptions import GoogleAPICallError
from vertexai.preview.generative_models import GenerativeModel
from vertexai.preview.language_models import CodeGenerationModel

from llm_toolkit import prompts

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
  ):
    self.ai_binary = ai_binary

    # Model parameters.
    self.max_tokens = max_tokens
    self.num_samples = num_samples
    self.temperature = temperature

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
  def generate_code(self,
                    prompt: prompts.Prompt,
                    response_dir: str,
                    log_output: bool = False) -> None:
    """Generates fuzz targets to the |response_dir|."""

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

    # A known case from vertex package.
    if (isinstance(err, ValueError) and
        'Content roles do not match' in str(err) and tb[-1].filename.endswith(
            'vertexai/generative_models/_generative_models.py')):
      return True

    return False

  def with_retry_on_error(  # pylint: disable=inconsistent-return-statements
      self, func: Callable, api_err: Type[Exception]) -> Any:
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
      print(f'Could not get a tiktoken encoding for {self.name}.')
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
  def generate_code(self,
                    prompt: prompts.Prompt,
                    response_dir: str,
                    log_output: bool = False) -> None:
    """Generates code with OpenAI's API."""
    if self.ai_binary:
      print(f'OpenAI does not use local AI binary: {self.ai_binary}')
    client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(messages=prompt.get(),
                                               model=self.name,
                                               n=self.num_samples,
                                               temperature=self.temperature),
        openai.OpenAIError)
    if log_output:
      print(completion)
    for index, choice in enumerate(completion.choices):  # type: ignore
      content = choice.message.content
      self._save_output(index, content, response_dir)


class GPT4(GPT):
  """OpenAI's GPTi-4 model."""

  name = 'gpt-4'


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
  def generate_code(self,
                    prompt: prompts.Prompt,
                    response_dir: str,
                    log_output: bool = False) -> None:
    """Generates code with internal LLM."""
    if not self.ai_binary:
      print(f'Error: This model requires a local AI binary: {self.ai_binary}')
      sys.exit(1)

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
        print(f'Failed to generate targets with prompt {prompt.get()}')
        print(f'stdout: {stdout}')
        print(f'stderr: {stderr}')
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

  def generate_code(self,
                    prompt: prompts.Prompt,
                    response_dir: str,
                    log_output: bool = False) -> None:
    del log_output
    if self.ai_binary:
      print(f'VertexAI does not use local AI binary: {self.ai_binary}')

    model = self.get_model()
    parameters = {
        'temperature': self.temperature,
        'max_output_tokens': self._max_output_tokens,
    }

    for index in range(self.num_samples):
      response = self.with_retry_on_error(
          lambda: self.do_generate(model, prompt.get(), parameters),
          GoogleAPICallError)
      self._save_output(index, response, response_dir)


class GeminiModel(VertexAIModel):
  """Gemini models."""

  def get_model(self) -> Any:
    return GenerativeModel(self._vertex_ai_model)

  def do_generate(self, model: Any, prompt: str, config: dict[str, Any]) -> Any:
    return model.generate_content(prompt, generation_config=config).text


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


class Gemini1_5(GeminiModel):
  """Gemini 1.5."""

  _max_output_tokens = 8192
  context_window = 1000000

  name = 'vertex_ai_gemini-1-5'
  _vertex_ai_model = 'gemini-1.5-pro-preview-0409'


class AIBinaryModel(GoogleModel):
  """A customized model hosted internally."""

  name = 'ai_binary_model'

  def __init__(self, name: str, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.name = name


DefaultModel = VertexAICodeBison32KModel
