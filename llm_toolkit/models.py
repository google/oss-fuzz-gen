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
import math
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

import anthropic
import openai
import tiktoken
import vertexai
from google.api_core.exceptions import (GoogleAPICallError, InternalServerError,
                                        InvalidArgument, ResourceExhausted,
                                        ServiceUnavailable, TooManyRequests)
from vertexai import generative_models
from vertexai.preview.generative_models import ChatSession, GenerativeModel
from vertexai.preview.language_models import CodeGenerationModel

from llm_toolkit import prompts
from utils import retryable

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

  MAX_INPUT_TOKEN: int = sys.maxsize

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

    # Preserve chat history for OpenAI
    self.messages = []

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
      yield from subcls.all_llm_subclasses()

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
  def query_llm(self, prompt: prompts.Prompt, response_dir: str) -> None:
    """Queries the LLM and stores responses in |response_dir|."""

  def ask_llm(self, prompt: prompts.Prompt) -> str:
    """Queries LLM a single prompt and returns its response."""
    del prompt
    return ''

  @abstractmethod
  def chat_llm_with_tools(self, client: Any, prompt: Optional[prompts.Prompt],
                          tools) -> Any:
    """Queries the LLM in the given chat session with tools."""

  @abstractmethod
  def chat_llm(self, client: Any, prompt: prompts.Prompt) -> str:
    """Queries the LLM in the given chat session and returns the response."""

  @abstractmethod
  def get_model(self) -> Any:
    """Returns the underlying model instance."""

  @abstractmethod
  def prompt_type(self) -> type[prompts.Prompt]:
    """Returns the expected prompt type."""

  def _delay_for_retry(self, attempt_count: int) -> None:
    """Sleeps for a while based on the |attempt_count|."""
    # Exponentially increase from 5 to 80 seconds + some random to jitter.
    delay = 5 * 2**attempt_count + random.randint(1, 5)
    logging.warning('Retry in %d seconds...', delay)
    time.sleep(delay)

  def _is_retryable_error(self, err: Exception,
                          api_errors: list[Type[Exception]],
                          tb: traceback.StackSummary) -> bool:
    """Validates if |err| is worth retrying."""
    if any(isinstance(err, api_error) for api_error in api_errors):
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
                          api_errs: list[Type[Exception]]) -> Any:
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
        if (not self._is_retryable_error(err, api_errs, tb) or
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

  def truncate_prompt(self,
                      raw_prompt_text: Any,
                      extra_text: Any = None) -> Any:
    """Truncates the prompt text to fit in MAX_INPUT_TOKEN."""
    del extra_text
    return raw_prompt_text

  @abstractmethod
  def get_chat_client(self, model: Any) -> Any:
    """Returns a new chat session."""


class GPT(LLM):
  """OpenAI's GPT model encapsulator."""

  name = 'gpt-3.5-turbo'

  def get_model(self) -> Any:
    """Returns the underlying model instance."""
    # Placeholder: No suitable implementation/usage yet.

  def get_chat_client(self, model: Any) -> Any:
    """Returns a new chat session."""
    return self._get_client()

  def truncate_prompt(self,
                      raw_prompt_text: Any,
                      extra_text: Any = None) -> Any:
    """Truncates the prompt text to fit in MAX_INPUT_TOKEN."""
    # Obtain token counts
    extra_text = extra_text or ''
    extra_tokens = self.estimate_token_num(extra_text)
    total_tokens = self.estimate_token_num(raw_prompt_text)

    # Assume 10 round max, with 1 portion reserved for tags and roles
    remaining = math.floor(self.MAX_INPUT_TOKEN / 11 - extra_tokens)
    if remaining <= 0:
      logger.warning('Insufficient tokens to add any text: %d, %d',
                     extra_tokens, remaining)
      return ''

    # Space enough, return directly
    if total_tokens <= remaining:
      return raw_prompt_text

    # Truncate marker
    marker = '\n..(truncated)...\n'

    # Space not enough for marker, recursively truncate again
    if remaining < self.estimate_token_num(marker):
      logger.warning('Insufficient tokens to add marker: %d, %d', extra_tokens,
                     remaining)
      return self.truncate_prompt(raw_prompt_text[:remaining], extra_text)

    # Add marker and return the truncated string with another recursive check
    truncated_prompt = raw_prompt_text[-remaining:] + marker
    logger.info('Truncated %d tokens from %d to %d chars.',
                len(raw_prompt_text) - remaining, len(raw_prompt_text),
                len(truncated_prompt))

    return self.truncate_prompt(truncated_prompt, extra_text)

  def _get_tiktoken_encoding(self, model_name: str):
    """Returns the tiktoken encoding for the model."""
    try:
      return tiktoken.encoding_for_model(model_name)
    except KeyError:
      logger.info('Could not get a tiktoken encoding for %s.', model_name)
      return tiktoken.get_encoding('cl100k_base')

  def _get_client(self):
    """Returns the OpenAI client."""
    return openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

  # ================================ Prompt ================================ #
  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""
    # https://cookbook.openai.com/examples/how_to_count_tokens_with_tiktoken

    encoder = self._get_tiktoken_encoding(self.name)

    if isinstance(text, str):
      return len(encoder.encode(text))

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

  def chat_llm(self, client: Any, prompt: prompts.Prompt) -> str:
    """Queries LLM in a chat session and returns its response."""
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('OpenAI does not allow temperature list: %s',
                  self.temperature_list)

    self.messages.extend(prompt.get())

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(messages=self.messages,
                                               model=self.name,
                                               n=self.num_samples,
                                               temperature=self.temperature),
        [openai.OpenAIError])

    llm_response = completion.choices[0].message.content
    self.messages.append({'role': 'assistant', 'content': llm_response})

    return llm_response

  def chat_llm_with_tools(self, client: Any, prompt: Optional[prompts.Prompt],
                          tools) -> Any:
    """Queries LLM in a chat session with tools."""
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('OpenAI does not allow temperature list: %s',
                  self.temperature_list)

    if prompt:
      self.messages.extend(prompt.get())

    result = self.with_retry_on_error(
        lambda: client.responses.create(
            model=self.name, input=self.messages, tools=tools),
        [openai.OpenAIError])
    return result

  def ask_llm(self, prompt: prompts.Prompt) -> str:
    """Queries LLM a single prompt and returns its response."""
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('OpenAI does not allow temperature list: %s',
                  self.temperature_list)

    client = self._get_client()

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(messages=prompt.get(),
                                               model=self.name,
                                               n=self.num_samples,
                                               temperature=self.temperature),
        [openai.OpenAIError])
    return completion.choices[0].message.content

  # ============================== Generation ============================== #
  def query_llm(self, prompt: prompts.Prompt, response_dir: str) -> None:
    """Queries OpenAI's API and stores response in |response_dir|."""
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('OpenAI does not allow temperature list: %s',
                  self.temperature_list)

    client = self._get_client()

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(messages=prompt.get(),
                                               model=self.name,
                                               n=self.num_samples,
                                               temperature=self.temperature),
        [openai.OpenAIError])
    for index, choice in enumerate(completion.choices):  # type: ignore
      content = choice.message.content
      self._save_output(index, content, response_dir)


class GPT4(GPT):
  """OpenAI's GPT-4 model."""

  name = 'gpt-4'


class GPT41(GPT):
  """OpenAI's GPT-4.1 model."""

  name = 'gpt-4.1'


class GPT41Mini(GPT):
  """OpenAI's GPT-4.1-Mini model."""

  name = 'gpt-4.1-mini'


class GPT4o(GPT):
  """OpenAI's GPT-4o model."""

  name = 'gpt-4o'
  MAX_INPUT_TOKEN = 128000
  _gpt_ai_model = 'gpt-4o'


class ChatGPT4oLatest(GPT):
  """OpenAI's chatgpt-4o-latest model."""

  name = 'chatgpt-4o-latest'
  MAX_INPUT_TOKEN = 128000
  _gpt_ai_model = 'gpt-4o'


class GPT4oMini(GPT):
  """OpenAI's GPT-4o-mini model."""

  name = 'gpt-4o-mini'


class GPT4Turbo(GPT):
  """OpenAI's GPT-4 Turbo model."""

  name = 'gpt-4-turbo'


class ChatGPT(GPT):
  """OpenAI's GPT model with chat session."""

  name = 'chatgpt-3.5-turbo'

  def __init__(
      self,
      ai_binary: str,
      max_tokens: int = MAX_TOKENS,
      num_samples: int = NUM_SAMPLES,
      temperature: float = TEMPERATURE,
      temperature_list: Optional[list[float]] = None,
  ):
    super().__init__(ai_binary, max_tokens, num_samples, temperature,
                     temperature_list)
    self.conversation_history = []

  def chat_llm(self, client: Any, prompt: prompts.Prompt) -> str:
    """Queries the LLM in the given chat session and returns the response."""
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('OpenAI does not allow temperature list: %s',
                  self.temperature_list)

    self.conversation_history.extend(prompt.get())

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(
            messages=self.conversation_history,
            model=self.name,
            n=self.num_samples,
            temperature=self.temperature), [openai.OpenAIError])

    # Choose the longest response
    longest_response = max(
        (choice.message.content for choice in completion.choices), key=len)
    self.conversation_history.append({
        'role': 'assistant',
        'content': longest_response
    })

    return longest_response


class ChatGPT4(ChatGPT):
  """OpenAI's GPT4 model with chat session."""

  name = 'chatgpt-4'


class ChatGPT4o(ChatGPT):
  """OpenAI's GPT-4o model with chat session."""

  name = 'chatgpt-4o'


class ChatGPT4oMini(ChatGPT):
  """OpenAI's GPT-4o-mini model with chat session."""

  name = 'chatgpt-4o-mini'


class ChatGPT4Turbo(ChatGPT):
  """OpenAI's GPT-4 Turbo model with chat session."""

  name = 'chatgpt-4-turbo'


class AzureGPT(GPT):
  """Azure's GPT model."""

  name = 'gpt-3.5-turbo-azure'

  def _get_tiktoken_encoding(self, model_name: str):
    """Returns the tiktoken encoding for the model."""
    return super()._get_tiktoken_encoding(model_name.replace('-azure', ''))

  def _get_client(self):
    """Returns the Azure client."""
    return openai.AzureOpenAI(azure_endpoint=os.getenv(
        "AZURE_OPENAI_ENDPOINT", "https://api.openai.com"),
                              api_key=os.getenv("AZURE_OPENAI_API_KEY"),
                              api_version=os.getenv("AZURE_OPENAI_API_VERSION",
                                                    "2024-02-01"))


class AzureGPT4(AzureGPT):
  """Azure's GPTi-4 model."""

  name = 'gpt-4-azure'


class AzureGPT4o(AzureGPT):
  """Azure's GPTi-4 model."""

  name = 'gpt-4o-azure'


class Claude(LLM):
  """Anthropic's Claude model encapsulator."""

  _max_output_tokens = 4096
  _vertex_ai_model = ''
  context_window = 200000

  # ================================ Prompt ================================ #
  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""
    client = anthropic.Client()
    return client.count_tokens(text)

  def prompt_type(self) -> type[prompts.Prompt]:
    """Returns the expected prompt type."""
    return prompts.ClaudePrompt

  def get_model(self) -> str:
    return self._vertex_ai_model

  # ============================== Generation ============================== #
  def query_llm(self, prompt: prompts.Prompt, response_dir: str) -> None:
    """Queries Claude's API and stores response in |response_dir|."""
    if self.ai_binary:
      raise ValueError(f'Claude does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('Claude does not allow temperature list: %s',
                  self.temperature_list)

    vertex_ai_locations = os.getenv('VERTEX_AI_LOCATIONS',
                                    'europe-west1').split(',')
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'oss-fuzz')
    region = random.sample(vertex_ai_locations, 1)[0]
    client = anthropic.AnthropicVertex(region=region, project_id=project_id)

    completion = self.with_retry_on_error(
        lambda: client.messages.create(max_tokens=self._max_output_tokens,
                                       messages=prompt.get(),
                                       model=self.get_model(),
                                       temperature=self.temperature),
        [anthropic.AnthropicError])
    for index, choice in enumerate(completion.content):
      content = choice.text
      self._save_output(index, content, response_dir)

  def get_chat_client(self, model: Any) -> Any:
    """Returns a new chat session."""
    del model
    # Placeholder: To Be Implemented.

  def chat_llm(self, client: Any, prompt: prompts.Prompt) -> Any:
    """Queries the LLM in the given chat session and returns the response."""
    del client, prompt
    # Placeholder: To Be Implemented.

  def chat_llm_with_tools(self, client: Any, prompt: Optional[prompts.Prompt],
                          tools) -> Any:
    """Queries the LLM in the given chat session with tools."""
    # Placeholder: To Be Implemented.
    return


class ClaudeHaikuV3(Claude):
  """Claude Haiku 3."""

  name = 'vertex_ai_claude-3-haiku'
  _vertex_ai_model = 'claude-3-haiku@20240307'


class ClaudeOpusV3(Claude):
  """Claude Opus 3."""

  name = 'vertex_ai_claude-3-opus'
  _vertex_ai_model = 'claude-3-opus@20240229'


class ClaudeSonnetV3D5(Claude):
  """Claude Sonnet 3.5."""

  name = 'vertex_ai_claude-3-5-sonnet'
  _vertex_ai_model = 'claude-3-5-sonnet@20240620'


class GoogleModel(LLM):
  """Generic Google model."""

  def prompt_type(self) -> type[prompts.Prompt]:
    """Returns the expected prompt type."""
    return prompts.TextPrompt

  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""
    # A rough estimation for very large prompt: Gemini suggest 4 char per token,
    # using 3 here to be safer.
    text = text or ''
    if len(text) // 3 > self.MAX_INPUT_TOKEN:
      return len(text) // 3

    # Otherwise, roughly 1.5 tokens per word:
    return int(len(re.split('[^a-zA-Z0-9]+', text)) * 1.5 + 0.5)

  def _estimate_char_index(self, token_target: int, text: str) -> int:
    """
      Estimates a character index in `text` corresponding to approximately
      `token_target` tokens. It uses the total token count for `text` and
      assumes a roughly linear relation between token count and character
      length.
      """
    total_tokens = self.estimate_token_num(text)
    if not total_tokens:
      return 0
    # Proportional mapping: If text has T tokens over L characters, then
    # token_target corresponds to roughly (token_target / T) * L characters.
    return int(len(text) * token_target / total_tokens)

  # ============================== Generation ============================== #
  def query_llm(self, prompt: prompts.Prompt, response_dir: str) -> None:
    """Queries a Google LLM and stores results in |response_dir|."""
    if not self.ai_binary:
      logger.info('Error: This model requires a local AI binary: %s',
                  self.ai_binary)
      sys.exit(1)
    if self.temperature_list:
      logger.info('AI Binary does not implement temperature list: %s',
                  self.temperature_list)

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
      ]

      proc = subprocess.Popen(
          command,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE,
          stdin=subprocess.DEVNULL,
      )
      stdout, stderr = proc.communicate()

      if proc.returncode != 0:
        logger.info('Failed to generate targets with prompt %s', prompt.get())
        logger.info('stdout: %s', stdout)
        logger.info('stderr: %s', stderr)
    finally:
      os.unlink(prompt_path)

  def get_model(self) -> Any:
    """Returns the underlying model instance."""
    raise NotImplementedError

  def get_chat_client(self, model: Any) -> Any:
    """Returns a new chat session."""
    del model
    raise NotImplementedError

  def chat_llm(self, client: Any, prompt: prompts.Prompt) -> Any:
    """Queries the LLM in the given chat session and returns the response."""
    del client, prompt
    raise NotImplementedError

  def chat_llm_with_tools(self, client: Any, prompt: Optional[prompts.Prompt],
                          tools) -> Any:
    """Queries the LLM in the given chat session with tools."""
    # Placeholder: To Be Implemented.
    return


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
            self.temperature_list[index % len(self.temperature_list)]
            if self.temperature_list else self.temperature,
        'max_output_tokens':
            self._max_output_tokens
    } for index in range(self.num_samples)]

  def query_llm(self, prompt: prompts.Prompt, response_dir: str) -> None:
    if self.ai_binary:
      logger.info('VertexAI does not use local AI binary: %s', self.ai_binary)

    model = self.get_model()
    parameters_list = self._prepare_parameters()

    for i in range(self.num_samples):
      response = self.with_retry_on_error(
          lambda i=i: self.do_generate(model, prompt.get(), parameters_list[i]),
          [GoogleAPICallError]) or ''
      self._save_output(i, response, response_dir)

  def ask_llm(self, prompt: prompts.Prompt) -> str:
    if self.ai_binary:
      logger.info('VertexAI does not use local AI binary: %s', self.ai_binary)

    model = self.get_model()
    # TODO: Allow each trial to customize its parameters_list.
    parameter = self._prepare_parameters()[0]
    response = self.with_retry_on_error(
        lambda: self.do_generate(model, prompt.get(), parameter),
        [GoogleAPICallError]) or ''
    return response


class GeminiModel(VertexAIModel):
  """Gemini models."""

  safety_config = [
      generative_models.SafetySetting(
          category=generative_models.HarmCategory.
          HARM_CATEGORY_DANGEROUS_CONTENT,
          threshold=generative_models.HarmBlockThreshold.BLOCK_NONE,
      ),
      generative_models.SafetySetting(
          category=generative_models.HarmCategory.HARM_CATEGORY_HARASSMENT,
          threshold=generative_models.HarmBlockThreshold.BLOCK_NONE,
      ),
      generative_models.SafetySetting(
          category=generative_models.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
          threshold=generative_models.HarmBlockThreshold.BLOCK_NONE,
      ),
      generative_models.SafetySetting(
          category=generative_models.HarmCategory.
          HARM_CATEGORY_SEXUALLY_EXPLICIT,
          threshold=generative_models.HarmBlockThreshold.BLOCK_NONE,
      ),
  ]

  def get_model(self) -> Any:
    return GenerativeModel(self._vertex_ai_model)

  def do_generate(self, model: Any, prompt: str, config: dict[str, Any]) -> Any:
    # Loosen inapplicable restrictions just in case.
    logger.info('%s generating response with config: %s', self.name, config)
    return model.generate_content(prompt,
                                  generation_config=config,
                                  safety_settings=self.safety_config).text


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
  _vertex_ai_model = 'gemini-1.5-pro-002'


class GeminiV2Flash(GeminiV1D5):
  """Gemini 2 Flash."""
  name = 'vertex_ai_gemini-2-flash'
  _vertex_ai_model = 'gemini-2.0-flash-001'


class GeminiV2(GeminiV1D5):
  """Gemini 2."""
  name = 'vertex_ai_gemini-2'
  _vertex_ai_model = 'gemini-2.0-pro-exp-02-05'


class GeminiV2Think(GeminiV1D5):
  """Gemini 2 thinking."""
  name = 'vertex_ai_gemini-2-think'
  _vertex_ai_model = 'gemini-2.0-flash-thinking-exp-01-21'


class GeminiV2D5Flash(GeminiModel):
  """Gemini 2.5 flash."""
  _max_output_tokens = 65535
  context_window = 1048576
  name = 'vertex_ai_gemini-2-5-flash'
  _vertex_ai_model = 'gemini-2.5-flash-preview-04-17'


class GeminiV2D5Pro(GeminiModel):
  """Gemini 2.5 pro."""
  _max_output_tokens = 65535
  context_window = 1048576
  name = 'vertex_ai_gemini-2-5-pro'
  _vertex_ai_model = 'gemini-2.5-pro'


class GeminiV1D5Chat(GeminiV1D5):
  """Gemini 1.5 for chat session."""
  name = 'vertex_ai_gemini-1-5-chat'
  _vertex_ai_model = 'gemini-1.5-pro-002'

  # Avoids sending large prompts.
  MAX_INPUT_TOKEN: int = 128000  # max 2000000

  def get_chat_client(self, model: GenerativeModel) -> Any:
    return model.start_chat(response_validation=False)

  @retryable(
      exceptions=[
          GoogleAPICallError,
          InvalidArgument,
          ValueError,  # TODO(dongge): Handle RECITATION specifically.
          IndexError,  # A known error from vertexai.
          InternalServerError,
      ],
      other_exceptions={
          ResourceExhausted: 100,
          TooManyRequests: 100,
          ServiceUnavailable: 100,
      })
  def _do_generate(self, client: ChatSession, prompt: str,
                   config: dict[str, Any]) -> Any:
    """Generates chat response."""
    logger.info('%s generating response with config: %s', self.name, config)
    return client.send_message(
        prompt,
        stream=False,
        generation_config=config,
        safety_settings=self.safety_config).text  # type: ignore

  def truncate_prompt(self,
                      raw_prompt_text: Any,
                      extra_text: Any = None) -> Any:
    """Truncates the prompt text to fit in MAX_INPUT_TOKEN."""
    extra_text = extra_text or ''
    extra_tokens = self.estimate_token_num(extra_text)
    total_tokens = self.estimate_token_num(raw_prompt_text)

    # Allow buffer space for potential prompts that will be appended later.
    # Allocates 1/10 of MAX_INPUT_TOKEN per prompt text block, assuming up to 10
    # blocks in the final prompt.
    # TODO(dongge): Move this to prompt builder (e.g., `append()`), dynamically
    # reduce each prompt text block if there is no space for raw_prompt_text.
    allowed_tokens = self.MAX_INPUT_TOKEN // 10 - extra_tokens
    if allowed_tokens <= 0:
      logger.warning('Insufficient tokens to add any text: %d, %d',
                     extra_tokens, allowed_tokens)
      return ''

    # raw_prompt_text already fits within the allowed #tokens, return it as is.
    if total_tokens <= allowed_tokens:
      return raw_prompt_text

    marker = '\n...(truncated due to exceeding input token limit)...\n'
    marker_tokens = self.estimate_token_num(marker)

    # extra_tokens is too large that allowed_tokens cannot include the marker,
    # return just a prefix of raw_prompt_text.
    if allowed_tokens < marker_tokens:
      prefix_index = self._estimate_char_index(allowed_tokens, raw_prompt_text)
      logger.warning('Insufficient tokens to add marker: %d, %d', extra_tokens,
                     allowed_tokens)
      return self.truncate_prompt(raw_prompt_text[:prefix_index], extra_text)

    # Prefix of the truncated prompt, 100 tokens by default.
    prefix_tokens = min(100, allowed_tokens - marker_tokens)
    prefix_index = self._estimate_char_index(prefix_tokens, raw_prompt_text)

    # Extra tokens beyond the allowed limit, with a 50-token buffer.
    excess_tokens = total_tokens - allowed_tokens + 50
    # Suffix keeps the last portion after removal_tokens, that is, remove a
    # block and keep the last (total_tokens - removal_tokens) tokens.
    tokens_before_suffix = prefix_tokens + marker_tokens + excess_tokens
    suffix_index = self._estimate_char_index(tokens_before_suffix,
                                             raw_prompt_text)

    truncated_prompt = (raw_prompt_text[:prefix_index] + marker +
                        raw_prompt_text[suffix_index:])
    logger.info('Truncated %d tokens from %d to %d chars.', excess_tokens,
                len(raw_prompt_text), len(truncated_prompt))
    return self.truncate_prompt(truncated_prompt, extra_text)

  def chat_llm(self, client: ChatSession, prompt: prompts.Prompt) -> str:
    if self.ai_binary:
      logger.info('VertexAI does not use local AI binary: %s', self.ai_binary)

    # TODO(dongge): Use different values for different trials
    parameters_list = self._prepare_parameters()[0]
    response = self._do_generate(client, prompt.get(), parameters_list) or ''
    return response

  def chat_llm_with_tools(self, client: Any, prompt: Optional[prompts.Prompt],
                          tools) -> Any:
    """Queries the LLM in the given chat session with tools."""
    # Placeholder: To Be Implemented.
    return


class GeminiV2FlashChat(GeminiV1D5Chat):
  """Gemini 2 Flash for chat session."""
  name = 'vertex_ai_gemini-2-flash-chat'
  _vertex_ai_model = 'gemini-2.0-flash-001'


class GeminiV2Chat(GeminiV1D5Chat):
  """Gemini 2 for chat session."""
  name = 'vertex_ai_gemini-2-chat'
  _vertex_ai_model = 'gemini-2.0-pro-exp-02-05'


class GeminiV2ThinkChat(GeminiV1D5Chat):
  """Gemini 2 for chat session."""
  name = 'vertex_ai_gemini-2-think-chat'
  _vertex_ai_model = 'gemini-2.0-flash-thinking-exp-01-21'


class GeminiV2D5FlashChat(GeminiV1D5Chat):
  """Gemini 2.5 flash for chat session."""
  _max_output_tokens = 65535
  context_window = 1048576
  name = 'vertex_ai_gemini-2-5-flash-chat'
  _vertex_ai_model = 'gemini-2.5-flash-preview-04-17'


class GeminiV2D5ProChat(GeminiV1D5Chat):
  """Gemini 2.5 pro for chat session."""
  _max_output_tokens = 65535
  context_window = 1048576
  name = 'vertex_ai_gemini-2-5-pro-chat'
  _vertex_ai_model = 'gemini-2.5-pro'


class AIBinaryModel(GoogleModel):
  """A customized model hosted internally."""

  name = 'ai_binary_model'

  def __init__(self, name: str, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.name = name

  def get_model(self) -> Any:
    """Returns the underlying model instance."""
    # Placeholder: No suitable implementation/usage yet.

  def get_chat_client(self, model: Any) -> Any:
    """Returns a new chat session."""
    del model
    # Placeholder: To Be Implemented.

  def chat_llm(self, client: Any, prompt: prompts.Prompt) -> Any:
    """Queries the LLM in the given chat session and returns the response."""
    del client, prompt
    # Placeholder: To Be Implemented.

  def chat_llm_with_tools(self, client: Any, prompt: Optional[prompts.Prompt],
                          tools) -> Any:
    """Queries the LLM in the given chat session with tools."""
    # Placeholder: To Be Implemented.
    return


DefaultModel = GeminiV1D5
