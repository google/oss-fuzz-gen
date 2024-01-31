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

import json
import logging
import os
import random
import re
import subprocess
import sys
import time
from abc import abstractmethod
from typing import Any, Callable, Optional, Tuple, Type

import openai
import tiktoken
import vertexai
from google.api_core.exceptions import GoogleAPICallError
from vertexai.preview.generative_models import GenerativeModel
from vertexai.preview.language_models import CodeGenerationModel

from data_prep import project_targets
from experiment.benchmark import FileType

# Model hyper-parameters.
MAX_TOKENS: int = 2000
NUM_SAMPLES: int = 1
TEMPERATURE: float = 0.4

DEFAULT_TEMPLATE_DIR: str = 'prompts/template_xml/'

# TODO(Dongge): Refactor this tot avoid hard-coding.
# Example files.
EXAMPLE_PATH = os.path.join('prompts', 'example')
# Example with FuzzeDataProvider.
FDP_EXAMPLE_1_PROBLEM = os.path.join(EXAMPLE_PATH, 'gdImageString-problem.txt')
FDP_EXAMPLE_1_SOLUTION = os.path.join(EXAMPLE_PATH, 'gdImageString-solution.cc')
FDP_EXAMPLE_2_PROBLEM = os.path.join(EXAMPLE_PATH, 'mpg123_decode-problem.txt')
FDP_EXAMPLE_2_SOLUTION = os.path.join(EXAMPLE_PATH, 'mpg123_decode-solution.cc')

EXAMPLES = [
    [FDP_EXAMPLE_1_PROBLEM, FDP_EXAMPLE_1_SOLUTION],
    [FDP_EXAMPLE_2_PROBLEM, FDP_EXAMPLE_2_SOLUTION],
]

# Code fixing examples.
FIXER_EXAMPLE_PATH = os.path.join('prompts', 'fixer_example')

FIXER_EXAMPLE_1_CODE = os.path.join(FIXER_EXAMPLE_PATH,
                                    'parse_complex_format_second-code.cc')
FIXER_EXAMPLE_1_ERROR = os.path.join(FIXER_EXAMPLE_PATH,
                                     'parse_complex_format_second-error.txt')
FIXER_EXAMPLE_1_FIX = os.path.join(FIXER_EXAMPLE_PATH,
                                   'parse_complex_format_second-fix.cc')
FIXER_EXAMPLE_2_CODE = os.path.join(FIXER_EXAMPLE_PATH,
                                    'fribidi_log2vis-code.cc')
FIXER_EXAMPLE_2_ERROR = os.path.join(FIXER_EXAMPLE_PATH,
                                     'fribidi_log2vis-error.txt')
FIXER_EXAMPLE_2_FIX = os.path.join(FIXER_EXAMPLE_PATH, 'fribidi_log2vis-fix.cc')

FIXER_EXAMPLES = [
    [FIXER_EXAMPLE_2_CODE, FIXER_EXAMPLE_2_ERROR, FIXER_EXAMPLE_2_FIX],
    [FIXER_EXAMPLE_1_CODE, FIXER_EXAMPLE_1_ERROR, FIXER_EXAMPLE_1_FIX],
]


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
      prompt_path: str,
      template_dir: str = DEFAULT_TEMPLATE_DIR,
      max_tokens: int = MAX_TOKENS,
      num_samples: int = NUM_SAMPLES,
      temperature: float = TEMPERATURE,
  ):
    self.ai_binary = ai_binary
    self.prompt_path = prompt_path

    # Load templates.
    self.priming_template_file = self._find_template(template_dir,
                                                     'priming.txt')
    self.cpp_priming_filler_file = self._find_template(
        template_dir, 'cpp-specific-priming-filler.txt')
    self.problem_template_file = self._find_template(template_dir,
                                                     'problem.txt')
    self.solution_template_file = self._find_template(template_dir,
                                                      'solution.txt')
    self.context_template_file = self._find_template(template_dir,
                                                     'context.txt')
    self.fixer_priming_template_file = self._find_template(
        template_dir, 'fixer_priming.txt')
    self.fixer_problem_template_file = self._find_template(
        template_dir, 'fixer_problem.txt')

    # Model parameters.
    self.max_tokens = max_tokens
    self.num_samples = num_samples
    self.temperature = temperature

    # Prompt message content.
    self._prompt = None  # Must call self._reset_prompt first

  def _find_template(self, template_dir: str, template_name: str) -> str:
    """Find template file based on |template_dir|."""
    preferred_template = os.path.join(template_dir, template_name)
    # Use the preferred template if it exists.
    if os.path.isfile(preferred_template):
      return preferred_template
    # Fall back to the default template.
    default_template = os.path.join(DEFAULT_TEMPLATE_DIR, template_name)
    return default_template

  @classmethod
  def cloud_setup(cls):
    """Run Cloud specific-setup."""
    vertex_ai_locations = os.getenv('VERTEX_AI_LOCATIONS',
                                    'us-central1').split(',')
    location = random.sample(vertex_ai_locations, 1)[0]

    logging.info('Using location %s for vertex AI', location)
    vertexai.init(location=location,)

  @classmethod
  def setup(
      cls,
      ai_binary: str,
      prompt_path: str,
      name: str,
      template_dir: str = DEFAULT_TEMPLATE_DIR,
      max_tokens: int = MAX_TOKENS,
      num_samples: int = NUM_SAMPLES,
      temperature: float = TEMPERATURE,
  ):
    """Prepares the LLM for fuzz target generation."""
    if ai_binary:
      return AIBinaryModel(name, ai_binary, prompt_path, template_dir,
                           max_tokens, num_samples, temperature)

    for subcls in cls.all_llm_subclasses():
      if getattr(subcls, 'name', None) == name:
        return subcls(
            ai_binary,
            prompt_path,
            template_dir,
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

  # ================================ Prompt ================================ #
  def _get_template(self, template_file: str) -> str:
    """Reads the template for prompts."""
    with open(template_file) as file:
      return file.read()

  def _format_priming(self, target_file_type: FileType) -> str:
    """Formats a priming based on the prompt template."""
    priming = self._get_template(self.priming_template_file)
    if target_file_type in [FileType.C, FileType.CPP]:
      type_specific_priming = self._get_template(self.cpp_priming_filler_file)
    else:
      type_specific_priming = ''
    priming = priming.replace('{TYPE_SPECIFIC_PRIMING}', type_specific_priming)
    return priming

  def format_problem(self, problem_content: str) -> str:
    """Formats a problem based on the prompt template."""
    problem = self._get_template(self.problem_template_file)
    problem = problem.replace('{PROBLEM_CONTENT}', problem_content)
    return problem

  def format_solution(self, solution_content: str) -> str:
    """Formats a solution based on the prompt template."""
    solution = self._get_template(self.solution_template_file)
    solution = solution.replace('{SOLUTION_CONTENT}', solution_content)
    return solution

  def format_context(self, header_content: str, type_content: str) -> str:
    context = self._get_template(self.context_template_file)
    context = context.replace('{CONTEXT_HEADER}', header_content)
    context = context.replace('{CONTEXT_TYPES}', type_content)
    return context

  def _select_examples(self, examples: list[list],
                       prompt_size: int) -> list[list[str]]:
    """Selects |examples| based on |prompt_size|."""
    # First remove repeated examples to avoid over fitting.
    targets = set()
    unique_examples = []
    for example in examples:
      if example[2] in targets:
        continue
      targets.add(example[2])
      unique_examples.append(example)

    if (sum(example[0] for example in unique_examples) + prompt_size
        < self.context_window):
      return [[example[1], example[2]] for example in examples]

    # Then prioritize complex (i.e., long) examples.
    unique_examples.sort(key=lambda x: x[0], reverse=True)
    selected_examples = []
    for example in unique_examples:
      if example[0] + prompt_size >= self.context_window:
        # The estimation is inaccurate, if an example's size equals to
        # the limit, it's safer to not include the example.
        continue
      selected_examples.append([example[1], example[2]])
      prompt_size += example[0]

    # Write the most complex examples at the end so that LLM gives them
    # a higher weight.
    selected_examples.sort(key=len, reverse=True)
    return selected_examples

  def _add_examples(self,
                    example_files: list[list[str]],
                    final_problem: str,
                    example_content: Optional[list[list[str]]] = None):
    """Constructs the |example_files| to be used in the prompt."""
    # Estimate prompt size so far.
    prompt_size = self._estimate_token_num(self._prompt)
    # Estimate space needed for the final problem.
    final_problem_prompt = self._create_prompt_piece(final_problem, 'user')
    query_size = prompt_size + self._estimate_token_num(final_problem_prompt)

    # Collect all examples in a single list
    examples = []
    for problem, solution in example_files:
      with open(problem) as problem_file:
        problem = problem_file.read()[:-1]
      with open(solution) as solution_file:
        solution = solution_file.read()[:-1]
        solution = project_targets.filter_target_lines(solution)
      examples.append((problem, solution))
    # TODO(mihaimaruseac): Should we start from these first?
    if example_content:
      for problem, solution in example_content:
        solution = project_targets.filter_target_lines(solution)
        examples.append((problem, solution))

    # Next, we need to expand all templates and determine how much the size
    # of the prompt would increase when adding each one of them:
    weights = []
    for problem, solution in examples:
      problem = self.format_problem(problem)
      solution = self.format_solution(solution)
      problem_prompt = self._create_prompt_piece(problem, 'user')
      solution_prompt = self._create_prompt_piece(solution, 'assistant')
      problem_weight = self._estimate_token_num(problem_prompt)
      solution_weight = self._estimate_token_num(solution_prompt)
      total_weight = problem_weight + solution_weight + 1  # one \n
      weights.append((total_weight, problem, solution))

    # Select examples up to context window and add them to prompt.
    selected_examples = self._select_examples(weights, query_size)
    for problem, solution in selected_examples:
      self._add_problem(problem)
      self._add_solution(solution)

  def save_prompt(self, prompt_path: str) -> str:
    """Saves the prompt to the |prompt_path|."""
    prompt_name, prompt_ext = os.path.splitext(prompt_path)
    prompt_path = f'{prompt_name}{prompt_ext}'
    with open(prompt_path, 'w+') as prompt_file:
      if isinstance(self._prompt, str):
        prompt_file.write(self._prompt)
      elif isinstance(self._prompt, list):
        json.dump(self._prompt, prompt_file)
      else:
        print(f'Error: Invalid prompt type: {type(self._prompt)}.')
    return prompt_path

  def prepare_generate_prompt(
      self,
      prompt_path: str,
      function_signature: str,
      target_file_type: FileType,
      example_pair: list[list[str]],
      project_example_content: Optional[list[list[str]]] = None,
      project_context_content: Optional[Tuple[str, str]] = None) -> str:
    """Constructs a prompt using the templates in |self| and saves it."""
    priming = self._format_priming(target_file_type)
    final_problem = self.format_problem(function_signature)
    final_problem += (f'You MUST call <code>\n'
                      f'{function_signature}\n'
                      f'</code> in your solution!\n')
    # TODO(ggryan@): Add a function to ensure the header is consistent
    # with others (e.g., use "" or <>, use the same path prefix
    # with other non-builtin include statements or the original fuzz target.)
    if project_context_content:
      final_problem += self.format_context(project_context_content[0],
                                           project_context_content[1])
    final_problem += '\n<solution>'
    return self.prepare_prompt(prompt_path, priming, final_problem,
                               example_pair, project_example_content)

  def format_fixer_priming(self) -> str:
    """Formats a priming for code fixer based on the template."""
    with open(self.fixer_priming_template_file) as f:
      priming = f.read().strip() + '\n'
    priming_prompt = self._create_prompt_piece(priming, 'system')
    return priming_prompt

  def format_fixer_problem(self, raw_code: str, errors: list[str],
                           priming_weight: int) -> str:
    """Formats a problem for code fixer based on the template."""
    with open(self.fixer_problem_template_file) as f:
      problem = f.read().strip()
    # Last 2 lines removed for LLM to complete.
    problem = problem.rsplit("\n", 2)[0]
    problem = problem.replace('{CODE_TO_BE_FIXED}', raw_code)

    problem_prompt = self._create_prompt_piece(problem, 'user')
    template_piece = self._create_prompt_piece('{ERROR_MESSAGES}', 'user')

    problem_weight = self._estimate_token_num(problem_prompt)
    template_weight = self._estimate_token_num(template_piece)

    # the template will be replaced later and should not be counted
    prompt_size = priming_weight + problem_weight - template_weight
    # Add extra 20-tokens redundancy
    # TODO(mihaimaruseac): Is this needed?
    prompt_size += 20

    # We are adding errors one by one until we reach the maximum prompt size
    selected_errors = []
    skip_line = 0
    for error in errors:
      # TODO: remove this
      if "fatal error: 'algorithm' file not found" in error:
        skip_line = 3
      if skip_line > 0:
        skip_line -= 1
        continue
      error_prompt = self._create_prompt_piece(error, 'user')
      error_token_num = self._estimate_token_num(error_prompt)
      if prompt_size + error_token_num >= self.context_window:
        # The estimation is inaccurate, if an example's size equals to
        # the limit, it's safer to not include the example.
        break
      prompt_size += error_token_num
      selected_errors.append(error)

    # Now, compose the problem part of the prompt
    error_message = '\n'.join(selected_errors)
    return problem.replace('{ERROR_MESSAGES}', error_message)

  def format_fixer_examples(self, example_files: list[list[str]]):
    """Formats code fixing examples based on the problem template."""
    # TODO(jimchoi): calculate the prompt size and select example
    #  when size is too large, maybe refactor and reuse _select_examples()
    examples = []
    for code, error, fix in example_files:
      with open(self.fixer_problem_template_file) as f:
        problem = f.read().strip()
      with open(code) as f:
        code = f.read().strip()
        problem = problem.replace('{CODE_TO_BE_FIXED}',
                                  project_targets.filter_target_lines(code))
      with open(error) as f:
        error = f.read().strip()
        problem = problem.replace('{ERROR_MESSAGES}', error)
      with open(fix) as f:
        fix = f.read().strip()
        problem = problem.replace('{FIXED_CODE}',
                                  project_targets.filter_target_lines(fix))
      examples.append(problem)
    return '\n\n'.join(examples)

  def prepare_fix_prompt(self, prompt_path: str, raw_code: str,
                         errors: list[str]) -> str:
    """Prepares the code-fixing prompt."""
    priming = self.format_fixer_priming()
    priming_weight = self._estimate_token_num(priming)
    problem = self.format_fixer_problem(raw_code, errors, priming_weight)

    examples = self.format_fixer_examples(FIXER_EXAMPLES)

    return self.prepare_prompt(prompt_path, priming,
                               examples + '\n\n' + problem)

  def prepare_prompt(
      self,
      prompt_path: str,
      priming: str,
      final_problem: str,
      example_pair: Optional[list[list[str]]] = None,
      project_example_content: Optional[list[list[str]]] = None) -> str:
    """Constructs a prompt using the parameters and saves it."""
    self._reset_prompt()
    self._add_priming(priming)

    if example_pair is None:
      example_pair = []

    self._add_examples(example_pair, final_problem, project_example_content)
    self._add_problem(final_problem)
    return self.save_prompt(prompt_path)

  @abstractmethod
  def _estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""

  @abstractmethod
  def _reset_prompt(self) -> None:
    """Resets prompt to empty."""

  @abstractmethod
  def _create_prompt_piece(self, content: str, role: str) -> Any:
    """Creates prompt based on the |content| and |role|."""

  @abstractmethod
  def _add_priming(self, priming_content: str) -> None:
    """Adds |priming_content| to prompt."""

  @abstractmethod
  def _add_problem(self, problem_content: str) -> None:
    """Adds |problem_content| to prompt."""

  @abstractmethod
  def _add_solution(self, solution_content: str) -> None:
    """Adds |solution_content| to prompt."""

  # ============================== Generation ============================== #
  @abstractmethod
  def generate_code(self, response_dir: str, log_output: bool = False) -> None:
    """Generates fuzz targets to the |response_dir|."""

  def with_retry_on_error(self, func: Callable,
                          err_type: Type[Exception]) -> Any:
    """
    Retry when the function returns an expected error with exponential backoff.
    """
    for attempt in range(self._max_attempts):
      try:
        return func()
      except err_type as err:
        # Exponentially increase from 5 to 80 seconds
        # + some random to jitter.
        delay = 5 * 2**attempt + random.randint(1, 5)
        print(f'Error generating LLM response\n'
              f'{err}')

        if attempt == self._max_attempts - 1:
          raise err

        print(f'Retry in {delay}s...')
        time.sleep(delay)
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
  def _estimate_token_num(self, text) -> int:
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

  def _reset_prompt(self) -> None:
    """Prepares the prompt for GPT based models."""
    self._prompt = []

  def _create_prompt_piece(self, content: str, role: str):
    """Returns a prompt piece in the format wanted by OpenAI."""
    # TODO(mihaimaruseac): We might want to consider stripping the XML tags
    # here? The roles kind of simulate them.
    return [{'role': role, 'content': content}]

  def _add_priming(self, priming_content: str) -> None:
    """Constructs the prompt priming in the required format."""
    self._prompt.append({
        'role': 'system',
        'content': priming_content,
    })

  def _add_problem(self, problem_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._prompt.append({
        'role': 'user',
        'content': problem_content,
    })

  def _add_solution(self, solution_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._prompt.append({
        'role': 'assistant',
        'content': solution_content,
    })

  # ============================== Generation ============================== #
  def generate_code(self, response_dir: str, log_output: bool = False) -> None:
    """Generates code with OpenAI's API."""
    if self.ai_binary:
      print(f'OpenAI does not use local AI binary: {self.ai_binary}')
    openai.api_key = os.getenv('OPENAI_API_KEY')

    completion = self.with_retry_on_error(
        lambda: openai.ChatCompletion.create(messages=self._prompt,
                                             model=self.name,
                                             n=self.num_samples,
                                             temperature=self.temperature),
        openai.OpenAIError)
    if log_output:
      print(completion)
    for index, choice in enumerate(completion.choices):  # type: ignore
      content = choice.message['content']
      self._save_output(index, content, response_dir)


class GPT4(GPT):
  """OpenAI's GPTi-4 model."""

  name = 'gpt-4'


class GoogleModel(LLM):
  """Generic Google model."""

  def _estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""
    # Roughly 1.5 tokens per word:
    return int(len(re.split('[^a-zA-Z0-9]+', text)) * 1.5 + 0.5)

  def _reset_prompt(self) -> None:
    """Prepares the prompt for Google models."""
    self._prompt = ""

  def _create_prompt_piece(self, content: str, role: str):
    """Returns a prompt piece in the format wanted by Google."""
    # Ignore role, just return content
    del role
    # TODO(Dongge): Use role as XML tags.
    return content

  def _add_priming(self, priming_content: str) -> None:
    """Constructs the prompt priming in the required format."""
    self._prompt += f'{priming_content}\n'

  def _add_problem(self, problem_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._prompt += f'{problem_content}\n'

  def _add_solution(self, solution_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._prompt += f'{solution_content}\n'

  # ============================== Generation ============================== #
  def generate_code(self, response_dir: str, log_output: bool = False) -> None:
    """Generates code with internal LLM."""
    if not self.ai_binary:
      print(f'Error: This model requires a local AI binary: {self.ai_binary}')
      sys.exit(1)
    command = [
        self.ai_binary,
        f'-model={self.name}',
        f'-prompt={self.prompt_path}',
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
      print(f'Failed to generate targets with prompt {self._prompt}')
      print(f'stdout: {stdout}')
      print(f'stderr: {stderr}')


class VertexAIModel(GoogleModel):
  """Vertex AI model."""

  _vertex_ai_model = ''
  _max_output_tokens = 2048

  def get_model(self) -> Any:
    return CodeGenerationModel.from_pretrained(self._vertex_ai_model)

  def do_generate(self, model: Any, prompt: str, config: dict[str, Any]) -> Any:
    return model.predict(prefix=prompt, **config).text

  def generate_code(self, response_dir: str, log_output: bool = False) -> None:
    del log_output
    if self.ai_binary:
      print(f'VertexAI does not use local AI binary: {self.ai_binary}')

    model = self.get_model()
    parameters = {
        'temperature': self.temperature,
        'max_output_tokens': self._max_output_tokens,
    }

    with open(self.prompt_path) as f:
      prompt = f.read()

    for index in range(self.num_samples):
      response = self.with_retry_on_error(
          lambda: self.do_generate(model, prompt, parameters),
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

  name = 'vertex_ai_gemini-pro'
  _vertex_ai_model = 'gemini-pro'


class AIBinaryModel(GoogleModel):
  """A customized model hosted internally."""

  name = 'ai_binary_model'

  def __init__(self, name: str, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.name = name


DefaultModel = VertexAICodeBison32KModel
