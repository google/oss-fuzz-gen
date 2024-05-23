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
Prompt building tools.
"""

import logging
import os
from abc import abstractmethod
from typing import Optional, Tuple

import jinja2
import requests
import yaml

from data_prep import project_targets
from experiment.benchmark import Benchmark, FileType
from experiment.fuzz_target_error import SemanticCheckResult
from llm_toolkit import models, prompts
from llm_toolkit.code_fixer import group_error_messages

DEFAULT_TEMPLATE_DIR: str = 'prompts/template_xml/'

# TODO(Dongge): Refactor this tot avoid hard-coding.
# Example files.
EXAMPLE_PATH = os.path.join('prompts', 'example')
# Example with FuzzeDataProvider.
FDP_EXAMPLE_1_PROBLEM = os.path.join(EXAMPLE_PATH, 'gdImageString-problem.txt')
FDP_EXAMPLE_1_SOLUTION = os.path.join(EXAMPLE_PATH, 'gdImageString-solution.cc')
FDP_EXAMPLE_2_PROBLEM = os.path.join(EXAMPLE_PATH, 'mpg123_decode-problem.txt')
FDP_EXAMPLE_2_SOLUTION = os.path.join(EXAMPLE_PATH, 'mpg123_decode-solution.cc')
FDP_JVM_EXAMPLE_1_PROBLEM = os.path.join(EXAMPLE_PATH, 'joni_regex-problem.txt')
FDP_JVM_EXAMPLE_1_SOLUTION = os.path.join(EXAMPLE_PATH,
                                          'joni_regex-solution.java')
FDP_JVM_EXAMPLE_2_PROBLEM = os.path.join(EXAMPLE_PATH,
                                         'jansi_colors-problem.txt')
FDP_JVM_EXAMPLE_2_SOLUTION = os.path.join(EXAMPLE_PATH,
                                          'jansi_colors-solution.java')

EXAMPLES = {
    'c++': [
        [FDP_EXAMPLE_1_PROBLEM, FDP_EXAMPLE_1_SOLUTION],
        [FDP_EXAMPLE_2_PROBLEM, FDP_EXAMPLE_2_SOLUTION],
    ],
    'c': [
        [FDP_EXAMPLE_1_PROBLEM, FDP_EXAMPLE_1_SOLUTION],
        [FDP_EXAMPLE_2_PROBLEM, FDP_EXAMPLE_2_SOLUTION],
    ],
    'jvm': [
        [FDP_JVM_EXAMPLE_1_PROBLEM, FDP_JVM_EXAMPLE_1_SOLUTION],
        [FDP_JVM_EXAMPLE_2_PROBLEM, FDP_JVM_EXAMPLE_2_SOLUTION],
    ],
}

BUILD_ERROR_SUMMARY = 'The code has the following build issues:'
FUZZ_ERROR_SUMMARY = 'The code can build successfully but has a runtime issue: '


class PromptBuilder:
  """Prompt builder."""

  def __init__(self, model: models.LLM):
    self._model = model
    self._prompt = model.prompt_type()()

  @abstractmethod
  def build(self,
            function_signature: str,
            target_file_type: FileType,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Builds a prompt."""

  @abstractmethod
  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Builds a fixer prompt."""


class DefaultTemplateBuilder(PromptBuilder):
  """Default builder for C/C++."""

  def __init__(self,
               model: models.LLM,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir

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

  def _format_priming(self, target_file_type: FileType) -> str:
    """Formats a priming based on the prompt template."""
    priming = self._get_template(self.priming_template_file)
    if target_file_type in [FileType.C, FileType.CPP]:
      type_specific_priming = self._get_template(self.cpp_priming_filler_file)
    else:
      type_specific_priming = ''
    priming = priming.replace('{TYPE_SPECIFIC_PRIMING}', type_specific_priming)
    return priming

  def _find_template(self, template_dir: str, template_name: str) -> str:
    """Finds template file based on |template_dir|."""
    preferred_template = os.path.join(template_dir, template_name)
    # Use the preferred template if it exists.
    if os.path.isfile(preferred_template):
      return preferred_template
    # Fall back to the default template.
    default_template = os.path.join(DEFAULT_TEMPLATE_DIR, template_name)
    return default_template

  def _get_template(self, template_file: str) -> str:
    """Reads the template for prompts."""
    with open(template_file) as file:
      return file.read()

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

  def format_context(self, context_info: dict) -> str:
    context = jinja2.Template(self._get_template(self.context_template_file),
                              trim_blocks=True,
                              lstrip_blocks=True)
    return context.render(
        headers='\n'.join(context_info['files']),
        must_insert=context_info['decl'],
        func_source=context_info['func_source'],
        xrefs='\n'.join(context_info['xrefs']),
    )

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
        < self._model.context_window):
      return [[example[1], example[2]] for example in examples]

    # Then prioritize complex (i.e., long) examples.
    unique_examples.sort(key=lambda x: x[0], reverse=True)
    selected_examples = []
    for example in unique_examples:
      if example[0] + prompt_size >= self._model.context_window:
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
    prompt_size = self._model.estimate_token_num(self._prompt.get())
    # Estimate space needed for the final problem.
    final_problem_prompt = self._prompt.create_prompt_piece(
        final_problem, 'user')
    query_size = prompt_size + self._model.estimate_token_num(
        final_problem_prompt)

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
      problem_prompt = self._prompt.create_prompt_piece(problem, 'user')
      solution_prompt = self._prompt.create_prompt_piece(solution, 'assistant')
      problem_weight = self._model.estimate_token_num(problem_prompt)
      solution_weight = self._model.estimate_token_num(solution_prompt)
      total_weight = problem_weight + solution_weight + 1  # one \n
      weights.append((total_weight, problem, solution))

    # Select examples up to context window and add them to prompt.
    selected_examples = self._select_examples(weights, query_size)
    for problem, solution in selected_examples:
      self._prompt.add_problem(problem)
      self._prompt.add_solution(solution)

  def build(self,
            function_signature: str,
            target_file_type: FileType,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    priming = self._format_priming(target_file_type)
    final_problem = self.format_problem(function_signature)
    final_problem += (f'You MUST call <code>\n'
                      f'{function_signature}\n'
                      f'</code> in your solution!\n')
    if project_context_content:
      final_problem += self.format_context(project_context_content)
    final_problem += '\n<solution>'
    self._prepare_prompt(priming, final_problem, example_pair,
                         project_example_content)
    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Prepares the code-fixing prompt."""
    priming, priming_weight = self._format_fixer_priming()
    problem = self._format_fixer_problem(benchmark, raw_code, error_desc,
                                         errors, priming_weight)

    self._prepare_prompt(priming, problem)
    return self._prompt

  def _format_fixer_priming(self) -> Tuple[str, int]:
    """Formats a priming for code fixer based on the template."""
    with open(self.fixer_priming_template_file) as f:
      priming = f.read().strip() + '\n'
    priming_prompt = self._prompt.create_prompt_piece(priming, 'system')
    priming_weight = self._model.estimate_token_num(priming_prompt)
    # NOTE: We need to return the priming _as text_ and the weight. Otherwise,
    # in the case of structured prompts, we will create nested structures.
    return priming, priming_weight

  def _format_fixer_problem(self, benchmark: Benchmark, raw_code: str,
                            error_desc: Optional[str], errors: list[str],
                            priming_weight: int) -> str:
    """Formats a problem for code fixer based on the template."""
    with open(self.fixer_problem_template_file) as f:
      problem = f.read().strip()
    problem = problem.replace('{CODE_TO_BE_FIXED}', raw_code)
    if error_desc:
      error_summary = FUZZ_ERROR_SUMMARY + error_desc
    else:
      # Build error does not pass error desc.
      error_summary = BUILD_ERROR_SUMMARY
    problem = problem.replace('{ERROR_SUMMARY}', error_summary)

    problem_prompt = self._prompt.create_prompt_piece(problem, 'user')
    error_template_piece = self._prompt.create_prompt_piece(
        '{ERROR_MESSAGES}', 'user')
    info_template_piece = self._prompt.create_prompt_piece('{AUX_INFO}', 'user')

    problem_weight = self._model.estimate_token_num(problem_prompt)
    template_weight = (self._model.estimate_token_num(error_template_piece) +
                       self._model.estimate_token_num(info_template_piece))

    # The template will be replaced later and should not be counted.
    prompt_size = priming_weight + problem_weight - template_weight
    # Add extra 20-tokens redundancy.
    # TODO(mihaimaruseac): Is this needed?
    prompt_size += 20

    # We are processing errors one by one until the maximum prompt size reached.
    selected_errors = []
    aux_info = []
    error_analyzer = group_error_messages(benchmark, errors)
    for error in error_analyzer.errors:
      error_str, aux_str = error_analyzer.process_error(error)

      error_token_num = 0
      aux_token_num = 0
      if error_str:
        error_prompt = self._prompt.create_prompt_piece(error_str, 'user')
        error_token_num = self._model.estimate_token_num(error_prompt)
      if aux_str:
        aux_prompt = self._prompt.create_prompt_piece(aux_str, 'user')
        aux_token_num = self._model.estimate_token_num(aux_prompt)
      if (prompt_size + error_token_num + aux_token_num
          >= self._model.context_window):
        # The estimation is inaccurate, if an example's size equals to
        # the limit, it's safer to not include the example.
        break
      prompt_size += error_token_num + aux_token_num
      if error_str:
        selected_errors.append(error_str)
      if aux_str:
        aux_info.append(aux_str)

    # Now, compose the problem part of the prompt
    problem = problem.replace('{AUX_INFO}', '\n'.join(aux_info))
    problem = problem.replace('{ERROR_MESSAGES}', '\n'.join(selected_errors))
    if aux_info or selected_errors:
      return problem

    # Expecting empty error message for NO_COV_INCREASE.
    if SemanticCheckResult.is_no_cov_increase_err(error_desc):
      return problem.replace('<error>\n', '')\
                    .replace('{ERROR_MESSAGES}\n', '')\
                    .replace('</error>\n', '')

    # Logging for empty error messages block.
    if not errors and not error_desc:
      logging.warning('Unexpected empty errors and error_desc')
    elif error_desc:
      logging.info('Using error_desc: %s', str(error_desc))
    else:
      logging.info('Empty error_desc, no error selected for prompt')
    return problem

  def _prepare_prompt(
      self,
      priming: str,
      final_problem: str,
      example_pair: Optional[list[list[str]]] = None,
      project_example_content: Optional[list[list[str]]] = None):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(priming)

    if example_pair is None:
      example_pair = []

    self._add_examples(example_pair, final_problem, project_example_content)
    self._prompt.add_problem(final_problem)


class DefaultJvmTemplateBuilder(PromptBuilder):
  """Default builder for JVM projects."""

  def __init__(self,
               model: models.LLM,
               project_name: str,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir
    self.project_name = project_name
    self.project_url = self._find_project_url(project_name)

    # Load templates.
    self.base_template_file = self._find_template(template_dir, 'jvm_base.txt')
    self.data_filler_template_file = self._find_template(
        template_dir, 'jvm_specific_data_filler.txt')
    self.problem_template_file = self._find_template(template_dir,
                                                     'jvm_problem.txt')
    self.requirement_template_file = self._find_template(
        template_dir, 'jvm_requirement.txt')

  def _find_project_url(self, project_name: str) -> str:
    """Discover project url from project's project.yaml in OSS-Fuzz"""
    oss_fuzz_url = 'https://raw.githubusercontent.com/google/oss-fuzz/master'
    project_url = f'{oss_fuzz_url}/projects/{project_name}/project.yaml'

    try:
      response = requests.get(project_url, timeout=20)
      if response and response.status_code == 200:
        project_yaml = yaml.load(response.content, Loader=yaml.SafeLoader)
        if 'main_repo' in project_yaml:
          return project_yaml['main_repo']
    except:
      pass

    print(f'Cannot retrieve project url of project {project_name}')
    return ''

  def _find_template(self, template_dir: str, template_name: str) -> str:
    """Finds template file based on |template_dir|."""
    preferred_template = os.path.join(template_dir, template_name)
    # Use the preferred template if it exists.
    if os.path.isfile(preferred_template):
      return preferred_template
    # Fall back to the default template.
    default_template = os.path.join(DEFAULT_TEMPLATE_DIR, template_name)
    return default_template

  def _get_template(self, template_file: str) -> str:
    """Reads the template for prompts."""
    with open(template_file) as file:
      return file.read()

  def _format_base(self) -> str:
    """Formats a priming based on the prompt template."""
    base = self._get_template(self.base_template_file)
    base = base.replace("{PROJECT_NAME}", self.project_name)
    base = base.replace("{PROJECT_URL}", self.project_url)
    return base

  def _format_problem(self, problem_content: str) -> str:
    """Formats a problem based on the prompt template."""
    problem = self._get_template(self.problem_template_file)
    problem = problem.replace('{PROBLEM_CONTENT}', problem_content)
    problem = problem.replace('{REQUIREMENTS}', self._format_requirement())
    problem = problem.replace('{DATA_MAPPING}', self._format_data_filler())
    return problem

  def _format_requirement(self) -> str:
    """Formats a requirement based on the prompt template."""
    requirement = self._get_template(self.requirement_template_file)
    return requirement

  def _format_data_filler(self) -> str:
    """Formats a data_filler based on the prompt template."""
    data_filler = self._get_template(self.data_filler_template_file)
    return data_filler

  def _prepare_prompt(self, base: str, final_problem: str):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(base)
    self._prompt.add_problem(final_problem)

  def build(self,
            function_signature: str,
            target_file_type: FileType,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it.
       Ignore target_file_type, project_example_content
       and project_context_content parameters.
    """
    base = self._format_base()
    final_problem = self._format_problem(function_signature)
    self._prepare_prompt(base, final_problem)

    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Builds a fixer prompt."""
    # Do nothing for jvm project now.
    return self._prompt
