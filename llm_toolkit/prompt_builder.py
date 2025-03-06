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
import re
from abc import abstractmethod
from typing import Any, Optional, Tuple

import jinja2

from data_prep import introspector, project_targets
from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark, FileType
from experiment.fuzz_target_error import SemanticCheckResult
from llm_toolkit import models, prompts
from results import BuildResult

logger = logging.getLogger(__name__)

DEFAULT_TEMPLATE_DIR: str = os.path.join(os.path.dirname(__file__),
                                         '../prompts/template_xml/')
AGENT_TEMPLATE_DIR: str = os.path.join(os.path.dirname(__file__),
                                       '../prompts/agent/')

# TODO(Dongge): Refactor this tot avoid hard-coding.
# Example files.
EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), '..', 'prompts',
                            'example')
# Example with FuzzeDataProvider.
FDP_EXAMPLE_1_PROBLEM = os.path.join(EXAMPLE_PATH, 'gdImageString-problem.txt')
FDP_EXAMPLE_1_SOLUTION = os.path.join(EXAMPLE_PATH, 'gdImageString-solution.cc')
FDP_EXAMPLE_2_PROBLEM = os.path.join(EXAMPLE_PATH, 'mpg123_decode-problem.txt')
FDP_EXAMPLE_2_SOLUTION = os.path.join(EXAMPLE_PATH, 'mpg123_decode-solution.cc')
C_EXAMPLE_1_PROBLEM = os.path.join(EXAMPLE_PATH, 'fuzzerPolygonToCells.txt')
C_EXAMPLE_1_SOLUTION = os.path.join(EXAMPLE_PATH, 'fuzzerPolygonToCells.c')
C_EXAMPLE_2_PROBLEM = os.path.join(EXAMPLE_PATH, 'dns_message_parse.txt')
C_EXAMPLE_2_SOLUTION = os.path.join(EXAMPLE_PATH, 'dns_message_parse.c')
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
        [C_EXAMPLE_1_PROBLEM, C_EXAMPLE_1_SOLUTION],
        [C_EXAMPLE_2_PROBLEM, C_EXAMPLE_2_SOLUTION],
    ],
    'jvm': [
        [FDP_JVM_EXAMPLE_1_PROBLEM, FDP_JVM_EXAMPLE_1_SOLUTION],
        [FDP_JVM_EXAMPLE_2_PROBLEM, FDP_JVM_EXAMPLE_2_SOLUTION],
    ],
}

BUILD_ERROR_SUMMARY = 'The code has the following build issues:'
FUZZ_ERROR_SUMMARY = 'The code can build successfully but has a runtime issue: '

C_PROMPT_HEADERS_TO_ALWAYS_INCLUDES = ['stdio.h', 'stdlib.h', 'stdint.h']


class PromptBuilder:
  """Prompt builder."""

  def __init__(self, model: models.LLM, initial=None):
    self._model = model
    self._prompt = model.prompt_type()(initial)

  @abstractmethod
  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Builds a prompt."""

  @abstractmethod
  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Builds a fixer prompt."""

  @abstractmethod
  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Builds a triager prompt."""

  def post_process_generated_code(self, generated_code: str) -> str:
    """Allows prompt builder to adjust the generated code."""
    # return the same by default
    return generated_code


class DefaultTemplateBuilder(PromptBuilder):
  """Default builder for C/C++."""

  def __init__(self,
               model: models.LLM,
               benchmark: Optional[Benchmark] = None,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, initial)
    self._template_dir = template_dir
    self.benchmark = benchmark

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
    self.fixer_context_template_file = self._find_template(
        template_dir, 'fixer_context.txt')
    self.fixer_instruction_template_file = self._find_template(
        template_dir, 'fixer_instruction.txt')
    self.triager_priming_template_file = self._find_template(
        template_dir, 'triager_priming.txt')
    self.triager_problem_template_file = self._find_template(
        template_dir, 'triager_problem.txt')

  def _format_priming(self, benchmark: Benchmark) -> str:
    """Formats a priming based on the prompt template."""
    priming = self._get_template(self.priming_template_file)
    priming = priming.replace('{LANGUAGE}', benchmark.file_type.value)
    priming = priming.replace('{FUZZ_TARGET_PATH}', benchmark.target_path)
    # TODO(Dongge): Add project name and fuzz target file path.
    if benchmark.needs_extern:
      priming += (
          'IMPORTANT: The fuzz target is written in C++, whereas the '
          'project-under-test is written in C. All headers, functions, and code'
          'from the project must be consistently wrapped in '
          '<code>extern "C"</code> to ensure error-free compilation and linkage'
          'between C and C++:\n<code>\nextern "C" {\n    //Include necessary C '
          'headers, source files, functions, and code here.\n}\n</code>\n')
    if benchmark.file_type == FileType.CPP:
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
        include_statement=context_info['header'],
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
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    if not self.benchmark:
      return self._prompt
    priming = self._format_priming(self.benchmark)
    final_problem = self.format_problem(self.benchmark.function_signature)
    final_problem += (f'You MUST call <code>\n'
                      f'{self.benchmark.function_signature}\n'
                      f'</code> in your solution!\n')
    if project_context_content:
      final_problem += self.format_context(project_context_content)
    final_problem += '\n<solution>'
    self._prepare_prompt(priming, final_problem, example_pair,
                         project_example_content)
    return self._prompt

  def build_fixer_prompt(self,
                         benchmark: Benchmark,
                         raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str],
                         context: str = '',
                         instruction: str = '') -> prompts.Prompt:
    """Prepares the code-fixing prompt."""
    priming, priming_weight = self._format_fixer_priming(benchmark)
    problem = self._format_fixer_problem(raw_code, error_desc, errors,
                                         priming_weight, context, instruction)

    self._prepare_prompt(priming, problem)
    return self._prompt

  def _format_fixer_priming(self, benchmark: Benchmark) -> Tuple[str, int]:
    """Formats a priming for code fixer based on the template."""
    with open(self.fixer_priming_template_file) as f:
      priming = f.read().strip() + '\n'
    priming = priming.replace('{LANGUAGE}', benchmark.file_type.value)
    if benchmark.needs_extern:
      priming += ('\nNote that some code may need to be wrapped with '
                  '<code>extern "C"</code> because the project under test is '
                  'written in C but the fuzz target is in C++.\n')
    priming_prompt = self._prompt.create_prompt_piece(priming, 'system')
    priming_weight = self._model.estimate_token_num(priming_prompt)
    # NOTE: We need to return the priming _as text_ and the weight. Otherwise,
    # in the case of structured prompts, we will create nested structures.
    return priming, priming_weight

  def _format_fixer_problem(self, raw_code: str, error_desc: Optional[str],
                            errors: list[str], priming_weight: int,
                            context: str, instruction: str) -> str:
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

    if context:
      with open(self.fixer_context_template_file) as f:
        context_template = f.read().strip()
      context = context_template.replace('{CONTEXT_SOURCE_CODE}', context)
    problem = problem.replace('{CONTEXT}', context)

    if instruction:
      with open(self.fixer_instruction_template_file) as f:
        instruction_template = f.read().strip()
      instruction = instruction_template.replace('{INSTRUCTION}', instruction)
    problem = problem.replace('{INSTRUCTION}', instruction)

    problem_prompt = self._prompt.create_prompt_piece(problem, 'user')
    template_piece = self._prompt.create_prompt_piece('{ERROR_MESSAGES}',
                                                      'user')

    problem_weight = self._model.estimate_token_num(problem_prompt)
    template_weight = self._model.estimate_token_num(template_piece)

    # the template will be replaced later and should not be counted
    prompt_size = priming_weight + problem_weight - template_weight
    # Add extra 20-tokens redundancy
    # TODO(mihaimaruseac): Is this needed?
    prompt_size += 20

    # We are adding errors one by one until we reach the maximum prompt size
    selected_errors = []
    for error in errors:
      error_prompt = self._prompt.create_prompt_piece(error, 'user')
      error_token_num = self._model.estimate_token_num(error_prompt)
      if prompt_size + error_token_num >= self._model.context_window:
        # The estimation is inaccurate, if an example's size equals to
        # the limit, it's safer to not include the example.
        break
      prompt_size += error_token_num
      selected_errors.append(error)

    # Now, compose the problem part of the prompt
    error_message = '\n'.join(selected_errors)
    if error_message.strip():
      return problem.replace('{ERROR_MESSAGES}', error_message)

    # Expecting empty error message for NO_COV_INCREASE.
    if SemanticCheckResult.is_no_cov_increase_err(error_desc):
      return problem.replace('<error>\n', '')\
                    .replace('{ERROR_MESSAGES}\n', '')\
                    .replace('</error>\n', '')

    # Log warning for an unexpected empty error message.
    logger.warning(
        'Unexpected empty error message in fix prompt for error_desc: %s',
        str(error_desc))
    return problem.replace('{ERROR_MESSAGES}', error_message)

  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Prepares the crash-triaging prompt."""
    priming, priming_weight = self._format_triager_priming()
    problem = self._format_triager_problem(benchmark, driver_code, crash_info,
                                           crash_func, priming_weight)

    self._prepare_prompt(priming, problem)
    return self._prompt

  def _format_triager_priming(self) -> Tuple[str, int]:
    """Formats a priming for crash triage based on the template."""
    with open(self.triager_priming_template_file) as f:
      priming = f.read().strip() + '\n'
    priming_prompt = self._prompt.create_prompt_piece(priming, 'system')
    priming_weight = self._model.estimate_token_num(priming_prompt)
    # NOTE: We need to return the priming _as text_ and the weight. Otherwise,
    # in the case of structured prompts, we will create nested structures.
    return priming, priming_weight

  def _format_triager_problem(self, benchmark: Benchmark, driver_code: str,
                              crash_info: str, crash_func: dict,
                              priming_weight: int) -> str:
    """Formats a problem for crash triage based on the template."""
    all_func_code = []
    for func_name, line_number in crash_func.items():
      if func_name == 'LLVMFuzzerTestOneInput':
        driver_code = self._slice_driver_code(benchmark.project, driver_code,
                                              line_number)
      else:
        func_code = self._slice_func_code(benchmark.project, func_name,
                                          line_number)
        all_func_code.append(func_code)

    with open(self.triager_problem_template_file) as f:
      problem = f.read().strip()
    problem = problem.replace('{CRASH_REPORT}', crash_info.strip())\
                     .replace('{DRIVER_CODE}', driver_code.strip())

    problem_prompt = self._prompt.create_prompt_piece(problem, 'user')
    template_piece = self._prompt.create_prompt_piece('{PROJECT_FUNCTION_CODE}',
                                                      'user')

    problem_weight = self._model.estimate_token_num(problem_prompt)
    template_weight = self._model.estimate_token_num(template_piece)

    prompt_size = priming_weight + problem_weight - template_weight
    # Add extra 20-tokens redundancy
    prompt_size += 20

    # Add function code one by one until we reach the maximum prompt size
    selected_func_code = []
    for func_code in all_func_code:
      func_code_prompt = self._prompt.create_prompt_piece(func_code, 'user')
      func_code_token_num = self._model.estimate_token_num(func_code_prompt)
      if prompt_size + func_code_token_num >= self._model.context_window:
        # The estimation is inaccurate, if an example's size equals to
        # the limit, it's safer to not include the example.
        logger.warning('Breaking because adding this function code \
              would exceed context window')
        break
      prompt_size += func_code_token_num
      selected_func_code.append(func_code)

    # Compose the problem part of the prompt
    project_function_code = '\n'.join(selected_func_code)
    if project_function_code.strip():
      return problem.replace('{PROJECT_FUNCTION_CODE}',
                             project_function_code.strip())

    logger.warning(
        'Empty project function code in triage prompt for project: %s, \
          function name: %s', benchmark.project, benchmark.function_name)

    return problem.replace('{PROJECT_FUNCTION_CODE}', \
                           'No relevant project function code')

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

  def _slice_driver_code(self, project: str, driver_code: str,
                         target_lines: set) -> str:
    """Slice the driver code up to the target line."""
    target_line = max(target_lines)
    lines = driver_code.split('\n')

    if target_line > len(lines):
      logger.warning(
          'Driver target line exceed maxium limit in Project: %s, \
                      try to use whole driver code in trigae prompt', project)
      return driver_code

    code_snippet = '\n'.join(lines[:target_line])
    result = f'\nLine 1 - {target_line}:\n{code_snippet}'
    return result

  def _slice_func_code(self, project: str, func_name: str,
                       target_lines: set) -> str:
    """Slice target line and four preceding lines from function code."""
    func_sig = introspector.query_introspector_function_signature(
        project, func_name)
    func_code = introspector.query_introspector_function_source(
        project, func_sig)
    begin_line, end_line = introspector.query_introspector_function_line(
        project, func_sig)

    if begin_line != 0 and end_line != 0 and all(
        begin_line <= line <= end_line for line in target_lines):
      lines = func_code.split('\n')
      output_lines = set()
      result = []
      for line in sorted(target_lines):
        start = max(line - 4, begin_line)
        end = line
        if not any(l in output_lines for l in range(start, end + 1)):
          code_snippet = '\n'.join(lines[(start -
                                          begin_line):(end - begin_line) + 1])
          result.append(f'\nFunction Name:\n{func_name}\n\
                Line {start} - {end}:\n{code_snippet}')
          output_lines.update(range(start, end + 1))
      return '\n'.join(result)

    logger.warning('Failed to slice Project: %s Function: %s at Lines: %s',
                   project, func_name, target_lines)
    return ''


class PrototyperTemplateBuilder(DefaultTemplateBuilder):
  """Builder specifically targeted C (and excluding C++)."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)
    self.agent_templare_dir = AGENT_TEMPLATE_DIR

    # Load templates.
    if benchmark.is_c_target:
      self.priming_template_file = self._find_template(
          self.agent_templare_dir, 'prototyper-priming.c.txt')
    elif benchmark.is_cpp_target:
      self.priming_template_file = self._find_template(
          self.agent_templare_dir, 'prototyper-priming.cpp.txt')
    else:
      self.problem_template_file = self._find_template(
          self.agent_templare_dir, 'prototyper-priming.txt')

    self.cpp_priming_filler_file = self._find_template(
        template_dir, 'cpp-specific-priming-filler.txt')
    self.problem_template_file = self._find_template(template_dir,
                                                     'problem.txt')
    self.solution_template_file = self._find_template(template_dir,
                                                      'solution.txt')
    self.context_template_file = self._find_template(template_dir,
                                                     'context.txt')

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    if not self.benchmark:
      return self._prompt
    priming = self._format_priming(self.benchmark)
    priming = priming.replace('{PROJECT_DIR}', project_dir)
    final_problem = self.format_problem(self.benchmark.function_signature)
    final_problem += (f'You MUST call <code>\n'
                      f'{self.benchmark.function_signature}\n'
                      f'</code> in your solution!\n')
    if project_context_content:
      final_problem += self.format_context(project_context_content)
    self._prepare_prompt(priming, final_problem, example_pair,
                         project_example_content)
    self._prompt.append(tool_guides, True)
    return self._prompt


class PrototyperFixerTemplateBuilder(PrototyperTemplateBuilder):
  """Builder specifically targeted C (and excluding C++)."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               build_result: BuildResult,
               compile_log: str,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)
    # Load templates.
    self.priming_template_file = self._find_template(self.agent_templare_dir,
                                                     'prototyper-fixing.txt')
    self.build_result = build_result
    self.compile_log = compile_log

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    del (example_pair, project_example_content, project_context_content,
         tool_guides)
    if not self.benchmark:
      return self._prompt

    if self.build_result.build_script_source:
      build_text = (f'<build script>\n{self.build_result.build_script_source}\n'
                    '</build script>')
    else:
      build_text = 'Build script reuses `/src/build.bk.sh`.'

    prompt = self._get_template(self.priming_template_file)
    prompt = prompt.replace('{FUZZ_TARGET_SOURCE}',
                            self.build_result.fuzz_target_source)
    prompt = prompt.replace('{BUILD_TEXT}', build_text)
    prompt = prompt.replace('{COMPILE_LOG}', self.compile_log)
    prompt = prompt.replace('{FUNCTION_SIGNATURE}',
                            self.benchmark.function_signature)
    prompt = prompt.replace('{PROJECT_DIR}', project_dir)
    self._prompt.append(prompt)

    return self._prompt


class DefaultJvmTemplateBuilder(PromptBuilder):
  """Default builder for JVM projects."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir
    self.benchmark = benchmark
    self.project_url = oss_fuzz_checkout.get_project_repository(
        self.benchmark.project)

    # Retrieve additional properties for the target method
    temp_properties = introspector.query_introspector_function_props(
        self.benchmark.project, self.benchmark.function_signature)
    self.exceptions = temp_properties.get('exceptions', [])
    self.is_jvm_static = temp_properties.get('is-jvm-static', False)
    self.need_close = temp_properties.get('need_close', False)

    # Load templates.
    self.base_template_file = self._find_template(template_dir, 'jvm_base.txt')
    self.data_filler_template_file = self._find_template(
        template_dir, 'jvm_specific_data_filler.txt')
    self.requirement_template_file = self._find_template(
        template_dir, 'jvm_requirement.txt')
    self.problem_template_file = self._find_template(template_dir,
                                                     'jvm_problem.txt')
    self.target_template_file = self._find_template(template_dir,
                                                    'jvm_target.txt')
    self.arg_description_template_file = self._find_template(
        template_dir, 'jvm_arg_description.txt')
    self.import_template_file = self._find_template(template_dir,
                                                    'jvm_import_mapping.txt')

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

  def _format_exceptions(self) -> str:
    """Formats the exception thrown from this method or constructor."""
    if self.exceptions:
      exception_str_list = [
          f'<exception>{exp}</exception>' for exp in self.exceptions
      ]
      return '<exceptions>\n' + '\n'.join(
          exception_str_list) + '\n</exceptions>'

    return ''

  def _format_import_mapping(self, full_class_name: str) -> str:
    """Formats the import mapping row on the prompt template."""
    # full_class_name format: <package>.<class_name>$<inner_class_name>
    # For example, the inner class Inner in class Test of package
    # a.b.c will have a full_class_name of a.b.c.Test$Inner
    class_name = full_class_name.rsplit('.')[-1]
    full_class_name = full_class_name.split('$')[0]

    mapping = self._get_template(self.import_template_file)
    mapping = mapping.replace('{CLASS_NAME}', class_name)
    mapping = mapping.replace('{FULL_CLASS_NAME}', full_class_name)

    return mapping

  def _format_generic_argument(self, arg_type: str) -> Tuple[str, str]:
    """Formats generic argument description."""
    generic_types = arg_type.split('<', 1)[1][:-1].split(',')

    new_types = []
    generic_desc = []
    for generic_type in generic_types:
      if generic_type.endswith(('T', 'K', 'V')):
        generic_type = 'java.lang.Object'

      new_types.append(generic_type)

      desc = (f'For generic type of {generic_type}, you MUST use '
              '{RANDOM_METHODS} to generate the needed variable.')

      method_str = self._get_methods_for_simple_type(generic_type)
      if method_str:
        desc = desc.replace('{RANDOM_METHODS}', method_str)
      else:
        desc = desc.replace('{RANDOM_METHODS}',
                            'correct constructors or static methods')

      generic_desc.append(desc)

    if not generic_desc:
      return '', ''

    generic_types = ','.join(new_types)
    return f' with generic types of {generic_types}', '\n'.join(generic_desc)

  def _format_argument(self, count: int, arg_type: str) -> str:
    """Formats general argument description."""
    method_str = self._get_methods_for_simple_type(arg_type)

    # Simple arguments
    argument = self._get_template(self.arg_description_template_file)
    argument = argument.replace('{ARG_COUNT}', str(count))

    if method_str:
      type_str = '{SIMPLE_TYPE} variable.'
      desc_str = f'You must use {method_str} to generate {{ARRAY_OR_NOT}}.'
    else:
      type_str = '{SIMPLE_TYPE} instance {GENERIC_TYPE}.'
      desc_str = ('Please generate {ARRAY_OR_NOT}. You should use constructors '
                  'or static methods for the generation.\nPlease also insert '
                  'random data into the created instance.')

    argument = argument.replace('{TYPE}', type_str)
    argument = argument.replace('{GENERAL_DESC}', desc_str)

    # Array handling
    if '[]' in arg_type:
      arg_type_no_array = arg_type.replace('[]', '').split('<')[0]
      argument = argument.replace('{SIMPLE_TYPE}',
                                  f'an array of {arg_type_no_array} ')
      argument = argument.replace(
          '{ARRAY_OR_NOT}',
          (f'multiple {arg_type_no_array} objects and initialise an array '
           'of {arg_type_no_array} with the generated objects.'))
    else:
      argument = argument.replace('{SIMPLE_TYPE}', f'a {arg_type}')
      argument = argument.replace('{ARRAY_OR_NOT}', 'the needed parameter.')

    # Generic type handling
    generic_type = ''
    generic_desc = ''
    if self._has_generic(arg_type):
      generic_type, generic_desc = self._format_generic_argument(arg_type)

    argument = argument.replace('{GENERIC_TYPE}', generic_type)
    argument = argument.replace('{GENERIC_DESC}', generic_desc)

    return argument

  def _format_requirement(self, signature: str) -> str:
    """Formats a requirement based on the prompt template."""
    classes = []

    class_name = signature[1:].split(']')[0]
    if self._need_import(class_name):
      classes.append(class_name)

    for arg_dict in self.benchmark.params:
      arg_type = arg_dict['type'].split('<')[0]
      if self._need_import(arg_type):
        classes.append(arg_type)

    classes = list(set(classes))
    mappings = [self._format_import_mapping(type) for type in classes]

    requirement = self._get_template(self.requirement_template_file)
    requirement = requirement.replace('{IMPORT_MAPPINGS}', '\n'.join(mappings))

    harness_name = os.path.basename(self.benchmark.target_path).replace(
        '.java', '')
    if harness_name:
      requirement = requirement.replace('{HARNESS_NAME}', harness_name)
    else:
      requirement = requirement.replace('{HARNESS_NAME}', 'Fuzz')

    class_name = self.benchmark.function_name[1:].split(']')[0]
    if '<init>' in self.benchmark.function_name:
      creation = (f'The target method is a constructor of {class_name} '
                  'invoke it directly with new keyword.')
    elif self.is_jvm_static:
      creation = ('The target method is a static method, invoke it directly '
                  'without creating an object.')
    else:
      creation = (f'You must create the {class_name} object before calling '
                  'the target method.')
    requirement = requirement.replace('{STATIC_OR_INSTANCE}', creation)

    close_statement = ''
    if self.need_close:
      close_statement = (
          '<item>You MUST invoke the close method of the '
          f'{class_name} objects in the finally block after the target method '
          'is invoked.</item>')

    requirement = requirement.replace('{NEED_CLOSE}', close_statement)

    return requirement

  def _format_data_filler(self) -> str:
    """Formats a data_filler based on the prompt template."""
    data_filler = self._get_template(self.data_filler_template_file)
    return data_filler

  def _format_arguments(self) -> str:
    """Formats a list of argument descriptions."""
    argument_descriptions = []

    for count, function_arg in enumerate(self.benchmark.params):
      arg_type = function_arg['type']
      argument = self._format_argument(count, arg_type)
      argument_descriptions.append(argument)

    return '<arguments>' + '\n'.join(argument_descriptions) + '</arguments>'

  def _format_constructors(self) -> str:
    """Formats a list of functions / constructors to create the object for
    invoking the target method."""
    if self.is_jvm_static:
      return ''

    constructors = []
    ctrs = introspector.query_introspector_matching_function_constructor_type(
        self.benchmark.project, self.benchmark.return_type, False)
    for ctr in ctrs:
      constructor_sig = ctr.get('function_signature', '')
      if constructor_sig:
        constructors.append(f'<signature>{constructor_sig}</signature>')
        exceptions = introspector.query_introspector_function_props(
            ctr.get('project', ''), constructor_sig).get('exceptions', [])
        self.exceptions.extend(exceptions)

    if constructors:
      ctr_str = '\n'.join(constructors)
      return f'<constructors>{ctr_str}</constructors>'

    functions = []
    funcs = introspector.query_introspector_matching_function_constructor_type(
        self.benchmark.project, self.benchmark.return_type, True)
    for func in funcs:
      is_static = func.get('is_static', False)
      function_sig = func.get('function_signature', '')
      if not function_sig:
        continue
      exceptions = introspector.query_introspector_function_props(
          func.get('project', ''), function_sig).get('exceptions', [])
      self.exceptions.extend(exceptions)
      if is_static:
        functions.append(f'<item><signature>{function_sig}</signature></item>')
      else:
        function_class = function_sig[1:].split(']')[0]
        function_str = f'<signature>{function_sig}</signature>'
        function_str = function_str + (
            '<prerequisite>You MUST create an '
            f'{function_class} object before calling this constructing method.'
            '</prerequisite>')
        function_str = f'<item>{function_str}</item>'
        functions.append(function_str)
    if functions:
      func_str = '\n'.join(functions)
      return f'<constructors>{func_str}</constructors>'

    return ''

  def _format_source_reference(self, signature: str) -> Tuple[str, str]:
    """Formats the source code reference for this target."""
    # Query for source code of the target method
    source_code = introspector.query_introspector_function_source(
        self.benchmark.project, signature)

    # Query for source code of target method callsites
    xref_source_list = []
    for xref_source in introspector.query_introspector_cross_references(
        self.benchmark.project, signature):
      if xref_source:
        xref_source_list.append(xref_source)

    return source_code, '\n'.join(xref_source_list)

  def _format_problem(self, signature: str) -> str:
    """Formats a problem based on the prompt template."""
    is_constructor = bool('<init>' in signature)

    base = self._get_template(self.base_template_file)
    problem = base + self._get_template(self.problem_template_file)
    problem = problem.replace('{TARGET}',
                              self._get_template(self.target_template_file))
    problem = problem.replace('{SIGNATURE}', signature)
    problem = problem.replace('{CLASS}', signature.split('].')[0][1:])
    problem = problem.replace('{REQUIREMENTS}',
                              self._format_requirement(signature))
    problem = problem.replace('{ARGUMENTS}', self._format_arguments())
    problem = problem.replace('{CONSTRUCTORS}', self._format_constructors())
    problem = problem.replace('{EXCEPTIONS}', self._format_exceptions())

    self_source, cross_source = self._format_source_reference(signature)
    problem = problem.replace('{SELF_SOURCE}', self_source)
    problem = problem.replace('{CROSS_SOURCE}', cross_source)
    problem = problem.replace("{PROJECT_NAME}", self.benchmark.project)
    problem = problem.replace("{PROJECT_URL}", self.project_url)
    problem = problem.replace('{DATA_MAPPING}', self._format_data_filler())

    if is_constructor:
      problem = problem.replace('{METHOD_OR_CONSTRUCTOR}', 'constructor')
    else:
      problem = problem.replace('{METHOD_OR_CONSTRUCTOR}', 'method')

    return problem

  def _prepare_prompt(self, prompt_str: str):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(prompt_str)

  def _has_generic(self, arg: str) -> bool:
    """Determine if the argument type contains generic type."""
    return ('<' in arg and not arg.startswith('<') and arg.endswith('>') and
            'java.lang.Class' not in arg and 'java.lang.Object' not in arg)

  def _need_import(self, class_name: str) -> bool:
    """Determine if the class with class_name needed to be imported."""
    return '.' in class_name and not class_name.startswith('java.lang.')

  def _get_methods_for_simple_type(self, simple_type: str) -> str:
    """Retrieve string descrbing how to generate random data of
    the provided simple type."""
    simple_type_mapping = {
        'int': [
            'FuzzedDataProvider::consumeInt()',
            'FuzzedDataProvider::consumeInt(int, int)'
        ],
        'boolean': [
            'FuzzedDataProvider::consumeBoolean()',
            'FuzzedDataProvider::pickValue(boolean[])'
        ],
        'byte': [
            'FuzzedDataProvider::consumeByte()',
            'FuzzedDataProvider::consumeByte(byte,byte)'
        ],
        'byte[]': [
            'FuzzedDataProvider::consumeBytes(int)',
            'FuzzedDataProvider::consumeRemainingAsBytes()'
        ],
        'short': [
            'FuzzedDataProvider::consumeShort()',
            'FuzzedDataProvider::consumeShort(short,short)'
        ],
        'long': [
            'FuzzedDataProvider::consumeLong()',
            'FuzzedDataProvider::consumeLong(long, long)'
        ],
        'float': [
            'FuzzedDataProvider::consumeFloat()',
            'FuzzedDataProvider::consumeRegularFloat()',
            'FuzzedDataProvider::consumeRegularFloat(float,float)',
            'FuzzedDataProvider::consumeProbabilityFloat()'
        ],
        'double': [
            'FuzzedDataProvider::consumeDouble()',
            'FuzzedDataProvider::consumeRegularDouble()',
            'FuzzedDataProvider::consumeRegularDouble(double, double)',
            'FuzzedDataProvider::consumeProbabilityDouble()'
        ],
        'char': [
            'FuzzedDataProvider::consumeChar()',
            'FuzzedDataProvider::consumeCharNoSurrogates()',
            'FuzzedDataProvider::consumeChar(char, char)'
        ],
        'string': [
            'FuzzedDataProvider::consumeString(int)',
            'FuzzedDataProvider::consumeAsciiString(int)',
            'FuzzedDataProvider::consumeRemainingAsString()',
            'FuzzedDataProvider::consumeRemainingAsAsciiString()'
        ],
        'class': ['Object::getClass()']
    }

    # Extract simple type
    simple_type = simple_type.replace('java.lang.Integer', 'int')
    simple_type = simple_type.replace('java.lang.Character', 'char')
    simple_type = simple_type.split('.')[-1].lower()

    if simple_type in simple_type_mapping:
      return ' or '.join(simple_type_mapping[simple_type])

    # If the type is not found, try if it is an array of any above types
    simple_type = simple_type.replace('[]', '')
    return ' or '.join(simple_type_mapping.get(simple_type, []))

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it.
       Ignore target_file_type, project_example_content
       and project_context_content parameters.
    """
    final_problem = self._format_problem(self.benchmark.function_signature)
    self._prepare_prompt(final_problem)
    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Builds a fixer prompt."""
    # Do nothing for jvm project now.
    return self._prompt

  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Builds a triager prompt."""
    # Do nothing for jvm project now.
    return self._prompt

  def post_process_generated_code(self, generated_code: str) -> str:
    """Allows prompt builder to adjust the generated code."""
    # From observation, the LLM model keeps using wrong method calls including
    # FuzzedDataProvider::consumeObject() or FuzzedDataProvider::getObject() or
    # FuzzedDataProvider::consumeInt(int) to generate random Object / Integer
    # instance. These methods are not valid in FuzzedDataProvider.

    # The fixes here change the calling of data.consumeObject() and
    # data.getObject() to data.consumeString(int)
    generated_code = generated_code.replace(
        'data.consumeObject()', 'data.consumeString(data.remainingBytes()/2)')
    generated_code = generated_code.replace(
        'data.getObject()', 'data.consumeString(data.remainingBytes()/2)')

    # The fixes here change the calling of data.consumeInt(int) to
    # data.consumeInt(0, int). For example, data.consumeInt(12345) will
    # be replaced by data.consumeInt(0, 12345)
    for wrong_method_call in re.findall(r'(data\.consumeInt\(([0-9]+)\))',
                                        generated_code):
      old_method_call = wrong_method_call[0]
      new_method_call = f'data.consumeInt(0, {wrong_method_call[1]})'
      generated_code = generated_code.replace(old_method_call, new_method_call)

    return generated_code


class DefaultRustTemplateBuilder(PromptBuilder):
  """Default builder for Rust projects."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir
    self.benchmark = benchmark
    self.project_url = oss_fuzz_checkout.get_project_repository(
        self.benchmark.project)

    # Load templates.
    self.base_template_file = self._find_template(template_dir, 'rust_base.txt')
    self.problem_template_file = self._find_template(template_dir,
                                                     'rust_problem.txt')

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

  def _format_target(self, signature: str) -> str:
    """Format the target function for the prompts creation."""
    target = self._get_template(self.problem_template_file)
    arg_count = len(self.benchmark.params)
    arg_type = [arg_dict['type'] for arg_dict in self.benchmark.params]

    target = target.replace('{FUNCTION_SIGNATURE}', signature)
    target = target.replace('{ARG_COUNT}', str(arg_count))
    target = target.replace('{ARG_TYPE}', ','.join(arg_type))

    return target

  def _format_problem(self, signature: str) -> str:
    """Formats a problem based on the prompt template."""
    base = self._get_template(self.base_template_file)
    target_str = self._format_target(signature)

    problem = base + target_str
    problem = problem.replace("{PROJECT_NAME}", self.benchmark.project)
    problem = problem.replace("{PROJECT_URL}", self.project_url)

    return problem

  def _prepare_prompt(self, prompt_str: str):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(prompt_str)

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it.
       Ignore target_file_type, project_example_content
       and project_context_content parameters.
    """
    final_problem = self._format_problem(self.benchmark.function_signature)
    self._prepare_prompt(final_problem)
    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Builds a fixer prompt."""
    # Do nothing for rust project now.
    return self._prompt

  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Builds a triager prompt."""
    # Do nothing for rust project now.
    return self._prompt

  def post_process_generated_code(self, generated_code: str) -> str:
    """Allows prompt builder to adjust the generated code."""
    # Do nothing for rust project now.
    return generated_code


class JvmFixingBuilder(PromptBuilder):
  """Prompt builder for fixing JVM harness with complication error or
  to increase code coverage."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               generated_harness: str,
               errors: list[str],
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir
    self.benchmark = benchmark
    self.generated_harness = generated_harness
    self.error_str = '\n'.join(errors)

    # Load templates.
    self.template_file = self._find_template(template_dir, 'jvm_fixer.txt')

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

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it.
       Ignore target_file_type, project_example_content
       and project_context_content parameters.
    """
    with open(self.template_file, 'r') as f:
      prompt_text = f.read()

    proj = self.benchmark.project

    # Format the repository
    target_repository = oss_fuzz_checkout.get_project_repository(
        self.benchmark.project)

    # Add information
    prompt_text = prompt_text.replace('{TARGET_REPO}', target_repository)
    prompt_text = prompt_text.replace('{HARNESS_NAME}',
                                      self.benchmark.target_name)
    prompt_text = prompt_text.replace('{GENERATED_HARNESS}',
                                      self.generated_harness)

    # Add all public candidates to prompt
    methods = introspector.query_introspector_all_public_candidates(proj)
    name = [method['function_name'] for method in methods]
    prompt_text = prompt_text.replace('{PUBLIC_METHODS}', ','.join(name))

    # Add source code of all existing harnesses to prompt
    source_list = []
    harnesses = introspector.query_introspector_for_harness_intrinsics(proj)
    for pair in harnesses:
      path = pair.get('source', '')
      if path:
        source = introspector.query_introspector_source_code(proj, path)
        if source:
          source_list.append(source)

    prompt_text = prompt_text.replace('{EXISTING_HARNESS}',
                                      '\n---\n'.join(source_list))

    if self.error_str:
      prompt_text = prompt_text.replace('{ERRORS}',
                                        ('There are no errors, please consider '
                                         'increasing the code coverage.'))
    else:
      prompt_text = prompt_text.replace('{ERRORS}', self.error_str)

    self._prompt.add_priming(prompt_text)
    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Builds a fixer prompt."""
    # Do nothing for jvm project now.
    return self._prompt

  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Builds a triager prompt."""
    # Do nothing for jvm project now.
    return self._prompt

  def post_process_generated_code(self, generated_code: str) -> str:
    """Allows prompt builder to adjust the generated code."""
    return generated_code


class DefaultPythonTemplateBuilder(PromptBuilder):
  """Default builder for Python projects."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir
    self.benchmark = benchmark
    self.project_url = oss_fuzz_checkout.get_project_repository(
        self.benchmark.project)

    # Load templates.
    self.base_template_file = self._find_template(template_dir,
                                                  'python_base.txt')
    self.problem_template_file = self._find_template(template_dir,
                                                     'python_problem.txt')

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

  def _format_target(self, signature: str) -> str:
    """Format the target function for the prompts creation."""
    target = self._get_template(self.problem_template_file)
    signature_split = signature.rsplit('.', 1)

    # Determine if the target is class function of instance function
    if self.benchmark.params[0].get('name', '') == 'self':
      arg_count = len(self.benchmark.params) - 1
      desc = ('This is an instance function. You MUST create the needed '
              f'class {signature_split[0]} before invoking the target '
              f'function {signature_split[-1]}.')
    else:
      arg_count = len(self.benchmark.params)
      desc = 'This is a class function. You MUST invoke it directly.'

    target = target.replace('{METHOD_SIGNATURE}', signature)
    target = target.replace('{PACKAGE}', signature_split[0])
    target = target.replace('{ARG_COUNT}', str(arg_count))
    target = target.replace('{CLASS_METHOD_OR_GENERAL_METHOD}', desc)

    return target

  def _format_problem(self, signature: str) -> str:
    """Formats a problem based on the prompt template."""
    base = self._get_template(self.base_template_file)
    target_str = self._format_target(signature)

    problem = base + target_str
    problem = problem.replace("{PROJECT_NAME}", self.benchmark.project)
    problem = problem.replace("{PROJECT_URL}", self.project_url)

    return problem

  def _prepare_prompt(self, prompt_str: str):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(prompt_str)

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it.
       Ignore target_file_type, project_example_content
       and project_context_content parameters.
    """
    final_problem = self._format_problem(self.benchmark.function_signature)
    self._prepare_prompt(final_problem)
    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Builds a fixer prompt."""
    # Do nothing for python project now.
    return self._prompt

  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Builds a triager prompt."""
    # Do nothing for python project now.
    return self._prompt

  def post_process_generated_code(self, generated_code: str) -> str:
    """Allows prompt builder to adjust the generated code."""
    # Do nothing for python project now.
    return generated_code


class CSpecificBuilder(PromptBuilder):
  """Builder specifically targeted C (and excluding C++)."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir
    self.benchmark = benchmark

    # Load templates.
    self.priming_template_file = self._find_template(template_dir,
                                                     'c-priming.txt')

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

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    with open(self.priming_template_file, 'r') as f:
      prompt_text = f.read()

    # Format the priming
    target_repository = oss_fuzz_checkout.get_project_repository(
        self.benchmark.project)
    prompt_text = prompt_text.replace('{TARGET_REPO}', target_repository)
    prompt_text = prompt_text.replace('{TARGET_FUNCTION}',
                                      self.benchmark.function_signature)
    function_source = introspector.query_introspector_function_source(
        self.benchmark.project, self.benchmark.function_signature)
    prompt_text = prompt_text.replace('{TARGET_FUNCTION_SOURCE_CODE}',
                                      function_source)

    # Set header inclusion string if there are any headers.
    headers_to_include = \
        introspector.query_introspector_header_files_to_include(
        self.benchmark.project, self.benchmark.function_signature)
    header_inclusion_string = ''
    if headers_to_include:
      header_inclusion_string = ', '.join(headers_to_include)

    # TODO: Programmatically select and refine the header.
    prompt_text = prompt_text.replace('{TARGET_HEADER_FILES}',
                                      header_inclusion_string)

    # Add function arg types
    arg_types = introspector.query_introspector_function_debug_arg_types(
        self.benchmark.project, self.benchmark.function_signature)

    arg_types_text = ''
    if arg_types:
      arg_types_text = 'The target function takes the following arguments:\n'
      arg_types_text += '- ' + '- '.join(f'{arg}\n' for arg in arg_types)

      arg_types_text += (
          'You must make sure the arguments passed to the '
          'function match the types of the function. Do this by casting '
          'appropriately.\n')

    prompt_text = prompt_text.replace('{FUNCTION_ARG_TYPES_MSG}',
                                      arg_types_text)

    sample_cross_references = introspector.query_introspector_sample_xrefs(
        self.benchmark.project, self.benchmark.function_signature)
    if sample_cross_references:
      additional_text = (
          'The target function is used in various places of the target project.'
          'Please see the following samples of code using the target, which '
          'you should use as inspiration for the harness to structure the code:'
          '\n')

      exp_usage = 'Example usage:\n'
      additional_text += exp_usage + exp_usage.join(
          f'```c{elem}\n```\n' for elem in sample_cross_references)
    else:
      additional_text = ''

    prompt_text = prompt_text.replace('{ADDITIONAL_INFORMATION}',
                                      additional_text)

    self._prompt.add_priming(prompt_text)
    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Prepares the code-fixing prompt."""
    return self._prompt

  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Builds a triager prompt."""
    return self._prompt

  def post_process_generated_code(self, generated_code: str) -> str:
    """Adds specific C headers we always want in the harnesses."""
    # TODO: explore if we can make this more precise, by only adding headers
    # if needed.
    for header in C_PROMPT_HEADERS_TO_ALWAYS_INCLUDES:
      generated_code = f'#include <{header}>\n' + generated_code
    return generated_code


class TestToHarnessConverter(PromptBuilder):
  """Builder for test-to-harness conversion."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    super().__init__(model)
    self._template_dir = template_dir
    self.benchmark = benchmark

    self.harness_source_code = introspector.query_introspector_source_code(
        self.benchmark.project, self.benchmark.target_path, 0, 10000)

    self.general_jvm_imports = [
        'import com.code_intelligence.jazzer.api.FuzzedDataProvider;'
    ]

    # Load templates.
    self.priming_template_file = self._find_template(
        template_dir, 'test_to_harness_priming.txt')
    jvm_requirement_template_file = self._find_template(
        template_dir, 'jvm_requirement_test_to_harness.txt')

    # Constant prompt description and text
    self.language_prompt = {
        'c':
            '''This is a C programming language so the harness
should be written in C. This means the  harness should have the structure:
<code>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {}
</code>
Specifically, you should *not* include any `extern "C"` in the harness
definition, and you should write the harness in pure C.
      ''',
        'c++':
            '''This is a CPP programming language so the harness
should be written in CPP. This means the  harness should have the structure:
<code>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {}
</code>
      ''',
        'jvm':
            self._get_template(jvm_requirement_template_file).replace(
                '{HARNESS_NAME}', self.benchmark.target_name)
    }

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

  def _extract_jvm_imports(self, src: str, cls: list[str]) -> list[str]:
    """Extract and interpret import statements from java source."""

    # Extract import statements
    # General import statemet: import test.Test;
    # Static import statement: import static test.Test.InnerTest;
    # Generic import statement: import test.*;
    import_pattern = r'^\s*(import\s+(static\s+)?([\w.*]+);)'
    imports = re.compile(import_pattern, re.MULTILINE).findall(src)

    # Group public classes by packages
    cls_map = {}
    for cls_name in cls:
      if '.' in cls_name:
        package, name = cls_name.rsplit('.', 1)
        if package not in cls_map:
          cls_map[package] = []
        cls_map[package].append(name)

    # Generalise public classes import statements
    results = set()
    for package, cls_name_list in cls_map.items():
      if len(cls_name_list) >= 3:
        # Generalise the import package if it has more than three items
        results.add(f'import {package}.*;')
      else:
        # Import each class separately
        for cls_name in cls_name_list:
          results.add(f'import {package}.{cls_name};')

    # Retrieve other import statements for reference
    others = set()
    for full_import, _, cls_name in imports:
      if cls_name.startswith('java'):
        results.add(full_import)
      elif '*' in cls_name:
        package = cls_name.rstrip('.*')
        if package not in cls_map:
          others.add(full_import)
      else:
        others.add(full_import)

    self.general_jvm_imports = list(sorted(results))
    return list(sorted(others))

  def _get_jvm_public_candidates(self, proj: str) -> list[str]:
    """Helper function to retrieve list of public candidates for jvm."""
    method_set = set()
    methods = introspector.query_introspector_all_public_candidates(proj)
    for method in methods:
      if "<init>" not in method['function_name']:
        method_set.add(method['function_name'])
    return list(method_set)

  def extract_header_files(self, text):
    # Include any weird macros defined that does not have any values. This
    # was found empirically to be valuable.
    includes_in_test = set()
    for line in text.split('\n'):
      if '#include' in line and 'test' not in line:
        includes_in_test.add(line)
    return includes_in_test

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            target_repository: str = '',
            test_source_code: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    with open(self.priming_template_file, 'r') as f:
      prompt_text = f.read()

    # Format the priming
    if not target_repository:
      target_repository = oss_fuzz_checkout.get_project_repository(
          self.benchmark.project)
    if not test_source_code:
      test_source_code = introspector.query_introspector_test_source(
          self.benchmark.project,
          self.benchmark.test_file_path.replace('//', '/'))

    prompt_text = prompt_text.replace("{TARGET_REPO}", target_repository)
    prompt_text = prompt_text.replace("{TEST_SOURCE_CODE}", test_source_code)

    language_text = self.language_prompt.get(self.benchmark.language.lower(),
                                             '')
    prompt_text = prompt_text.replace('{PROGRAMMING_LANGUAGE_TEXT}',
                                      language_text)

    if self.benchmark.language == 'jvm':
      prompt_text = prompt_text.replace('{HEADER_FILE_LANG}', '')
      prompt_text = prompt_text.replace('{HARNESS_HEADERS}', '')

      # Fuzz Introspector use JVM as it support other JVM languages in addition
      # to Java. Currently, the logic in OSS-Fuzz-Gen is only working on Java.
      prompt_text = prompt_text.replace('{PROG_LANG}', 'Java')

      # Provide list of public classes of this project
      classes = introspector.query_introspector_public_classes(
          self.benchmark.project)
      prompt_text = prompt_text.replace('{PUBLIC_CLASSES}', ','.join(classes))

      # Proivde sample harness code
      harness_sample_text = ('There are already harnesses targeting this '
                             'project, and an example of this is:\n'
                             f'<code>\n{self.harness_source_code}\n</code>')
      prompt_text = prompt_text.replace('{TARGET_SAMPLE_HARNESS}',
                                        harness_sample_text)

      # Extract must included methods
      methods = self._get_jvm_public_candidates(self.benchmark.project)
      prompt_text = prompt_text.replace('{PUBLIC_METHODS}', ','.join(methods))

      # Extract import list
      other_import_list = self._extract_jvm_imports(test_source_code, classes)
      prompt_text = prompt_text.replace('{IMPORT_STATEMENTS}',
                                        '\n'.join(self.general_jvm_imports))
      prompt_text = prompt_text.replace('{OTHER_IMPORT_STATEMENTS}',
                                        '\n'.join(other_import_list))
    else:
      included_header_files = self.extract_header_files(test_source_code)
      if included_header_files:
        harness_included_header_files = (
            'The following header files are used in the '
            'test source code. Please make sure to include the same ones: '
            f'{included_header_files}')
      else:
        harness_included_header_files = ''
      prompt_text = prompt_text.replace('{HARNESS_HEADERS}',
                                        harness_included_header_files)

      headers_to_include = \
        introspector.query_introspector_header_files(
        self.benchmark.project)
      if headers_to_include:
        header_inclusion_string = '<headers>\n'
        header_inclusion_string += ''.join(
            f'<elem>{h}</elem>\n' for h in headers_to_include)

        header_inclusion_string += '</headers>\n'
        header_inclusion_string = (
            'The following header files exist in the project source code. '
            'If the harness you create needs any header files make sure '
            'they are in the list:\n'
            f'{header_inclusion_string}')
      else:
        header_inclusion_string = ''
      prompt_text = prompt_text.replace('{HEADER_FILE_LANG}',
                                        header_inclusion_string)
      prompt_text = prompt_text.replace('{PROG_LANG}', self.benchmark.language)

      harness_sample_text = ('There are already harnesses targeting this '
                             'project, and an example of this is:\n'
                             f'<code>{self.harness_source_code}</code>')
      prompt_text = prompt_text.replace('{TARGET_SAMPLE_HARNESS}',
                                        harness_sample_text)

    self._prompt.add_priming(prompt_text)
    return self._prompt

  def build_fixer_prompt(self, benchmark: Benchmark, raw_code: str,
                         error_desc: Optional[str],
                         errors: list[str]) -> prompts.Prompt:
    """Prepares the code-fixing prompt."""
    return self._prompt

  def build_triager_prompt(self, benchmark: Benchmark, driver_code: str,
                           crash_info: str, crash_func: dict) -> prompts.Prompt:
    """Builds a triager prompt."""
    return self._prompt

  def post_process_generated_code(self, generated_code: str) -> str:
    """Adds specific C headers we always want in the harnesses for C/C++.
    Add general import statements and remove unnecessary statments for JVM"""
    if self.benchmark.language.lower() == 'jvm':
      # For JVM
      # Remove assert and out statements
      fixed_code = []
      prefixes = ['assert', 'System.out']
      for line in generated_code.split('\n'):
        if not any(line.lstrip().startswith(prefix) for prefix in prefixes):
          fixed_code.append(line)

      # Add general import statements
      import_str = '\n'.join(self.general_jvm_imports)
      generated_code = '\n'.join(fixed_code)
      generated_code = f'{import_str}\n{generated_code}'
    else:
      # For C/C++
      for header in C_PROMPT_HEADERS_TO_ALWAYS_INCLUDES:
        generated_code = f'#include <{header}>\n{generated_code}'
      generated_code += '\n'
      if self.benchmark.language.lower() == 'c':
        generated_code = generated_code.replace(
            'extern "C" int LLVMFuzzerTestOneInput',
            'int LLVMFuzzerTestOneInput')

    return generated_code
