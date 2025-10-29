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
from results import (AnalysisResult, BuildResult, CoverageResult,
                     CrashContextResult, CrashResult, RunResult)

logger = logging.getLogger(__name__)

DEFAULT_TEMPLATE_DIR: str = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '../prompts/template_xml/'))
AGENT_TEMPLATE_DIR: str = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '../prompts/agent_graph/'))

# TODO(Dongge): Refactor this tot avoid hard-coding.
# Example files.
EXAMPLE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', 'prompts', 'example'))
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
FIX_RECOMMENDATION_HEADER = 'Here are some fix suggestions you can apply.\n'

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
        typedef='\n'.join(context_info['typedef']),
        func_source=context_info['func_source'],
        xrefs='\n'.join(context_info['xrefs']),
        include_statement=context_info['header'],
        tests_xrefs='\n'.join(context_info['tests_xrefs']),
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
                         coverage_result: Optional[CoverageResult] = None,
                         context: str = '',
                         instruction: str = '') -> prompts.Prompt:
    """Prepares the code-fixing prompt."""
    priming, priming_weight = self._format_fixer_priming(benchmark)

    if error_desc or errors:
      pass
    elif coverage_result:
      error_desc = coverage_result.insight
      errors = coverage_result.suggestions.splitlines()
    else:
      error_desc = error_desc or ''
      errors = errors or []
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

    # If errors list is empty, return the formatted prompt
    if not errors:
      return problem.replace('<error>\n', '')\
                    .replace('{ERROR_MESSAGES}\n', '')\
                    .replace('</error>\n', '')

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
        if not selected_errors:
          # At least include one error in order for LLM to have something
          # to fix even if not enough token left.
          selected_errors.append(error)
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
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder specifically targeted C (and excluding C++).
  """

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
            project_dir: str = '',
            function_requirements: str = '') -> prompts.Prompt:
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
    if function_requirements:
      final_problem += (f'\nHere are the requirements for the function:\n'
                        f'{function_requirements}\n')
    self._prepare_prompt(priming, final_problem, example_pair,
                         project_example_content)
    self._prompt.append(tool_guides, True)
    return self._prompt

class PrototyperFixerTemplateBuilder(PrototyperTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder specifically targeted C (and excluding C++).
  """

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
            project_dir: str = '',
            function_requirements: str = '') -> prompts.Prompt:
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

class CoverageAnalyzerTemplateBuilder(PrototyperTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder specifically targeted C (and excluding C++).
  """

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               run_result: RunResult,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)
    # Load templates.
    self.priming_template_file = self._find_template(
        self.agent_templare_dir, 'coverage-analyzer-priming.txt')
    self.run_result = run_result

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '',
            function_requirements: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    del (example_pair, project_example_content, project_context_content)
    if not self.benchmark:
      return self._prompt

    prompt = self._get_template(self.priming_template_file)
    prompt = prompt.replace('{LANGUAGE}', self.benchmark.file_type.value)
    prompt = prompt.replace('{PROJECT}', self.benchmark.project)
    prompt = prompt.replace('{PROJECT_DIR}', project_dir)
    prompt = prompt.replace('{PROJECT_LANGUAGE}', self.benchmark.language)
    prompt = prompt.replace('{FUNCTION_SIGNATURE}',
                            self.benchmark.function_signature)
    prompt = prompt.replace('{FUZZ_TARGET}', self.run_result.fuzz_target_source)
    prompt = prompt.replace('{TOOL_GUIDES}', tool_guides)
    prompt = prompt.replace('{FUZZING_LOG}', self.run_result.run_log)
    prompt = prompt.replace('{FUNCTION_REQUIREMENTS}', function_requirements)

    self._prompt.append(prompt)
    return self._prompt

class EnhancerTemplateBuilder(PrototyperTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder specifically targeted C (and excluding C++).
  """

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               build_result: BuildResult,
               error_desc: str = '',
               errors: Optional[list[str]] = None,
               coverage_result: Optional[CoverageResult] = None,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)
    # Load templates.
    self.priming_template_file = self._find_template(self.agent_templare_dir,
                                                     'enhancer-priming.txt')
    self.build_result = build_result
    self.error_desc = error_desc
    self.errors = errors
    self.coverage_result = coverage_result

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '',
            function_requirements: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    del (example_pair, project_example_content, project_context_content)
    if not self.benchmark:
      return self._prompt

    priming = self._get_template(self.priming_template_file)
    priming = priming.replace('{LANGUAGE}', self.benchmark.file_type.value)
    priming = priming.replace('{FUNCTION_SIGNATURE}',
                              self.benchmark.function_signature)
    priming = priming.replace('{PROJECT_DIR}', project_dir)
    priming = priming.replace('{TOOL_GUIDES}', tool_guides)
    if self.build_result.build_script_source:
      build_text = (f'<build script>\n{self.build_result.build_script_source}\n'
                    '</build script>')
    else:
      build_text = 'Build script reuses `/src/build.bk.sh`.'
    priming = priming.replace('{BUILD_TEXT}', build_text)
    if function_requirements:
      priming = priming.replace('{FUNCTION_REQUIREMENTS}',
                                function_requirements)
    priming_weight = self._model.estimate_token_num(priming)
    # TODO(dongge): Refine this logic.
    if self.error_desc and self.errors:
      error_desc = self.error_desc
      errors = self.errors
    elif self.coverage_result:
      error_desc = self.coverage_result.insight
      errors = self.coverage_result.suggestions.splitlines()
    else:
      error_desc = ''
      errors = []
    problem = self._format_fixer_problem(self.build_result.fuzz_target_source,
                                         error_desc, errors, priming_weight, '',
                                         '')
    self._prepare_prompt(priming, problem)
    return self._prompt

class CrashEnhancerTemplateBuilder(PrototyperTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder specifically targeted C (and excluding C++).
  """

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               build_result: BuildResult,
               crash_result: CrashResult,
               context_result: Optional[CrashContextResult],
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)
    # Load templates.
    self.priming_template_file = self._find_template(
        self.agent_templare_dir, 'enhancer-crash-priming.txt')
    self.build_result = build_result
    self.crash_result = crash_result
    self.context_result = context_result

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '',
            function_requirements: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    del (example_pair, project_example_content, project_context_content)
    if not self.benchmark:
      return self._prompt

    priming = self._get_template(self.priming_template_file)
    priming = priming.replace('{LANGUAGE}', self.benchmark.file_type.value)
    priming = priming.replace('{FUNCTION_SIGNATURE}',
                              self.benchmark.function_signature)
    priming = priming.replace('{PROJECT_DIR}', project_dir)
    priming = priming.replace('{TOOL_GUIDES}', tool_guides)

    priming = priming.replace('{FUZZ_TARGET_SOURCE}',
                              self.build_result.fuzz_target_source)
    priming = priming.replace('{CRASH_STACKTRACE}',
                              self.crash_result.stacktrace)
    priming = priming.replace('{CRASH_ANALYZER_INSIGHT}',
                              self.crash_result.insight)

    if self.context_result:
      context_analyzer_insight = f"""
      {self.context_result.analysis}

      Here is the source code evidence for this insight.
      {self.context_result.source_code_evidence}
      """
      priming = priming.replace('CONTEXT_ANALYZER_INSIGHT',
                                context_analyzer_insight)
      fix_recommendations = FIX_RECOMMENDATION_HEADER + self.context_result.recommendations
      priming = priming.replace('FIX_RECOMMENDATION', fix_recommendations)

    if function_requirements:
      priming = priming.replace('{FUNCTION_REQUIREMENTS}',
                                function_requirements)

    self._prompt.append(priming)

    return self._prompt

class CoverageEnhancerTemplateBuilder(PrototyperTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder specifically targeted C (and excluding C++).
  """

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               build_result: BuildResult,
               coverage_result: CoverageResult,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)
    # Load templates.
    self.priming_template_file = self._find_template(
        self.agent_templare_dir, 'enhancer-coverage-priming.txt')
    self.build_result = build_result
    self.coverage_result = coverage_result

  def build(self,
            example_pair: list[list[str]],
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '',
            function_requirements: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""
    del (example_pair, project_example_content, project_context_content)
    if not self.benchmark:
      return self._prompt

    prompt = self._get_template(self.priming_template_file)
    prompt = prompt.replace('{TOOL_GUIDES}', tool_guides)
    prompt = prompt.replace('{LANGUAGE}', self.benchmark.file_type.value)
    prompt = prompt.replace('{PROJECT}', self.benchmark.project)
    prompt = prompt.replace('{PROJECT_DIR}', project_dir)
    prompt = prompt.replace('{PROJECT_LANGUAGE}', self.benchmark.language)
    prompt = prompt.replace('{FUZZ_TARGET}',
                            self.build_result.fuzz_target_source)
    prompt = prompt.replace('{FUNCTION_SIGNATURE}',
                            self.benchmark.function_signature)

    if self.build_result.build_script_source:
      build_text = (f'<build script>\n{self.build_result.build_script_source}\n'
                    '</build script>')
    else:
      build_text = 'Build script reuses `/src/build.bk.sh`.'
    prompt = prompt.replace('{BUILD_TEXT}', build_text)
    prompt = prompt.replace('{INSIGHTS}', self.coverage_result.insight)
    prompt = prompt.replace('{SUGGESTIONS}', self.coverage_result.suggestions)
    if function_requirements:
      prompt = prompt.replace('{FUNCTION_REQUIREMENTS}', function_requirements)
    self._prompt.append(prompt)

    return self._prompt

class FunctionAnalyzerTemplateBuilder(DefaultTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder for function analyzer.
  """

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)

    # Load templates.
    self.function_analyzer_instruction_file = self._find_template(
        AGENT_TEMPLATE_DIR, 'function-analyzer-instruction.txt')
    self.function_analyzer_description_file = self._find_template(
        AGENT_TEMPLATE_DIR, 'function-analyzer-description.txt')
    self.function_analyzer_prompt_template_file = self._find_template(
        AGENT_TEMPLATE_DIR, 'function-analyzer-priming.txt')
    self.function_analyzer_response_file = self._find_template(
        DEFAULT_TEMPLATE_DIR, 'function-analyzer-response.txt')

  def get_instruction(self) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    self._prompt = self._model.prompt_type()(None)
    if not self.benchmark:
      return self._prompt

    prompt = self._get_template(self.function_analyzer_instruction_file)

    self._prompt.append(prompt)

    return self._prompt

  def get_description(self) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    self._prompt = self._model.prompt_type()(None)
    if not self.benchmark:
      return self._prompt

    prompt = self._get_template(self.function_analyzer_description_file)

    self._prompt.append(prompt)

    return self._prompt

  def build_prompt(self, project_dir: str) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    if not self.benchmark:
      logger.error(
          'No benchmark provided for function analyzer template builder.')
      return self._prompt

    prompt = self._get_template(self.function_analyzer_prompt_template_file)

    prompt = prompt.replace('{PROJECT_NAME}', self.benchmark.project)
    prompt = prompt.replace('{FUNCTION_SIGNATURE}',
                            self.benchmark.function_signature)
    prompt = prompt.replace('{PROJECT_DIR}', project_dir)

    # Get the function source
    func_source = introspector.query_introspector_function_source(
        self.benchmark.project, self.benchmark.function_signature)

    if not func_source:
      logger.error('No function source found for project: %s, function: %s',
                   self.benchmark.project, self.benchmark.function_signature)

    prompt = prompt.replace('{FUNCTION_SOURCE}', func_source)

    # Get the function's references
    xrefs = introspector.query_introspector_cross_references(
        self.benchmark.project, self.benchmark.function_signature)
    if not xrefs:
      logger.error('No cross references found for project: %s, function: %s',
                   self.benchmark.project, self.benchmark.function_signature)
      prompt = prompt.replace('<function-references>', '')\
                      .replace('{FUNCTION_REFERENCES}', '')\
                        .replace('</function-references>', '')
    else:
      references = [f'<reference>\n{xref}\n</reference>' for xref in xrefs]
      references_str = '\n'.join(references)
      prompt = prompt.replace('{FUNCTION_REFERENCES}', references_str)

    prompt = prompt.replace('{RESPONSE_FORMAT}', self.get_response_format())

    self._prompt.append(prompt)

    return self._prompt

  def get_response_format(self) -> str:
    """Returns the response format for the function analyzer."""
    return self._get_template(self.function_analyzer_response_file)

  def build(self,
            example_pair: Optional[list[list[str]]] = None,
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '',
            project_name: str = '',
            function_signature: str = '') -> prompts.Prompt:

    del (example_pair, project_example_content, project_context_content,
         tool_guides, project_dir, project_name, function_signature)

    return self._prompt

class ContextAnalyzerTemplateBuilder(DefaultTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder for context analyzer.
  """

  def __init__(self,
               model: models.LLM,
               benchmark: Optional[Benchmark] = None,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)

    # Load templates.
    self.context_analyzer_instruction_file = self._find_template(
        AGENT_TEMPLATE_DIR, 'context-analyzer-instruction.txt')
    self.context_analyzer_description_file = self._find_template(
        AGENT_TEMPLATE_DIR, 'context-analyzer-description.txt')
    self.context_analyzer_prompt_template_file = self._find_template(
        AGENT_TEMPLATE_DIR, 'context-analyzer-priming.txt')
    self.context_analyzer_response_file = self._find_template(
        DEFAULT_TEMPLATE_DIR, 'context-analyzer-response.txt')

  def get_instruction(self) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    self._prompt = self._model.prompt_type()(None)
    if not self.benchmark:
      return self._prompt

    prompt = self._get_template(self.context_analyzer_instruction_file)

    self._prompt.append(prompt)

    return self._prompt

  def get_description(self) -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    self._prompt = self._model.prompt_type()(None)
    if not self.benchmark:
      return self._prompt

    prompt = self._get_template(self.context_analyzer_description_file)

    self._prompt.append(prompt)

    return self._prompt

  def build_context_analysis_prompt(self,
                                    last_result: AnalysisResult,
                                    function_requirements: str,
                                    tool_guides: str = '',
                                    project_dir: str = '') -> prompts.Prompt:
    """Constructs a prompt using the templates in |self| and saves it."""

    if not self.benchmark:
      logger.error(
          'No benchmark provided for function analyzer template builder.')
      return self._prompt

    prompt = self._get_template(self.context_analyzer_prompt_template_file)

    prompt = prompt.replace('{PROJECT_NAME}', self.benchmark.project)
    prompt = prompt.replace('{PROJECT_DIR}', project_dir)

    # Add the function source
    func_source = introspector.query_introspector_function_source(
        self.benchmark.project, self.benchmark.function_signature)

    if not func_source:
      logger.error('No function source found for project: %s, function: %s',
                   self.benchmark.project, self.benchmark.function_signature)

    crash_result = last_result.crash_result
    run_result = last_result.run_result

    if not crash_result or not run_result:
      logger.error('No crash or run result found for project: %s, function: %s',
                   self.benchmark.project, self.benchmark.function_signature)
      return self._prompt

    # Add the fuzz target and crash results
    prompt = prompt.replace('{FUZZ_TARGET}', run_result.fuzz_target_source)
    prompt = prompt.replace('{CRASH_ANALYSIS}', crash_result.insight)
    prompt = prompt.replace('{CRASH_STACKTRACE}', crash_result.stacktrace)

    # Add the function requirements
    prompt = prompt.replace('{FUNCTION_REQUIREMENTS}', function_requirements)
    self._prompt.append(prompt)
    self._prompt.append(tool_guides)

    return self._prompt

  def get_response_format(self) -> str:
    """Returns the response format for the context analyzer."""
    return self._get_template(self.context_analyzer_response_file)

  def build(self,
            example_pair: Optional[list[list[str]]] = None,
            project_example_content: Optional[list[list[str]]] = None,
            project_context_content: Optional[dict] = None,
            tool_guides: str = '',
            project_dir: str = '',
            project_name: str = '',
            function_signature: str = '') -> prompts.Prompt:
    """Returns an empty prompt."""

    del (example_pair, project_example_content, project_context_content,
         tool_guides, project_dir, project_name, function_signature)

    return self._prompt

class CrashAnalyzerTemplateBuilder(DefaultTemplateBuilder):
  """
  DEPRECATED: This class has been migrated to agent_graph/prompt_loader.py.
  Use PromptManager from agent_graph.prompt_loader instead.
  
  Builder for crash analyzer.
  """

  def __init__(self,
               model: models.LLM,
               benchmark: Optional[Benchmark] = None,
               template_dir: str = DEFAULT_TEMPLATE_DIR,
               initial: Any = None):
    super().__init__(model, benchmark, template_dir, initial)
    self.agent_templare_dir = AGENT_TEMPLATE_DIR

    self.crash_analyzer_priming_template_file = self._find_template(
        self.agent_templare_dir, 'crash_analyzer-priming.txt')

  def _prepare_prompt(
      self,
      priming: str,
      final_problem: str,
      example_pair: Optional[list[list[str]]] = None,
      project_example_content: Optional[list[list[str]]] = None):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(priming)

  def build_crash_analyzer_prompt(self, benchmark: Benchmark, driver_code: str,
                                  crash_info: str,
                                  crash_func: dict) -> prompts.Prompt:
    """Prepares the crash analyzer prompt."""
    all_func_code = []
    for func_name, line_number in crash_func.items():
      if func_name == 'LLVMFuzzerTestOneInput':
        driver_code = self._slice_driver_code(benchmark.project, driver_code,
                                              line_number)
      else:
        func_code = self._slice_func_code(benchmark.project, func_name,
                                          line_number)
        all_func_code.append(func_code)

    with open(self.crash_analyzer_priming_template_file) as f:
      priming = f.read().strip()
    priming = priming.replace('{CRASH_REPORT}', crash_info.strip())\
                     .replace('{DRIVER_CODE}', driver_code.strip())

    priming_prompt = self._prompt.create_prompt_piece(priming, 'user')
    template_piece = self._prompt.create_prompt_piece('{PROJECT_FUNCTION_CODE}',
                                                      'user')

    priming_weight = self._model.estimate_token_num(priming_prompt)
    template_weight = self._model.estimate_token_num(template_piece)

    prompt_size = priming_weight - template_weight
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

    project_function_code = '\n'.join(selected_func_code)
    if project_function_code.strip():
      priming.replace('{PROJECT_FUNCTION_CODE}', project_function_code.strip())
    else:
      logger.warning(
          'Empty project function code in triage prompt for project: %s, \
          function name: %s', benchmark.project, benchmark.function_name)
      priming.replace('{PROJECT_FUNCTION_CODE}', \
                           'No relevant project function code')

    self._prepare_prompt(priming, '')
    return self._prompt

class DefaultJvmTemplateBuilder(PromptBuilder):
  """Default builder for JVM projects - DEPRECATED: JVM support has been removed."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    raise NotImplementedError(
        "JVM/Java support has been removed from LogicFuzz. "
        "The experimental/jvm module and related functionality are no longer available."
    )

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
    self.priming_template_file = self._find_template(template_dir,
                                                     'rust_priming.txt')
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
    problem = self._format_target(signature)

    problem = problem.replace('{PROJECT_NAME}', self.benchmark.project)
    problem = problem.replace('{PROJECT_URL}', self.project_url)

    return problem

  def _prepare_prompt(self, prompt_str: str):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(self._get_template(self.priming_template_file))
    self._prompt.add_problem(prompt_str)

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
  """Prompt builder for fixing JVM harness - DEPRECATED: JVM support has been removed."""

  def __init__(self,
               model: models.LLM,
               benchmark: Benchmark,
               generated_harness: str,
               errors: list[str],
               template_dir: str = DEFAULT_TEMPLATE_DIR):
    raise NotImplementedError(
        "JVM/Java support has been removed from LogicFuzz. "
        "The experimental/jvm module and related functionality are no longer available."
    )

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
    self.priming_template_file = self._find_template(template_dir,
                                                     'python_priming.txt')
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
    problem = self._format_target(signature)

    problem = problem.replace('{PROJECT_NAME}', self.benchmark.project)
    problem = problem.replace('{PROJECT_URL}', self.project_url)

    return problem

  def _prepare_prompt(self, prompt_str: str):
    """Constructs a prompt using the parameters and saves it."""
    self._prompt.add_priming(self._get_template(self.priming_template_file))
    self._prompt.add_problem(prompt_str)

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
      # to Java. Currently, the logic in LogicFuzz is only working on Java.
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
