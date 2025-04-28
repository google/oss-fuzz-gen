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
"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import os
import subprocess as sp
import time
import logging
from datetime import timedelta
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from data_prep import project_targets
from data_prep.project_context.context_introspector import ContextRetriever
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from llm_toolkit import (code_fixer, models, output_parser, prompt_builder,
                         prompts)
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.container_tool import ProjectContainerTool


class OnePromptPrototyper(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _prompt_builder(self,
                      results: list[Result]) -> prompt_builder.PromptBuilder:
    """Returns the prompt builder based on language and customization."""
    last_result = results[-1]
    benchmark = last_result.benchmark

    # If this is a test benchmark then we will use a test prompt builder.
    if self.args.prompt_builder == 'UnitTestToHarness':
      return prompt_builder.UnitTestToHarnessConverter(self.llm, benchmark,
                                                   self.args.template_directory)
    if benchmark.test_file_path:
      logger.info('Generating a target for test case: %s',
                  benchmark.test_file_path,
                  trial=last_result.trial)
      return prompt_builder.TestToHarnessConverter(self.llm, benchmark,
                                                   self.args.template_directory)
    # TODO: Do these in separate agents.
    if benchmark.language == 'jvm':
      # For Java projects
      return prompt_builder.DefaultJvmTemplateBuilder(
          self.llm, benchmark, self.args.template_directory)
    if benchmark.language == 'python':
      # For Python projects
      return prompt_builder.DefaultPythonTemplateBuilder(
          self.llm, benchmark, self.args.template_directory)
    if benchmark.language == 'rust':
      # For Rust projects
      return prompt_builder.DefaultRustTemplateBuilder(
          self.llm, benchmark, self.args.template_directory)

    if self.args.prompt_builder == 'CSpecific':
      return prompt_builder.CSpecificBuilder(self.llm, benchmark,
                                             self.args.template_directory)
    # Use default
    return prompt_builder.DefaultTemplateBuilder(self.llm, benchmark,
                                                 self.args.template_directory)

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    last_result = results[-1]
    benchmark = last_result.benchmark
    if benchmark.use_project_examples:
      project_examples = project_targets.generate_data(
          benchmark.project,
          benchmark.language,
          cloud_experiment_bucket=self.args.cloud_experiment_bucket)
    else:
      project_examples = []

    if self.args.context:
      retriever = ContextRetriever(benchmark)
      context_info = retriever.get_context_info()
    else:
      context_info = {}

    builder = self._prompt_builder(results)
    prompt = builder.build(prompt_builder.EXAMPLES.get(benchmark.language, []),
                           project_example_content=project_examples,
                           project_context_content=context_info)
    prompt.save(self.args.work_dirs.prompt)
    return prompt

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    last_result = result_history[-1]
    logger.info('Executing %s', self.name, trial=last_result.trial)
    # Use keep to avoid deleting files, such as benchmark.yaml
    WorkDirs(self.args.work_dirs.base, keep=True)
    start_time = time.localtime()
    logger.info(f"_initial_prompt start time=======================================================: {time.strftime('%Y-%m-%d %H:%M:%S', start_time)}", trial=last_result.trial)
    prompt = self._initial_prompt(result_history)
    end_time = time.time()
    end_time = time.localtime()
    execution_time = time.mktime(end_time) - time.mktime(start_time)
    logger.info(f"_initial_prompt end time=======================================================: {time.strftime('%Y-%m-%d %H:%M:%S', end_time)}", trial=last_result.trial)
    logger.info(f"_initial_prompt execution time: {execution_time:.2f} seconds", trial=last_result.trial)
    cur_round = 1
    build_result = BuildResult(benchmark=last_result.benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: prompt.gettext()})
    logger.info("开始执行1", trial=last_result.trial) 
    while prompt and cur_round <= self.max_round:
      logger.info("开始执行", trial=last_result.trial)
      self._generate_fuzz_target(prompt, result_history, build_result,
                                 cur_round)
      self._validate_fuzz_target(cur_round, build_result)
      prompt = self._advice_fuzz_target(build_result, cur_round)
      cur_round += 1

    return build_result

  def _advice_fuzz_target(self, build_result: BuildResult,
                          cur_round: int) -> Optional[Prompt]:
    """Returns a prompt to fix fuzz target based on its build result errors."""
    if build_result.success:
      logger.info('***** %s succeded in %02d rounds *****',
                  self.name,
                  cur_round,
                  trial=build_result.trial)
      return None
    fixer_model = models.LLM.setup(ai_binary=self.args.ai_binary,
                                   name=self.llm.name,
                                   num_samples=1,
                                   temperature=self.args.temperature)

    errors = code_fixer.extract_error_from_lines(
        build_result.compile_log.split('\n'),
        os.path.basename(build_result.benchmark.target_path),
        build_result.benchmark.language)
    build_result.compile_error = '\n'.join(errors)
    if build_result.benchmark.language == 'jvm':
      builder = prompt_builder.JvmFixingBuilder(
          fixer_model, build_result.benchmark, build_result.fuzz_target_source,
          build_result.compile_error.split('\n'))
      prompt = builder.build([], None, None)
    else:
      builder = prompt_builder.DefaultTemplateBuilder(fixer_model)

      context = code_fixer.collect_context(build_result.benchmark, errors)
      instruction = code_fixer.collect_instructions(
          build_result.benchmark, errors, build_result.fuzz_target_source)
      prompt = builder.build_fixer_prompt(build_result.benchmark,
                                          build_result.fuzz_target_source,
                                          '',
                                          errors,
                                          context=context,
                                          instruction=instruction)

    return prompt

  def _generate_fuzz_target(self, prompt: prompts.Prompt,
                            result_history: list[Result],
                            build_result: BuildResult, cur_round: int) -> None:
    """Generates and iterates fuzz target with LLM."""
    benchmark = build_result.benchmark

    logger.info('Generating targets for %s %s using %s..',
                benchmark.project,
                benchmark.function_signature,
                self.llm.name,
                trial=build_result.trial)

    target_code = self.ask_llm(cur_round, prompt, self.trial)
    target_code = output_parser.filter_code(target_code)
    target_code = self._prompt_builder(
        result_history).post_process_generated_code(target_code)
    build_result.fuzz_target_source = target_code

  def _validate_fuzz_target(self, cur_round: int,
                            build_result: BuildResult) -> None:
    """Validates the new fuzz target by recompiling it."""
    benchmark = build_result.benchmark
    compilation_tool = ProjectContainerTool(benchmark=benchmark)

    # Replace fuzz target and build script in the container.
    replace_file_content_command = (
        'cat << "OFG_EOF" > {file_path}\n{file_content}\nOFG_EOF')
    compilation_tool.execute(
        replace_file_content_command.format(
            file_path=benchmark.target_path,
            file_content=build_result.fuzz_target_source))

    if build_result.build_script_source:
      compilation_tool.execute(
          replace_file_content_command.format(
              file_path='/src/build.sh',
              file_content=build_result.build_script_source))

    # Recompile.
    logger.info('===== ROUND %02d Recompile =====',
                cur_round,
                trial=build_result.trial)
    start_time = time.time()
    compile_process = compilation_tool.compile()
    end_time = time.time()
    logger.debug('ROUND %02d compilation time: %s',
                 cur_round,
                 timedelta(seconds=end_time - start_time),
                 trial=build_result.trial)
    compile_succeed = compile_process.returncode == 0
    logger.debug('ROUND %02d Fuzz target compiles: %s',
                 cur_round,
                 compile_succeed,
                 trial=build_result.trial)

    # Double-check binary.
    ls_result = compilation_tool.execute(f'ls /out/{benchmark.target_name}')
    binary_exists = ls_result.returncode == 0
    logger.debug('ROUND %02d Final fuzz target binary exists: %s',
                 cur_round,
                 binary_exists,
                 trial=build_result.trial)

    # Validate if function-under-test is referenced by the fuzz target.
    function_referenced = self._validate_fuzz_target_references_function(
        compilation_tool, benchmark, cur_round, build_result.trial)

    compilation_tool.terminate()
    self._update_build_result(build_result,
                              compile_process=compile_process,
                              compiles=compile_succeed,
                              binary_exists=binary_exists,
                              referenced=function_referenced)

  def _validate_fuzz_target_references_function(
      self, compilation_tool: ProjectContainerTool, benchmark: Benchmark,
      cur_round: int, trial: int) -> bool:
    """Validates if the LLM generated fuzz target assembly code references
    function-under-test."""

    # LLVMFuzzerTestOneInput and binary dumps are only valid
    # for C/C++ projects.
    # Temporary skipping this check for other language.
    if benchmark.language in ['jvm', 'python', 'rust']:
      return True

    disassemble_result = compilation_tool.execute(
        'objdump --disassemble=LLVMFuzzerTestOneInput -d '
        f'/out/{benchmark.target_name}')
    function_referenced = (disassemble_result.returncode == 0 and
                           benchmark.function_name in disassemble_result.stdout)
    logger.debug('ROUND %02d Final fuzz target function referenced: %s',
                 cur_round,
                 function_referenced,
                 trial=trial)
    if not function_referenced:
      logger.debug('ROUND %02d Final fuzz target function not referenced',
                   cur_round,
                   trial=trial)
    return function_referenced

  def _update_build_result(self, build_result: BuildResult,
                           compile_process: sp.CompletedProcess, compiles: bool,
                           binary_exists: bool, referenced: bool) -> None:
    """Updates the build result with the latest info."""
    build_result.compiles = compiles
    build_result.binary_exists = binary_exists
    build_result.compile_error = compile_process.stderr
    build_result.compile_log = self._format_bash_execution_result(
        compile_process)
    build_result.is_function_referenced = referenced
