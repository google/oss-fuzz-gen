"""An LLM agent to improve a fuzz target's runtime performance.
Use it as a usual module locally, or as script in cloud builds.
"""
import os
import shutil

import logger
from agent.base_agent import BaseAgent
from experiment import benchmark as benchmarklib
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as exp_evaluator
from experiment.workdir import WorkDirs
from llm_toolkit import models, output_parser, prompt_builder, prompts
from llm_toolkit.prompt_builder import (DefaultTemplateBuilder,
                                        JvmErrorFixingBuilder)
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, BuildResult, Result

MAX_ROUND = 100


class OnePromptEnhancer(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    last_result = results[-1]
    if not isinstance(last_result, AnalysisResult):
      logger.error('The last result in Enhancer is not AnalysisResult: %s',
                   results,
                   trial=self.trial)
      return Prompt()

    benchmark = last_result.benchmark

    fixer_model = models.LLM.setup(
        ai_binary=self.args.ai_binary,
        name=self.llm.name,
        num_samples=1,
        temperature=self.args.temperature,
    )
    if benchmark.language == 'jvm':
      jvm_coverage_fix = True
      error_desc, errors = '', []
      builder = JvmErrorFixingBuilder(fixer_model, benchmark,
                                      last_result.run_result.fuzz_target_source,
                                      errors, jvm_coverage_fix)
      prompt = builder.build([], None, None)
    else:
      error_desc, errors = last_result.semantic_result.get_error_info()

      builder = DefaultTemplateBuilder(fixer_model)

      prompt = builder.build_fixer_prompt(benchmark,
                                          last_result.fuzz_target_source,
                                          error_desc,
                                          errors,
                                          context='',
                                          instruction='')
      prompt_path = os.path.join(last_result.work_dirs.base, 'prompt-fix.txt')
      prompt.save(prompt_path)
    return prompt

  def _prompt_builder(self,
                      results: list[Result]) -> prompt_builder.PromptBuilder:
    """Returns the prompt builder based on language and customization."""
    last_result = results[-1]
    benchmark = last_result.benchmark
    # If this is a test benchmark then we will use a test prompt builder.
    if benchmark.test_file_path:
      logger.info('Generating a target for test case: %s',
                  benchmark.test_file_path,
                  trial=last_result.trial)
      return prompt_builder.TestToHarnessConverter(self.llm, benchmark,
                                                   self.args.template_directory)
    if benchmark.language == 'jvm':
      # For Java projects
      return prompt_builder.DefaultJvmTemplateBuilder(
          self.llm, benchmark, self.args.template_directory)
    if benchmark.language == 'python':
      # For Python projects
      return prompt_builder.DefaultPythonTemplateBuilder(
          self.llm, benchmark, self.args.template_directory)

    if self.args.prompt_builder == 'CSpecific':
      return prompt_builder.CSpecificBuilder(self.llm, benchmark,
                                             self.args.template_directory)
    # Use default
    return prompt_builder.DefaultTemplateBuilder(self.llm, benchmark,
                                                 self.args.template_directory)

  def _read_from_file(self, file_path: str) -> str:
    """Reads the file content from a local |file_path|."""
    with open(file_path, 'r') as file:
      file_lines = file.readlines()
    return '\n'.join(file_lines)

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    last_result = result_history[-1]
    logger.info('Executing Enhancer', trial=last_result.trial)
    benchmark = last_result.benchmark
    WorkDirs(self.args.work_dirs.base)
    build_result = BuildResult(benchmark=benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: ''})
    prompt = self._initial_prompt(result_history)
    generated_target = self._generate_targets(
        prompt, self._prompt_builder(result_history), result_history)[0]
    logger.info('Final fuzz target path:\n %s',
                generated_target,
                trial=last_result.trial)
    build_result.fuzz_target_source = self._read_from_file(generated_target)
    build_result = self._check_targets(benchmark, generated_target,
                                       build_result)
    return build_result

  def _generate_targets(self, prompt: prompts.Prompt,
                        builder: prompt_builder.PromptBuilder,
                        result_history: list[Result]) -> list[str]:
    """Generates fuzz target with LLM."""
    last_result = result_history[-1]
    benchmark = last_result.benchmark

    logger.info('Generating targets for %s %s using %s..',
                benchmark.project,
                benchmark.function_signature,
                self.llm.name,
                trial=last_result.trial)
    self.llm.query_llm(prompt, response_dir=self.args.work_dirs.raw_targets)

    _, target_ext = os.path.splitext(benchmark.target_path)
    generated_targets = []
    for file in os.listdir(self.args.work_dirs.raw_targets):
      if not output_parser.is_raw_output(file):
        continue
      raw_output = os.path.join(self.args.work_dirs.raw_targets, file)
      target_code = output_parser.parse_code(raw_output)
      target_code = builder.post_process_generated_code(target_code)
      target_id, _ = os.path.splitext(raw_output)
      target_file = f'{target_id}{target_ext}'
      target_path = os.path.join(self.args.work_dirs.raw_targets, target_file)
      output_parser.save_output(target_code, target_path)
      generated_targets.append(target_path)

    if generated_targets:
      targets_relpath = map(os.path.relpath, generated_targets)
      targets_relpath_str = '\n '.join(targets_relpath)
      logger.info('Generated:\n %s',
                  targets_relpath_str,
                  trial=last_result.trial)
    else:
      logger.info('Failed to generate targets: %s',
                  generated_targets,
                  trial=last_result.trial)

    fixed_targets = []
    # Prepare all LLM-generated targets for code fixes.
    for file in generated_targets:
      fixed_target = os.path.join(self.args.work_dirs.fixed_targets,
                                  os.path.basename(file))
      shutil.copyfile(file, fixed_target)
      fixed_targets.append(fixed_target)
    return fixed_targets

  def _check_targets(
      self,
      benchmark: benchmarklib.Benchmark,
      generated_target: str,
      build_result: BuildResult,
  ) -> BuildResult:
    """Builds all targets in the fixed target directory."""

    # TODO(Dongge): Split Builder and Runner.
    # Only run builder here.
    if self.args.cloud_experiment_name:
      builder_runner = builder_runner_lib.CloudBuilderRunner(
          benchmark,
          self.args.work_dirs,
          fixer_model_name=self.llm.name,
          experiment_name=self.args.cloud_experiment_name,
          experiment_bucket=self.args.cloud_experiment_bucket,
      )
    else:
      builder_runner = builder_runner_lib.BuilderRunner(
          benchmark, self.args.work_dirs, fixer_model_name=self.llm.name)

    evaluator = exp_evaluator.Evaluator(builder_runner, benchmark,
                                        self.args.work_dirs)

    target_stat = evaluator.check_target(self.args.ai_binary, generated_target)
    if target_stat is None:
      logger.error('This should never happen: Error evaluating target: %s',
                   generated_target,
                   trial=self.trial)
    build_result.compiles = target_stat.compiles
    build_result.is_function_referenced = True
    build_result.compile_error = target_stat.compile_error
    build_result.compile_log = target_stat.compile_log
    return build_result
