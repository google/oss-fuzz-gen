"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import os
import shutil

import logger
from agent.base_agent import BaseAgent
from data_prep import project_targets
from data_prep.project_context.context_introspector import ContextRetriever
from experiment import benchmark as benchmarklib
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as exp_evaluator
from experiment.workdir import WorkDirs
from llm_toolkit import models, output_parser, prompt_builder, prompts
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result

MAX_ROUND = 100


class OnePrompter(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

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

  def _read_from_file(self, file_path: str) -> str:
    """Reads the file content from a local |file_path|."""
    with open(file_path, 'r') as file:
      file_lines = file.readlines()
    return '\n'.join(file_lines)

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    last_result = result_history[-1]
    benchmark = last_result.benchmark
    WorkDirs(self.args.work_dirs.base)
    build_result = BuildResult(benchmark=benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: ''})

    prompt = self._initial_prompt(result_history)
    generated_target = self._generate_targets(
        self.llm, prompt, self.args.work_dirs,
        self._prompt_builder(result_history), result_history)[0]
    logger.info('Final fuzz target path:\n %s',
                generated_target,
                trial=last_result.trial)
    build_result.fuzz_target_source = self._read_from_file(generated_target)
    build_result = self._check_targets(self.args.ai_binary, benchmark,
                                       generated_target, build_result,
                                       self.llm.name)
    return build_result

  def _generate_targets(self, model: models.LLM, prompt: prompts.Prompt,
                        work_dirs: WorkDirs,
                        builder: prompt_builder.PromptBuilder,
                        result_history: list[Result]) -> list[str]:
    """Generates fuzz target with LLM."""
    last_result = result_history[-1]
    benchmark = last_result.benchmark

    logger.info('Generating targets for %s %s using %s..',
                benchmark.project,
                benchmark.function_signature,
                model.name,
                trial=last_result.trial)
    model.query_llm(prompt, response_dir=work_dirs.raw_targets)

    _, target_ext = os.path.splitext(benchmark.target_path)
    generated_targets = []
    for file in os.listdir(work_dirs.raw_targets):
      if not output_parser.is_raw_output(file):
        continue
      raw_output = os.path.join(work_dirs.raw_targets, file)
      target_code = output_parser.parse_code(raw_output)
      target_code = builder.post_process_generated_code(target_code)
      target_id, _ = os.path.splitext(raw_output)
      target_file = f'{target_id}{target_ext}'
      target_path = os.path.join(work_dirs.raw_targets, target_file)
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
      fixed_target = os.path.join(work_dirs.fixed_targets,
                                  os.path.basename(file))
      shutil.copyfile(file, fixed_target)
      fixed_targets.append(fixed_target)
    return fixed_targets

  def _check_targets(
      self,
      ai_binary: str,
      benchmark: benchmarklib.Benchmark,
      generated_target: str,
      build_result: BuildResult,
      fixer_model_name: str = models.DefaultModel.name,
  ) -> BuildResult:
    """Builds all targets in the fixed target directory."""

    if self.args.cloud_experiment_name:
      builder_runner = builder_runner_lib.CloudBuilderRunner(
          benchmark,
          self.args.work_dirs,
          self.args.run_timeout,
          fixer_model_name,
          experiment_name=self.args.cloud_experiment_name,
          experiment_bucket=self.args.cloud_experiment_bucket,
      )
    else:
      builder_runner = builder_runner_lib.BuilderRunner(benchmark,
                                                        self.args.work_dirs,
                                                        self.args.run_timeout,
                                                        fixer_model_name)

    evaluator = exp_evaluator.Evaluator(builder_runner, benchmark,
                                        self.args.work_dirs)

    target_stat = evaluator.check_target(ai_binary, generated_target)
    if target_stat is None:
      logger.error('This should never happen: Error evaluating target: %s',
                   generated_target,
                   trial=self.trial)
    build_result.compiles = target_stat.compiles
    return build_result
