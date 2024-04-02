#!/usr/bin/env python3
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
"""Run an experiment with one function-under-test."""

import dataclasses
import logging
import os
import shutil
import subprocess
from multiprocessing import pool
from typing import List, Optional

from data_prep import project_targets
from data_prep.project_context.context_retriever import ContextRetriever
from experiment import benchmark as benchmarklib
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as exp_evaluator
from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from llm_toolkit import models, output_parser, prompt_builder, prompts

# WARN: Avoid NUM_EVA for local experiments.
# NUM_EVA controls the number of fuzz targets to evaluate in parallel by each
# experiment, while {run_all_experiments.NUM_EXP, default 2} experiments will
# run in parallel.
NUM_EVA = int(os.getenv('LLM_NUM_EVA', '3'))
DEBUG: bool = False

# Default LLM hyper-parameters.
# WARN: Avoid large NUM_SAMPLES in highly parallelized local experiment.
# NUM_SAMPLES controls the number of LLM responses per query, which may exceed
# your LLM's limit on query-per-second.
NUM_SAMPLES = 2
MAX_TOKENS: int = 4096
RUN_TIMEOUT: int = 30
TEMPERATURE: float = 0.4

RESULTS_DIR = './results'


@dataclasses.dataclass
class AggregatedResult:
  """Aggregated evaluation result."""
  build_success_rate: float = 0.0
  crash_rate: float = 0.0
  max_coverage: float = 0.0
  max_line_coverage_diff: float = 0.0
  max_coverage_sample: str = ''
  max_coverage_diff_sample: str = ''
  max_coverage_diff_report: str = ''

  def __str__(self):
    return (
        f'build success rate: {self.build_success_rate}, '
        f'crash rate: {self.crash_rate}, '
        f'max coverage: {self.max_coverage}, '
        f'max line coverage diff: {self.max_line_coverage_diff}\n'
        f'max coverage sample: {self.max_coverage_sample}\n'
        f'max coverage diff sample: {self.max_coverage_diff_sample}\n'
        f'max coverage diff report: {self.max_coverage_diff_report or "None"}')


def generate_targets(benchmark: Benchmark,
                     model: models.LLM,
                     prompt: prompts.Prompt,
                     work_dirs: WorkDirs,
                     debug: bool = DEBUG) -> list[str]:
  """Generates fuzz target with LLM."""
  print(f'Generating targets for {benchmark.project} '
        f'{benchmark.function_signature} using {model.name}..')
  model.generate_code(prompt,
                      response_dir=work_dirs.raw_targets,
                      log_output=debug)

  _, target_ext = os.path.splitext(benchmark.target_path)
  generated_targets = []
  for file in os.listdir(work_dirs.raw_targets):
    if not output_parser.is_raw_output(file):
      continue
    raw_output = os.path.join(work_dirs.raw_targets, file)
    target_code = output_parser.parse_code(raw_output)
    target_id, _ = os.path.splitext(raw_output)
    target_file = f'{target_id}{target_ext}'
    target_path = os.path.join(work_dirs.raw_targets, target_file)
    output_parser.save_output(target_code, target_path)
    generated_targets.append(target_path)

  if generated_targets:
    targets_relpath = map(os.path.relpath, generated_targets)
    print('Generated:\n', '\n '.join(targets_relpath))
  else:
    print(f'Failed to generate targets: {generated_targets}')
  return generated_targets


def fix_code(work_dirs: WorkDirs, generated_targets: List[str]) -> List[str]:
  """Copies the generated target to the fixed target directory for simple
    code fixes."""
  fixed_targets = []
  # Prepare all LLM-generated targets for code fixes.
  for file in generated_targets:
    fixed_target = os.path.join(work_dirs.fixed_targets, os.path.basename(file))
    shutil.copyfile(file, fixed_target)
    fixed_targets.append(fixed_target)

  return fixed_targets


def aggregate_results(target_stats: list[tuple[int, exp_evaluator.Result]],
                      generated_targets: list[str]) -> AggregatedResult:
  """Aggregates experiment status and results of a targets."""
  build_success_rate = sum([int(stat.compiles) for _, stat in target_stats
                           ]) / len(target_stats)
  crash_rate = sum([int(stat.crashes) for _, stat in target_stats
                   ]) / len(target_stats)
  max_coverage = max([stat.coverage for _, stat in target_stats])
  max_line_coverage_diff = max(
      [stat.line_coverage_diff for _, stat in target_stats])

  max_coverage_sample = ''
  max_coverage_diff_sample = ''
  max_coverage_diff_report = ''

  for i, stat in target_stats:
    if stat.coverage == max_coverage:
      max_coverage_sample = generated_targets[i]

    if stat.line_coverage_diff == max_line_coverage_diff:
      max_coverage_diff_sample = generated_targets[i]
      max_coverage_diff_report = stat.coverage_report_path

  return AggregatedResult(build_success_rate, crash_rate, max_coverage,
                          max_line_coverage_diff, max_coverage_sample,
                          max_coverage_diff_sample, max_coverage_diff_report)


def check_targets(
    ai_binary: str,
    benchmark: Benchmark,
    work_dirs: WorkDirs,
    generated_targets: List[str],
    cloud_experiment_name: str = '',
    cloud_experiment_bucket: str = '',
    run_timeout: int = RUN_TIMEOUT,
    fixer_model_name: str = models.DefaultModel.name,
) -> Optional[AggregatedResult]:
  """Builds all targets in the fixed target directory."""
  target_stats = []

  if cloud_experiment_name:
    builder_runner = builder_runner_lib.CloudBuilderRunner(
        benchmark,
        work_dirs,
        run_timeout,
        fixer_model_name,
        experiment_name=cloud_experiment_name,
        experiment_bucket=cloud_experiment_bucket,
    )
  else:
    builder_runner = builder_runner_lib.BuilderRunner(benchmark, work_dirs,
                                                      run_timeout,
                                                      fixer_model_name)

  evaluator = exp_evaluator.Evaluator(builder_runner, benchmark, work_dirs)

  ai_target_pairs = [(ai_binary, target) for target in generated_targets]
  with pool.ThreadPool(NUM_EVA) as p:
    for i, target_stat in enumerate(
        p.starmap(evaluator.check_target, ai_target_pairs)):
      if target_stat is None:
        print(f'Error evaluating target {generated_targets[i]}')
        continue

      target_stats.append((i, target_stat))

  if len(target_stats) > 0:
    return aggregate_results(target_stats, generated_targets)

  print('No targets to check.')
  return None


def prepare() -> None:
  """Prepares the experiment environment."""
  oss_fuzz_checkout.clone_oss_fuzz(temp_repo=True)
  oss_fuzz_checkout.postprocess_oss_fuzz()


def run(benchmark: Benchmark,
        model: models.LLM,
        template_dir: str,
        work_dirs: WorkDirs,
        example_pair: Optional[list[list[str]]] = None,
        debug: bool = DEBUG,
        manual_fix: bool = False,
        cloud_experiment_name: str = '',
        cloud_experiment_bucket: str = '',
        use_context: bool = False,
        run_timeout: int = RUN_TIMEOUT) -> Optional[AggregatedResult]:
  """Generates code via LLM, and evaluates them."""
  model.cloud_setup()
  logging.basicConfig(level=logging.INFO)

  if example_pair is None:
    example_pair = prompt_builder.EXAMPLES

  if manual_fix:
    generated_targets = [
        os.path.join(work_dirs.fixed_targets, f)
        for f in os.listdir(work_dirs.fixed_targets)
        if benchmarklib.is_c_file(f) or benchmarklib.is_cpp_file(f)
    ]
  else:
    if benchmark.use_project_examples:
      project_examples = project_targets.generate_data(
          benchmark.project, cloud_experiment_bucket=cloud_experiment_bucket)
    else:
      project_examples = []

    context_info = None

    if use_context:
      retriever = ContextRetriever(benchmark)
      try:
        retriever.retrieve_asts()
      # GSutil fails on the same project immediately after
      # it succeeds a batch copy.
      except subprocess.CalledProcessError:
        pass
      retriever.generate_lookups()
      context_header = retriever.get_header()
      print(context_header)
      context_types = '\n'.join(retriever.get_type_info())
      context_info = (context_header, context_types)
      retriever.cleanup_asts()

    builder = prompt_builder.DefaultTemplateBuilder(model, template_dir)
    prompt = builder.build(benchmark.function_signature,
                           benchmark.file_type,
                           example_pair,
                           project_examples,
                           project_context_content=context_info)
    prompt.save(work_dirs.prompt)
    generated_targets = generate_targets(benchmark,
                                         model,
                                         prompt,
                                         work_dirs,
                                         debug=debug)
    generated_targets = fix_code(work_dirs, generated_targets)

  return check_targets(model.ai_binary, benchmark, work_dirs, generated_targets,
                       cloud_experiment_name, cloud_experiment_bucket,
                       run_timeout, model.name)
