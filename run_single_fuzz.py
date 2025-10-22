#!/usr/bin/env python3
"""Run an experiment with one function-under-test."""

import argparse
import dataclasses
import datetime
import logging
import os
from multiprocessing import pool
from typing import List, Optional

import logger
import pipeline
from agent_graph.agents.context_analyzer import ContextAnalyzer
from agent_graph.agents.coverage_analyzer import CoverageAnalyzer
from agent_graph.agents.crash_analyzer import CrashAnalyzer
from agent_graph.agents.enhancer import Enhancer
from agent_graph.agents.function_analyzer import FunctionAnalyzer
from agent_graph.agents.function_based_prototyper import FunctionToolPrototyper
from agent_graph.agents.one_prompt_enhancer import OnePromptEnhancer
from agent_graph.agents.one_prompt_prototyper import OnePromptPrototyper
from agent_graph.agents.prototyper import Prototyper
from agent_graph.agents.semantic_analyzer import SemanticAnalyzer
from agent_graph import FuzzingWorkflow
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as exp_evaluator
from experiment import oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from llm_toolkit import models, output_parser, prompt_builder, prompts
from results import BenchmarkResult, Result, TrialResult

# WARN: Avoid high value for NUM_EVA for local experiments.
# NUM_EVA controls the number of fuzz targets to evaluate in parallel by each
# experiment, while {run_logicfuzz.NUM_EXP, default 2} experiments will
# run in parallel.
NUM_EVA = int(os.getenv('LLM_NUM_EVA', '3'))

# Default LLM hyper-parameters.
# #182 shows Gemini returns NUM_SAMPLES independent responses via repeated
#  queries, which generally performs better than top-k responses from one
#  query [1].
# WARN: Avoid large NUM_SAMPLES in highly parallelized local experiments.
# It controls the number of LLM responses per prompt, which may exceed your
# LLM's limit on query-per-second.
NUM_SAMPLES = 5
MAX_TOKENS: int = 409600
RUN_TIMEOUT: int = 60
TEMPERATURE: float = 0.4

# Create a unique results directory for each run to avoid interference
# between different experiments
RESULTS_DIR = f'./results/run-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}'

@dataclasses.dataclass
class AggregatedResult:
  """Aggregated evaluation result."""
  build_success_count: int = 0
  build_success_rate: float = 0.0
  crash_rate: float = 0.0
  found_bug: int = 0
  max_coverage: float = 0.0
  max_line_coverage_diff: float = 0.0
  max_coverage_sample: str = ''
  max_coverage_diff_sample: str = ''
  max_coverage_diff_report: str = ''
  full_textcov_diff: textcov.Textcov = dataclasses.field(
      default_factory=textcov.Textcov)

  def __str__(self):
    return (
        f'build success rate: {self.build_success_rate}, '
        f'crash rate: {self.crash_rate}, '
        f'found bug: {self.found_bug}, '
        f'max coverage: {self.max_coverage}, '
        f'max line coverage diff: {self.max_line_coverage_diff}\n'
        f'max coverage sample: {self.max_coverage_sample}\n'
        f'max coverage diff sample: {self.max_coverage_diff_sample}\n'
        f'max coverage diff report: {self.max_coverage_diff_report or "None"}')

  @classmethod
  def from_benchmark_result(
      cls, benchmark_result: BenchmarkResult) -> 'AggregatedResult':
    """Aggregates experiment history results of all samples."""

    return AggregatedResult(
        build_success_count=benchmark_result.build_success_count,
        build_success_rate=benchmark_result.build_success_rate,
        crash_rate=benchmark_result.crash_rate,
        max_coverage=benchmark_result.coverage,
        max_line_coverage_diff=benchmark_result.line_coverage_diff,
        max_coverage_diff_report=benchmark_result.line_coverage_report,
        full_textcov_diff=benchmark_result.textcov_diff)

# DEPRECATED: The following functions were used in the old non-agent workflow.
# They are no longer needed in the new LangGraph-based agent workflow.
# Kept for backwards compatibility with legacy experiments.

def generate_targets(benchmark: Benchmark, model: models.LLM,
                     prompt: prompts.Prompt, work_dirs: WorkDirs,
                     builder: prompt_builder.PromptBuilder) -> list[str]:
  """[DEPRECATED] Generates fuzz target with LLM.
  
  This function is deprecated and only used in legacy non-agent workflows.
  The new agent workflow generates targets via FuzzingWorkflow.
  """
  raise NotImplementedError(
      "generate_targets() is deprecated. Use the agent workflow instead.")

def fix_code(work_dirs: WorkDirs, generated_targets: List[str]) -> List[str]:
  """[DEPRECATED] Copies the generated target to the fixed target directory.
  
  This function is deprecated and only used in legacy non-agent workflows.
  The new agent workflow handles code fixes internally.
  """
  raise NotImplementedError(
      "fix_code() is deprecated. Use the agent workflow instead.")

def aggregate_results(target_stats: list[tuple[int, exp_evaluator.Result]],
                      generated_targets: list[str]) -> AggregatedResult:
  """Aggregates experiment status and results of a targets."""
  build_success_count = sum([int(stat.compiles) for _, stat in target_stats])
  build_success_rate = build_success_count / len(target_stats)
  crash_rate = sum([int(stat.crashes) for _, stat in target_stats
                   ]) / len(target_stats)
  found_bug = sum([
      int(stat.crashes and not stat.is_semantic_error)
      for _, stat in target_stats
  ])
  max_coverage = max([stat.coverage for _, stat in target_stats])
  max_line_coverage_diff = max(
      [stat.line_coverage_diff for _, stat in target_stats])

  max_coverage_sample = ''
  max_coverage_diff_sample = ''
  max_coverage_diff_report = ''

  all_textcov = textcov.Textcov()
  for i, stat in target_stats:
    if stat.coverage == max_coverage:
      max_coverage_sample = generated_targets[i]

    if stat.line_coverage_diff == max_line_coverage_diff:
      max_coverage_diff_sample = generated_targets[i]
      max_coverage_diff_report = stat.coverage_report_path

    if isinstance(stat.textcov_diff, textcov.Textcov):
      all_textcov.merge(stat.textcov_diff)

  return AggregatedResult(build_success_count, build_success_rate, crash_rate,
                          found_bug, max_coverage, max_line_coverage_diff,
                          max_coverage_sample, max_coverage_diff_sample,
                          max_coverage_diff_report, all_textcov)

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
        logging.error('This should never happen: Error evaluating target: %s',
                      generated_targets[i])
        target_stat = exp_evaluator.Result()

      target_stats.append((i, target_stat))

  if len(target_stats) > 0:
    return aggregate_results(target_stats, generated_targets)

  logging.info('No targets to check.')
  return None

def prepare(oss_fuzz_dir: str) -> None:
  """Prepares the experiment environment."""
  oss_fuzz_checkout.clone_oss_fuzz(oss_fuzz_dir)
  oss_fuzz_checkout.postprocess_oss_fuzz()

def _fuzzing_pipeline(benchmark: Benchmark, model: models.LLM,
                      args: argparse.Namespace, work_dirs: WorkDirs,
                      trial: int) -> TrialResult:
  """Runs the predefined 3-stage pipeline for one trial."""
  trial_logger = logger.get_trial_logger(trial=trial, level=logging.DEBUG)
  trial_logger.info('Trial Starts')

  # Support custom pipeline.
  if args.custom_pipeline == 'function_based_prototyper':
    p = pipeline.Pipeline(args=args,
                          trial=trial,
                          writing_stage_agents=[
                              FunctionToolPrototyper(trial=trial,
                                                     llm=model,
                                                     args=args),
                              FunctionToolPrototyper(trial=trial,
                                                     llm=model,
                                                     args=args),
                          ],
                          analysis_stage_agents=[
                              SemanticAnalyzer(trial=trial,
                                               llm=model,
                                               args=args),
                          ])
  elif args.agent:
    # Use the new LangGraph-based agent system
    trial_logger.info('Using LangGraph-based agent workflow')
    
    # Update args with work_dirs for compatibility
    args.work_dirs = work_dirs
    
    # Create and run the LangGraph workflow
    workflow = FuzzingWorkflow(model, args)
    
    # Run the full supervisor-based workflow
    final_state = workflow.run(
        benchmark=benchmark,
        trial=trial,
        workflow_type='full'
    )
    
    # Convert LangGraph state back to legacy RunResult format
    from results import RunResult
    result = RunResult(
        benchmark=benchmark,
        trial=trial,
        work_dirs=work_dirs,
        fuzz_target_source=final_state.get('fuzz_target_source', ''),
        build_script_source=final_state.get('build_script_source', ''),
        compiles=final_state.get('compile_success', False),
        compile_error='\n'.join(final_state.get('build_errors', [])),
        compile_log=final_state.get('compile_log', ''),
        binary_exists=final_state.get('binary_exists', False),
        is_function_referenced=final_state.get('is_function_referenced', False),
        crashes=final_state.get('crashes', False),
        run_error=final_state.get('run_error', ''),
        crash_func=final_state.get('crash_func', {}),
        run_log=final_state.get('run_log', ''),
        coverage_summary=final_state.get('coverage_summary', {}),
        coverage=final_state.get('coverage_percent', 0.0),
        line_coverage_diff=final_state.get('line_coverage_diff', 0.0),
        reproducer_path=final_state.get('reproducer_path', ''),
        artifact_path=final_state.get('artifact_path', ''),
        sanitizer='address',  # Default from execution
        coverage_report_path=final_state.get('coverage_report_path', ''),
        cov_pcs=final_state.get('cov_pcs', 0),
        total_pcs=final_state.get('total_pcs', 0),
        log_path='',  # Not tracked in LangGraph state
        corpus_path='',  # Not tracked in LangGraph state
        textcov_diff=None  # Not tracked in LangGraph state
    )
    
    # Convert agent_messages to chat_history format
    if 'agent_messages' in final_state:
      chat_history = {}
      for agent_name, messages in final_state['agent_messages'].items():
        # Convert message list to string format
        history_str = '\n'.join([
            f"{msg.get('role', 'unknown').upper()}: {msg.get('content', '')}"
            for msg in messages
        ])
        chat_history[agent_name] = history_str
      result.chat_history = chat_history
    
    trial_logger.info('LangGraph workflow completed')
    
    # Save fuzz target and build script to disk (matching WritingStage behavior)
    if result.fuzz_target_source:
      trial_logger.write_fuzz_target(result)
      trial_logger.info(f'Saved fuzz target to {work_dirs.fuzz_targets}')
    if result.build_script_source:
      trial_logger.write_build_script(result)
      trial_logger.info(f'Saved build script to {work_dirs.fuzz_targets}')
    
    # Save chat history
    if result.chat_history:
      trial_logger.write_chat_history(result, cycle_count=0)
      trial_logger.info(f'Saved chat history to {work_dirs.status}')
    
    # Create trial result to match expected return format
    trial_result = TrialResult(benchmark=benchmark,
                               trial=trial,
                               work_dirs=work_dirs,
                               result_history=[result])
    trial_logger.write_result(
        result_status_dir=trial_result.best_result.work_dirs.status,
        result=trial_result,
        finished=True)
    return trial_result
  else:
    writer_agents = []
    if 'gemini' in args.model or 'vertex' in args.model:
      writer_agents.append(
          FunctionAnalyzer(trial=trial,
                           llm=model,
                           args=args,
                           benchmark=benchmark))
    writer_agents += [
        OnePromptPrototyper(trial=trial, llm=model, args=args),
        OnePromptEnhancer(trial=trial, llm=model, args=args)
    ]

    p = pipeline.Pipeline(args=args,
                          trial=trial,
                          writing_stage_agents=writer_agents,
                          analysis_stage_agents=[
                              SemanticAnalyzer(trial=trial,
                                               llm=model,
                                               args=args),
                          ])

  results = p.execute(result_history=[
      Result(benchmark=benchmark, trial=trial, work_dirs=work_dirs)
  ])

  trial_result = TrialResult(benchmark=benchmark,
                             trial=trial,
                             work_dirs=work_dirs,
                             result_history=results)
  trial_logger.write_result(
      result_status_dir=trial_result.best_result.work_dirs.status,
      result=trial_result,
      finished=True)
  return trial_result

def _fuzzing_pipelines(benchmark: Benchmark, model: models.LLM,
                       args: argparse.Namespace,
                       work_dirs: WorkDirs) -> BenchmarkResult:
  """Runs all trial experiments in their pipelines."""
  # Create a pool of worker processes
  with pool.ThreadPool(processes=NUM_EVA) as p:
    # Initialize thread-local storage in each worker before processing
    task_args = [(benchmark, model, args, work_dirs, trial)
                 for trial in range(1, args.num_samples + 1)]
    trial_results = p.starmap(_fuzzing_pipeline, task_args)
  return BenchmarkResult(benchmark=benchmark,
                         work_dirs=work_dirs,
                         trial_results=trial_results)

def run(benchmark: Benchmark, model: models.LLM, args: argparse.Namespace,
        work_dirs: WorkDirs) -> Optional[AggregatedResult]:
  """Generates code via LLM, and evaluates them."""
  model.cloud_setup()

  # Save the benchmark in the WorkDir base. This is saved to the working
  # directory, and should not be deleted in future executions. As such,
  # from here on, do not erase all WorkDir contents.
  Benchmark.to_yaml([benchmark],
                    outdir=work_dirs.base,
                    out_basename='benchmark.yaml')

  return AggregatedResult.from_benchmark_result(
      _fuzzing_pipelines(benchmark, model, args, work_dirs))
