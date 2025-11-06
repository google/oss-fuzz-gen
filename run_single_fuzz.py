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
from agent_graph import FuzzingWorkflow
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as exp_evaluator
from experiment import oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from llm_toolkit import models
from results import BenchmarkResult, Result, TrialResult

# WARN: Avoid high value for NUM_EVA for local experiments.
# NUM_EVA controls the number of fuzz targets to evaluate in parallel by each
# experiment, while {run_logicfuzz.NUM_EXP, default 2} experiments will
# run in parallel.
NUM_EVA = int(os.getenv('LLM_NUM_EVA', '6'))

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

# Default results directory (matches main branch behavior)
# Each benchmark gets its own directory: results/output-{project}-{function}/
RESULTS_DIR = './results'

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
        max_coverage_sample=benchmark_result.max_coverage_sample,
        max_coverage_diff_sample=benchmark_result.max_coverage_diff_sample,
        max_coverage_diff_report=benchmark_result.line_coverage_report,
        full_textcov_diff=benchmark_result.textcov_diff)


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

def _prepare_shared_data(benchmark: Benchmark, args: argparse.Namespace) -> dict:
  """
  Extract shared data that's identical for all trials.
  
  This function queries FuzzIntrospector once and returns data that
  all trials can share, avoiding redundant network I/O and computation.
  
  Args:
      benchmark: Benchmark containing project and function info
      args: Command line arguments
      
  Returns:
      Dictionary with shared data:
      - source_code: Function source code from FI
      - api_context: API context (parameters, types, examples, etc.)
      - api_dependencies: Dependency graph
      - header_info: Header file information
      - existing_fuzzer_headers: Headers from existing fuzzers
  """
  import time
  from data_prep import introspector
  from agent_graph.api_context_extractor import APIContextExtractor
  from agent_graph.api_dependency_analyzer import APIDependencyAnalyzer
  
  project_name = benchmark.project
  function_signature = benchmark.function_signature
  
  logger.info(f'📦 Pre-fetching shared data for {function_signature}', trial=0)
  fetch_start = time.time()
  
  # 1. Query function source code
  logger.debug(f'  1/4 Querying source code...', trial=0)
  source_code = introspector.query_introspector_function_source(
      project_name, function_signature
  )
  
  # 2. Extract API context (parameters, types, examples)
  logger.debug(f'  2/4 Extracting API context...', trial=0)
  extractor = APIContextExtractor(project_name)
  api_context = extractor.extract(function_signature)
  
  # 3. Build dependency graph
  logger.debug(f'  3/4 Building dependency graph...', trial=0)
  use_llm_for_deps = getattr(args, 'use_llm_api_analysis', False)
  analyzer = APIDependencyAnalyzer(
      project_name,
      llm=None,  # Don't use LLM in shared data preparation
      use_llm=False  # Always use heuristic mode for shared data
  )
  api_dependencies = analyzer.build_dependency_graph(function_signature)
  
  # 4. Extract header information
  logger.debug(f'  4/4 Extracting headers...', trial=0)
  from agent_graph.header_extractor import HeaderExtractor
  header_extractor = HeaderExtractor(project_name)
  header_info = header_extractor.get_all_headers(function_signature)
  
  # Extract existing fuzzer headers
  existing_fuzzer_headers = _extract_existing_fuzzer_headers_helper(project_name)
  
  fetch_duration = time.time() - fetch_start
  logger.info(f'✅ Shared data prepared in {fetch_duration:.2f}s', trial=0)
  logger.info(
      f'   └─ Source: {len(source_code) if source_code else 0} chars, '
      f'API context: {len(api_context.get("parameters", []))} params, '
      f'Deps: {len(api_dependencies.get("call_sequence", []))} funcs, '
      f'Headers: {len(header_info)} types',
      trial=0
  )
  
  return {
      'source_code': source_code,
      'api_context': api_context,
      'api_dependencies': api_dependencies,
      'header_info': header_info,
      'existing_fuzzer_headers': existing_fuzzer_headers,
      'timestamp': fetch_start,  # For debugging
  }


def _extract_existing_fuzzer_headers_helper(project_name: str) -> dict:
  """Helper to extract headers from existing fuzzers."""
  from data_prep import introspector
  import re
  
  existing_fuzzer_headers = {
      'standard_headers': set(),
      'project_headers': set()
  }
  
  try:
      # Get all fuzzer files
      fuzzers = introspector.query_introspector_harness_files(project_name)
      if not fuzzers:
          return existing_fuzzer_headers
      
      # Extract headers from each fuzzer
      for fuzzer_path in fuzzers[:5]:  # Limit to avoid overhead
          fuzzer_source = introspector.query_introspector_file_source(
              project_name, fuzzer_path
          )
          if fuzzer_source:
              # Extract #include statements
              for line in fuzzer_source.split('\n')[:50]:  # Only check top of file
                  include_match = re.match(r'^\s*#include\s+[<"]([^>"]+)[>"]', line)
                  if include_match:
                      header = include_match.group(1)
                      if header.startswith(project_name) or '/' in header:
                          existing_fuzzer_headers['project_headers'].add(header)
                      else:
                          existing_fuzzer_headers['standard_headers'].add(header)
  except Exception as e:
      logger.warning(f'Failed to extract existing fuzzer headers: {e}', trial=0)
  
  return {
      'standard_headers': list(existing_fuzzer_headers['standard_headers']),
      'project_headers': list(existing_fuzzer_headers['project_headers'])
  }


def _fuzzing_pipeline(benchmark: Benchmark, model: models.LLM,
                      args: argparse.Namespace, work_dirs: WorkDirs,
                      trial: int, shared_data: dict = None) -> TrialResult:
  """Runs the LangGraph-based fuzzing workflow for one trial."""
  trial_logger = logger.get_trial_logger(trial=trial, level=logging.DEBUG)
  trial_logger.info('Trial Starts')
  
  # Log shared data usage
  if shared_data:
    trial_logger.info(f'Using shared data prepared at timestamp {shared_data.get("timestamp", "unknown")}')
  else:
    trial_logger.warning('No shared data provided - will query FI independently (inefficient!)')
  
  # Note: signal-based timeout is disabled because signal.signal() only works in main thread
  # ThreadPool workers run in separate threads, so signal.SIGALRM cannot be used here
  # If timeout protection is needed, consider using multiprocessing.Pool instead of ThreadPool
  TRIAL_TIMEOUT = getattr(args, 'trial_timeout', 7200)  # 2 hours default
  trial_logger.info(f'⏰ Trial timeout configured: {TRIAL_TIMEOUT} seconds ({TRIAL_TIMEOUT/3600:.1f} hours)')
  trial_logger.info('⏰ Note: signal-based timeout disabled (running in ThreadPool, not main thread)')
  
  try:
    # Use the LangGraph-based agent system
    trial_logger.info('Using LangGraph-based agent workflow')
    
    # Update args with work_dirs for compatibility
    args.work_dirs = work_dirs
    
    # Create and run the LangGraph workflow
    trial_logger.info('🔧 Creating FuzzingWorkflow instance...')
    workflow = FuzzingWorkflow(model, args, shared_data=shared_data)
    trial_logger.info('✅ FuzzingWorkflow instance created')
    
    # Run the full supervisor-based workflow
    trial_logger.info('🚀 Starting workflow.run()...')
    trial_logger.info(f'   Benchmark: {benchmark.id}')
    trial_logger.info(f'   Trial: {trial}')
    trial_logger.info(f'   Workflow type: full')
    if shared_data:
      trial_logger.info(f'   Using shared data: YES (timestamp {shared_data.get("timestamp", "?")})')
    else:
      trial_logger.info(f'   Using shared data: NO (will query FI)')
    
    import time
    workflow_start_time = time.time()
    
    try:
      final_state = workflow.run(
          benchmark=benchmark,
          trial=trial,
          workflow_type='full'
      )
      workflow_end_time = time.time()
      workflow_duration = workflow_end_time - workflow_start_time
      trial_logger.info(f'✅ workflow.run() completed in {workflow_duration:.2f} seconds')
    except Exception as e:
      workflow_end_time = time.time()
      workflow_duration = workflow_end_time - workflow_start_time
      trial_logger.error(f'❌ workflow.run() failed after {workflow_duration:.2f} seconds: {e}')
      raise
    
    # Convert LangGraph state back to legacy result format using StateAdapter
    trial_logger.info('🔄 Converting state to result_history...')
    from agent_graph.adapters import StateAdapter
    
    # Use StateAdapter to properly convert state to result_history
    # This creates a complete result_history with BaseResult, BuildResult, RunResult, etc.
    result_history = StateAdapter.state_to_result_history(final_state)
    trial_logger.info(f'✅ Converted to result_history ({len(result_history)} results)')
    
    trial_logger.info('🎉 LangGraph workflow completed successfully')
    
    # Get the best result for saving files
    # The last result should be the most complete one (RunResult or AnalysisResult)
    trial_logger.info('📍 Getting best result from result_history...')
    best_result = result_history[-1] if result_history else None
    trial_logger.info(f'📍 Best result: {type(best_result).__name__ if best_result else "None"}')
    
    # Save fuzz target and build script to disk (matching WritingStage behavior)
    if best_result and best_result.fuzz_target_source:
      trial_logger.info('📍 Writing fuzz target to disk...')
      write_start = time.time()
      trial_logger.write_fuzz_target(best_result)
      write_duration = time.time() - write_start
      trial_logger.info(f'📍 Fuzz target written in {write_duration:.3f}s to {work_dirs.fuzz_targets}')
    else:
      trial_logger.info('📍 No fuzz target to write')
      
    if best_result and best_result.build_script_source:
      trial_logger.info('📍 Writing build script to disk...')
      write_start = time.time()
      trial_logger.write_build_script(best_result)
      write_duration = time.time() - write_start
      trial_logger.info(f'📍 Build script written in {write_duration:.3f}s to {work_dirs.fuzz_targets}')
    else:
      trial_logger.info('📍 No build script to write')
    
    # Convert agent_messages to chat_history format
    trial_logger.info('📍 Converting agent_messages to chat_history...')
    if best_result and 'agent_messages' in final_state:
      chat_history = {}
      for agent_name, messages in final_state['agent_messages'].items():
        # Convert message list to string format
        history_str = '\n'.join([
            f"{msg.get('role', 'unknown').upper()}: {msg.get('content', '')}"
            for msg in messages
        ])
        chat_history[agent_name] = history_str
      best_result.chat_history = chat_history
      trial_logger.info(f'📍 Converted {len(chat_history)} agent message histories')
    else:
      trial_logger.info('📍 No agent_messages to convert')
    
    # Save chat history
    if best_result and best_result.chat_history:
      trial_logger.info('📍 Writing chat history to disk...')
      write_start = time.time()
      trial_logger.write_chat_history(best_result, cycle_count=0)
      write_duration = time.time() - write_start
      trial_logger.info(f'📍 Chat history written in {write_duration:.3f}s to {work_dirs.status}')
    else:
      trial_logger.info('📍 No chat history to write')
    
    # Save token usage to best_result
    if best_result and 'token_usage' in final_state:
      trial_logger.info('📍 Saving token usage to best_result...')
      best_result.token_usage = final_state['token_usage']
      trial_logger.info('📍 Token usage saved')
    
    # Create trial result to match expected return format
    trial_logger.info('📍 Creating TrialResult...')
    trial_result = TrialResult(benchmark=benchmark,
                               trial=trial,
                               work_dirs=work_dirs,
                               result_history=result_history)
    trial_logger.info('📍 TrialResult created')
    
    trial_logger.info('📍 Writing trial result to disk...')
    write_start = time.time()
    trial_logger.write_result(
        result_status_dir=trial_result.best_result.work_dirs.status,
        result=trial_result,
        finished=True)
    write_duration = time.time() - write_start
    trial_logger.info(f'📍 Trial result written in {write_duration:.3f}s')
    
    trial_logger.info('✅ _fuzzing_pipeline completed, returning trial_result')
    return trial_result
    
  except TimeoutError as e:
    trial_logger.error(f'⏰ Trial timed out: {e}')
    trial_logger.error('⏰ Returning empty result due to timeout')
    # Return a minimal failed result
    return TrialResult(
        benchmark=benchmark,
        trial=trial,
        work_dirs=work_dirs,
        result_history=[]
    )
  finally:
    # Note: signal.alarm(0) removed because we disabled signal-based timeout
    trial_logger.info('⏰ Trial cleanup complete')

def _fuzzing_pipelines(benchmark: Benchmark, model: models.LLM,
                       args: argparse.Namespace,
                       work_dirs: WorkDirs) -> BenchmarkResult:
  """Runs all trial experiments in their pipelines."""
  import time
  
  # Use trial=0 for global/non-trial-specific logs
  logger.info(f'📍 [_fuzzing_pipelines] Starting with {args.num_samples} trial(s)', trial=0)
  logger.info(f'📍 [_fuzzing_pipelines] ThreadPool size: {NUM_EVA}', trial=0)
  
  # ============================================================
  # OPTIMIZATION: Pre-fetch shared data (only once for all trials)
  # ============================================================
  logger.info('📍 [_fuzzing_pipelines] Pre-fetching shared data...', trial=0)
  shared_data_start = time.time()
  shared_data = _prepare_shared_data(benchmark, args)
  shared_data_duration = time.time() - shared_data_start
  logger.info(
      f'📍 [_fuzzing_pipelines] Shared data prepared in {shared_data_duration:.2f}s '
      f'(will be reused by all {args.num_samples} trials)',
      trial=0
  )
  
  # Create a pool of worker processes
  logger.info('📍 [_fuzzing_pipelines] Creating ThreadPool...', trial=0)
  pool_start = time.time()
  
  with pool.ThreadPool(processes=NUM_EVA) as p:
    pool_create_duration = time.time() - pool_start
    logger.info(f'📍 [_fuzzing_pipelines] ThreadPool created in {pool_create_duration:.2f}s', trial=0)
    
    # Initialize thread-local storage in each worker before processing
    # IMPORTANT: Pass shared_data to each trial
    task_args = [(benchmark, model, args, work_dirs, trial, shared_data)
                 for trial in range(1, args.num_samples + 1)]
    logger.info(f'📍 [_fuzzing_pipelines] Starting {len(task_args)} trial(s) via starmap...', trial=0)
    
    starmap_start = time.time()
    trial_results = p.starmap(_fuzzing_pipeline, task_args)
    starmap_duration = time.time() - starmap_start
    logger.info(f'📍 [_fuzzing_pipelines] All trials completed in {starmap_duration:.2f}s', trial=0)
    
    # Calculate efficiency metrics
    if args.num_samples > 1:
      time_saved = shared_data_duration * (args.num_samples - 1)
      logger.info(
          f'📊 [_fuzzing_pipelines] Shared data optimization: '
          f'saved ~{time_saved:.1f}s by avoiding {args.num_samples - 1} redundant queries',
          trial=0
      )
    
    logger.info('📍 [_fuzzing_pipelines] Exiting ThreadPool context (will wait for cleanup)...', trial=0)
  
  cleanup_duration = time.time() - starmap_start - starmap_duration
  logger.info(f'📍 [_fuzzing_pipelines] ThreadPool cleanup completed in {cleanup_duration:.2f}s', trial=0)
  
  logger.info('📍 [_fuzzing_pipelines] Creating BenchmarkResult...', trial=0)
  result = BenchmarkResult(benchmark=benchmark,
                          work_dirs=work_dirs,
                          trial_results=trial_results)
  logger.info('📍 [_fuzzing_pipelines] BenchmarkResult created, returning', trial=0)
  return result

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
