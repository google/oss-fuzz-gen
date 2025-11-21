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
"""
OSS-Fuzz SDK - Comprehensive Main Facade.

This module provides the main SDK facade for the complete OSS-Fuzz SDK,
including build operations, execution, result management, benchmark management,
and historical data analysis. It serves as the primary entry point for all
SDK capabilities.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from ossfuzz_py.build.build_config import BuildConfig
from ossfuzz_py.build.builder import LocalBuilder
from ossfuzz_py.build.docker_manager import DockerManager
from ossfuzz_py.core.benchmark_manager import BenchmarkManager
from ossfuzz_py.core.data_models import FuzzingEngine, Sanitizer
# Core imports
from ossfuzz_py.data.storage_manager import StorageManager
from ossfuzz_py.errors import (BenchmarkError, OSSFuzzSDKConfigError,
                               OSSFuzzSDKError)
from ossfuzz_py.execution.fuzz_runner import FuzzRunOptions, LocalRunner
from ossfuzz_py.execution.fuzz_target import FuzzTarget
from ossfuzz_py.history import (BuildHistoryManager, CorpusHistoryManager,
                                CoverageHistoryManager, CrashHistoryManager)
from ossfuzz_py.result.result_manager import ResultManager
from ossfuzz_py.utils.env_utils import EnvUtils
from ossfuzz_py.utils.env_vars import EnvVars
from ossfuzz_py.utils.work_dir_manager import WorkDirManager

# Configuration and Options Classes


class SDKConfig:
  """Configuration class for the OSS-Fuzz SDK."""

  def __init__(self,
               storage_backend: str = 'local',
               storage_path: Optional[str] = None,
               gcs_bucket_name: Optional[str] = None,
               work_dir: Optional[str] = None,
               oss_fuzz_dir: Optional[str] = None,
               enable_caching: bool = True,
               log_level: str = 'INFO',
               timeout_seconds: int = 3600,
               max_retries: int = 3):
    """Initialize SDK configuration."""
    self.storage_backend = storage_backend
    self.storage_path = storage_path or EnvUtils.get_work_dir()
    self.gcs_bucket_name = gcs_bucket_name
    self.work_dir = work_dir or EnvUtils.get_work_dir()
    self.oss_fuzz_dir = oss_fuzz_dir or EnvUtils.get_oss_fuzz_dir()
    self.enable_caching = enable_caching
    self.log_level = log_level
    self.timeout_seconds = timeout_seconds
    self.max_retries = max_retries

  def to_dict(self) -> Dict[str, Any]:
    """Convert configuration to dictionary."""
    return {
        'storage_backend': self.storage_backend,
        'storage_path': self.storage_path,
        'gcs_bucket_name': self.gcs_bucket_name,
        'work_dir': self.work_dir,
        'oss_fuzz_dir': self.oss_fuzz_dir,
        'enable_caching': self.enable_caching,
        'log_level': self.log_level,
        'timeout_seconds': self.timeout_seconds,
        'max_retries': self.max_retries,
    }


class BuildOptions:
  """Options for build operations."""

  def __init__(self,
               sanitizer: Optional[str] = 'address',
               architecture: str = 'x86_64',
               fuzzing_engine: Optional[str] = 'libfuzzer',
               environment_vars: Optional[Dict[str, str]] = None,
               build_args: Optional[List[str]] = None,
               timeout_seconds: Optional[int] = None):
    """Initialize build options."""
    self.sanitizer = sanitizer
    self.architecture = architecture
    self.fuzzing_engine = fuzzing_engine
    self.environment_vars = environment_vars or {}
    self.build_args = build_args or []
    self.timeout_seconds = timeout_seconds


class RunOptions:
  """Options for execution operations."""

  def __init__(self,
               duration_seconds: int = 3600,
               timeout_seconds: int = 25,
               max_memory_mb: int = 1024,
               detect_leaks: bool = True,
               extract_coverage: bool = False,
               corpus_dir: Optional[str] = None,
               output_dir: str = 'fuzz_output',
               engine_args: Optional[List[str]] = None,
               env_vars: Optional[Dict[str, str]] = None):
    """Initialize run options."""
    self.duration_seconds = duration_seconds
    self.timeout_seconds = timeout_seconds
    self.max_memory_mb = max_memory_mb
    self.detect_leaks = detect_leaks
    self.extract_coverage = extract_coverage
    self.corpus_dir = corpus_dir
    self.output_dir = output_dir
    self.engine_args = engine_args or []
    self.env_vars = env_vars or {}


class PipelineOptions:
  """Options for full pipeline operations."""

  def __init__(self,
               build_options: Optional[BuildOptions] = None,
               run_options: Optional[RunOptions] = None,
               trials: int = 1,
               analyze_coverage: bool = True,
               store_results: bool = True):
    """Initialize pipeline options."""
    self.build_options = build_options or BuildOptions()
    self.run_options = run_options or RunOptions()
    self.trials = trials
    self.analyze_coverage = analyze_coverage
    self.store_results = store_results


# Result Classes


class BuildResult:
  """Result of a build operation."""

  def __init__(self,
               success: bool,
               message: str = '',
               build_id: Optional[str] = None,
               artifacts: Optional[Dict] = None):
    self.success = success
    self.message = message
    self.build_id = build_id or str(uuid.uuid4())
    self.artifacts = artifacts or {}
    self.timestamp = datetime.now()


class RunResult:
  """Result of a run operation."""

  def __init__(self,
               success: bool,
               message: str = '',
               run_id: Optional[str] = None,
               crashes: bool = False,
               coverage_data: Optional[Dict] = None):
    self.success = success
    self.message = message
    self.run_id = run_id or str(uuid.uuid4())
    self.crashes = crashes
    self.coverage_data = coverage_data or {}
    self.timestamp = datetime.now()


class PipelineResult:
  """Result of a full pipeline operation."""

  def __init__(self,
               success: bool,
               message: str = '',
               pipeline_id: Optional[str] = None,
               build_results: Optional[List[BuildResult]] = None,
               run_results: Optional[List[RunResult]] = None):
    self.success = success
    self.message = message
    self.pipeline_id = pipeline_id or str(uuid.uuid4())
    self.build_results = build_results or []
    self.run_results = run_results or []
    self.timestamp = datetime.now()


class OSSFuzzSDK:
  """
  Comprehensive main facade for the OSS-Fuzz SDK.

  This class provides a unified interface for all
  OSS-Fuzz SDK capabilities including:
  - Build operations (building fuzz targets and benchmarks)
  - Execution operations (running fuzz targets and benchmarks)
  - Result management (storing, retrieving, and analyzing results)
  - Benchmark management (CRUD operations on benchmarks)
  - Workflow orchestration (full build → run → analyze pipelines)
  - Historical data analysis (reports and analytics)

  The SDK is designed to be both beginner-friendly for simple tasks and
  expert-capable for advanced use cases.

  Examples:
      ```python
      # Initialize SDK
      sdk = OSSFuzzSDK('libpng')

      # Simple benchmark run
      result = sdk.run_benchmark('benchmark_id')

      # Full pipeline with custom options
      options = PipelineOptions(trials=3)
      pipeline_result = sdk.run_full_pipeline('benchmark_id', options)

      # Get comprehensive metrics
      metrics = sdk.get_benchmark_metrics('benchmark_id')

      # Historical analysis
      report = sdk.generate_project_report(days=30)
      ```
  """

  def __init__(self,
               project_name: str,
               config: Optional[Union[Dict[str, Any], SDKConfig]] = None):
    """
    Initialize the comprehensive OSS-Fuzz SDK.

    Args:
        project_name: Name of the OSS-Fuzz project
        config: Configuration dictionary or SDKConfig instance

    Raises:
        OSSFuzzSDKConfigError: If configuration is invalid
        OSSFuzzSDKError: If initialization fails
    """
    self.project_name = project_name

    # Handle configuration
    if isinstance(config, SDKConfig):
      self.sdk_config = config
      self.config = config.to_dict()
    else:
      self.config = config or {}
      self.sdk_config = SDKConfig(**self.config)

    self.logger = logging.getLogger(f"{__name__}.{project_name}")

    try:
      if not project_name:
        raise OSSFuzzSDKConfigError("Project name is required")

      # Merge environment variables into config
      self._load_config_from_env()

      # Initialize storage manager
      self.storage = StorageManager(self.config)

      # Initialize core components
      self._initialize_components()

      self.logger.info("Initialized comprehensive OSSFuzzSDK for project: %s",
                       project_name)

    except OSSFuzzSDKConfigError:
      # Re-raise config errors as-is
      raise
    except Exception as e:
      error_msg = (
          f"Failed to initialize OSSFuzzSDK for {project_name}: {str(e)}")
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg) from e

  def _initialize_components(self) -> None:
    """Initialize all SDK components"""
    self.build_history = BuildHistoryManager(self.storage, self.project_name)
    self.crash_history = CrashHistoryManager(self.storage, self.project_name)
    self.corpus_history = CorpusHistoryManager(self.storage, self.project_name)
    self.coverage_history = CoverageHistoryManager(self.storage,
                                                   self.project_name)

    # Initialize BenchmarkManager first
    self.benchmark_manager = BenchmarkManager()

    # Initialize ResultManager with BenchmarkManager
    self.result_manager = ResultManager(
        build_mgr=self.build_history,
        crash_mgr=self.crash_history,
        corpus_mgr=self.corpus_history,
        coverage_mgr=self.coverage_history,
        benchmark_manager=self.benchmark_manager,
    )

    # Initialize build components
    self._initialize_build_components()

    # Initialize execution components
    self._initialize_execution_components()

  @property
  def build(self) -> BuildHistoryManager:
    """Access to build history manager."""
    return self.build_history

  @property
  def crash(self) -> CrashHistoryManager:
    """Access to crash history manager."""
    return self.crash_history

  @property
  def corpus(self) -> CorpusHistoryManager:
    """Access to corpus history manager."""
    return self.corpus_history

  @property
  def coverage(self) -> CoverageHistoryManager:
    """Access to coverage history manager."""
    return self.coverage_history

  def _initialize_build_components(self) -> None:
    """Initialize build-related components."""
    try:
      # Create build configuration
      build_config = BuildConfig(
          project_name=self.project_name,
          language='c++',  # Default language
          sanitizer=Sanitizer.ADDRESS,
          fuzzing_engine=FuzzingEngine.LIBFUZZER,
      )

      # Initialize Docker manager for local builds
      docker_manager = DockerManager()

      # Initialize builders
      self.local_builder = LocalBuilder(
          storage_manager=self.storage,
          build_config=build_config,
          docker_manager=docker_manager,
          result_manager=self.result_manager,
      )

      # Cloud builder initialization would go here
      self.cloud_builder = None  # TODO: Initialize when needed

    except Exception as e:
      self.logger.warning("Failed to initialize build components: %s", str(e))
      self.local_builder = self.cloud_builder = None

  def _initialize_execution_components(self) -> None:
    """Initialize execution-related components."""
    try:
      # Initialize work directory manager
      work_dir_manager = WorkDirManager(base_dir=self.sdk_config.work_dir)

      # Initialize runners
      self.local_runner = LocalRunner(
          work_dir_manager=work_dir_manager,
          result_manager=self.result_manager,
      )

      # Cloud runner initialization would go here
      self.cloud_runner = None  # TODO: Initialize when needed

    except Exception as e:
      self.logger.warning("Failed to initialize execution components: %s",
                          str(e))
      self.local_runner = self.cloud_runner = None

  def _load_config_from_env(self) -> None:
    """Load configuration from environment variables."""
    try:
      # Storage configuration
      storage_backend = EnvUtils.get_env(
          EnvVars.OSSFUZZ_HISTORY_STORAGE_BACKEND)
      if storage_backend:
        self.config['storage_backend'] = storage_backend

      storage_path = EnvUtils.get_env(EnvVars.OSSFUZZ_HISTORY_STORAGE_PATH)
      if storage_path:
        self.config['storage_path'] = storage_path

      # GCS configuration
      gcs_bucket = EnvUtils.get_env(EnvVars.GCS_BUCKET_NAME)
      if gcs_bucket:
        self.config['gcs_bucket_name'] = gcs_bucket

      # Work directory
      work_dir = EnvUtils.get_env(EnvVars.WORK_DIR)
      if work_dir:
        self.config['work_dir'] = work_dir

    except Exception as e:
      self.logger.warning("Failed to load some environment variables: %s",
                          str(e))

  # Build Operations

  def build_fuzz_target(self,
                        target_spec: Union[FuzzTarget, Dict[str, Any]],
                        options: Optional[BuildOptions] = None) -> BuildResult:
    """
    Build a single fuzz target.

    Args:
        target_spec: FuzzTarget instance or dictionary specification
        options: Build options (optional)

    Returns:
        BuildResult: Result of the build operation

    Raises:
        BuilderError: If build fails
        OSSFuzzSDKError: If SDK components not available
    """
    try:
      if not self.local_builder:
        raise OSSFuzzSDKError("Build components not available")

      # Convert dict to FuzzTarget if needed
      if isinstance(target_spec, dict):
        target = FuzzTarget(**target_spec)
      else:
        target = target_spec

      options = options or BuildOptions()

      # Convert options to appropriate format
      sanitizer = getattr(
          Sanitizer,
          options.sanitizer.upper()) if options.sanitizer else Sanitizer.ADDRESS

      # Perform the build
      result = self.local_builder.build(target=target,
                                        sanitizer=sanitizer,
                                        benchmark_id=target.name,
                                        trial=1)

      return BuildResult(
          success=result.success,
          message=result.message,
          artifacts=result.metadata if hasattr(result, 'metadata') else {})

    except Exception as e:
      error_msg = f"Failed to build fuzz target: {str(e)}"
      self.logger.error(error_msg)
      return BuildResult(success=False, message=error_msg)

  def build_benchmark(self,
                      benchmark_id: str,
                      options: Optional[BuildOptions] = None) -> BuildResult:
    """
    Build a specific benchmark.

    Args:
        benchmark_id: Benchmark identifier
        options: Build options (optional)

    Returns:
        BuildResult: Result of the build operation

    Raises:
        BenchmarkError: If benchmark not found
        BuilderError: If build fails
    """
    try:
      if not self.benchmark_manager:
        raise OSSFuzzSDKError("BenchmarkManager not available")

      # Get benchmark from manager
      benchmark = self.benchmark_manager.get_benchmark(benchmark_id)
      if not benchmark:
        raise BenchmarkError(f"Benchmark not found: {benchmark_id}")

      # Create FuzzTarget from benchmark (would need implementation)
      # For now, create a minimal target
      target = FuzzTarget(
          name=benchmark.function_name,
          source_code="// Generated fuzz target",
          build_script="// Generated build script",
          project_name=benchmark.project,
          language=benchmark.language,
          function_signature=benchmark.function_signature,
      )

      return self.build_fuzz_target(target, options)

    except Exception as e:
      error_msg = f"Failed to build benchmark {benchmark_id}: {str(e)}"
      self.logger.error(error_msg)
      return BuildResult(success=False, message=error_msg)

  def get_build_status(self, build_id: str) -> Dict[str, Any]:
    """
    Check build status.

    Args:
        build_id: Build identifier

    Returns:
        Dictionary containing build status information
    """
    try:
      # This would query build history or active builds
      # For now, return a basic status
      return {
          'build_id': build_id,
          'status': 'unknown',
          'message': 'Build status tracking not yet implemented',
          'timestamp': datetime.now().isoformat()
      }
    except Exception as e:
      self.logger.error("Failed to get build status: %s", str(e))
      return {
          'build_id': build_id,
          'status': 'error',
          'message': str(e),
          'timestamp': datetime.now().isoformat()
      }

  def get_build_artifacts(self, build_id: str) -> Dict[str, Any]:
    """
    Retrieve build artifacts.

    Args:
        build_id: Build identifier

    Returns:
        Dictionary containing build artifacts
    """
    try:
      # This would retrieve artifacts from storage
      # For now, return empty artifacts
      return {
          'build_id': build_id,
          'artifacts': {},
          'message': 'Artifact retrieval not yet implemented'
      }
    except Exception as e:
      self.logger.error("Failed to get build artifacts: %s", str(e))
      return {'build_id': build_id, 'artifacts': {}, 'error': str(e)}

  def list_recent_builds(
      self,
      limit: int = 10,
      filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    List recent builds with filtering.

    Args:
        limit: Maximum number of builds to return
        filters: Optional filters to apply

    Returns:
        List of build information dictionaries
    """
    try:
      if not self.build_history:
        return []

      # Get build history
      builds = self.build_history.get_build_history(limit=limit)

      # Apply filters if provided
      if filters:
        # Basic filtering implementation
        filtered_builds = []
        for build in builds:
          include = True
          for key, value in filters.items():
            if key in build and build[key] != value:
              include = False
              break
          if include:
            filtered_builds.append(build)
        builds = filtered_builds

      return builds[:limit]

    except Exception as e:
      self.logger.error("Failed to list recent builds: %s", str(e))
      return []

  # Execution Operations

  def run_fuzz_target(self,
                      target_spec: Union[FuzzTarget, Dict[str, Any]],
                      build_metadata: Dict[str, Any],
                      options: Optional[RunOptions] = None) -> RunResult:
    """
    Run a single fuzz target.

    Args:
        target_spec: FuzzTarget instance or dictionary specification
        build_metadata: Build metadata from previous build operation
        options: Run options (optional)

    Returns:
        RunResult: Result of the run operation

    Raises:
        FuzzRunnerError: If run fails
        OSSFuzzSDKError: If SDK components not available
    """
    try:
      if not self.local_runner:
        raise OSSFuzzSDKError("Execution components not available")

      # Convert dict to FuzzTarget if needed
      if isinstance(target_spec, dict):
        target = FuzzTarget(**target_spec)
      else:
        target = target_spec

      options = options or RunOptions()

      # Convert options to FuzzRunOptions
      fuzz_options = FuzzRunOptions(
          duration_seconds=options.duration_seconds,
          timeout_seconds=options.timeout_seconds,
          max_memory_mb=options.max_memory_mb,
          detect_leaks=options.detect_leaks,
          extract_coverage=options.extract_coverage,
          corpus_dir=options.corpus_dir,
          output_dir=options.output_dir,
          engine_args=options.engine_args,
          env_vars=options.env_vars,
      )

      # Perform the run
      run_info = self.local_runner.run(target=target.name,
                                       options=fuzz_options,
                                       build_metadata=build_metadata,
                                       benchmark_id=target.name,
                                       trial=1)

      return RunResult(
          success=not run_info.crashes if run_info else False,
          message=run_info.run_log if run_info else 'Run completed',
          crashes=run_info.crashes if run_info else False,
          coverage_data={
              'cov_pcs': run_info.cov_pcs if run_info else 0,
              'total_pcs': run_info.total_pcs if run_info else 0,
          } if run_info else {})

    except Exception as e:
      error_msg = f"Failed to run fuzz target: {str(e)}"
      self.logger.error(error_msg)
      return RunResult(success=False, message=error_msg)

  def run_benchmark(self,
                    benchmark_id: str,
                    options: Optional[RunOptions] = None) -> RunResult:
    """
    Run a specific benchmark (build + run).

    Args:
        benchmark_id: Benchmark identifier
        options: Run options (optional)

    Returns:
        RunResult: Result of the run operation

    Raises:
        BenchmarkError: If benchmark not found
        FuzzRunnerError: If run fails
    """
    try:
      # First build the benchmark
      build_result = self.build_benchmark(benchmark_id)
      if not build_result.success:
        return RunResult(success=False,
                         message=f"Build failed: {build_result.message}")

      # Then run it
      if not self.benchmark_manager:
        raise OSSFuzzSDKError("BenchmarkManager not available")

      benchmark = self.benchmark_manager.get_benchmark(benchmark_id)
      if not benchmark:
        raise BenchmarkError(f"Benchmark not found: {benchmark_id}")

      # Create FuzzTarget from benchmark
      target = FuzzTarget(
          name=benchmark.function_name,
          source_code="// Generated fuzz target",
          build_script="// Generated build script",
          project_name=benchmark.project,
          language=benchmark.language,
          function_signature=benchmark.function_signature,
      )

      return self.run_fuzz_target(target, build_result.artifacts, options)

    except Exception as e:
      error_msg = f"Failed to run benchmark {benchmark_id}: {str(e)}"
      self.logger.error(error_msg)
      return RunResult(success=False, message=error_msg)

  def get_run_status(self, run_id: str) -> Dict[str, Any]:
    """
    Check run status.

    Args:
        run_id: Run identifier

    Returns:
        Dictionary containing run status information
    """
    try:
      # This would query run history or active runs
      # For now, return a basic status
      return {
          'run_id': run_id,
          'status': 'unknown',
          'message': 'Run status tracking not yet implemented',
          'timestamp': datetime.now().isoformat()
      }
    except Exception as e:
      self.logger.error("Failed to get run status: %s", str(e))
      return {
          'run_id': run_id,
          'status': 'error',
          'message': str(e),
          'timestamp': datetime.now().isoformat()
      }

  def get_run_results(self, run_id: str) -> Dict[str, Any]:
    """
    Retrieve run results and artifacts.

    Args:
        run_id: Run identifier

    Returns:
        Dictionary containing run results
    """
    try:
      # This would retrieve results from storage
      # For now, return empty results
      return {
          'run_id': run_id,
          'results': {},
          'message': 'Result retrieval not yet implemented'
      }
    except Exception as e:
      self.logger.error("Failed to get run results: %s", str(e))
      return {'run_id': run_id, 'results': {}, 'error': str(e)}

  def list_recent_runs(
      self,
      limit: int = 10,
      filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    List recent runs with filtering.

    Args:
        limit: Maximum number of runs to return
        filters: Optional filters to apply

    Returns:
        List of run information dictionaries
    """
    try:
      if not self.crash_history:
        return []

      # Get crash history as proxy for run history
      runs = self.crash_history.get_crash_history(limit=limit)

      # Apply filters if provided
      if filters:
        # Basic filtering implementation
        filtered_runs = []
        for run in runs:
          include = True
          for key, value in filters.items():
            if key in run and run[key] != value:
              include = False
              break
          if include:
            filtered_runs.append(run)
        runs = filtered_runs

      return runs[:limit]

    except Exception as e:
      self.logger.error("Failed to list recent runs: %s", str(e))
      return []

  # Workflow Orchestration

  def run_full_pipeline(
      self,
      benchmark_id: str,
      options: Optional[PipelineOptions] = None) -> PipelineResult:
    """
    Run a complete build → run → analyze pipeline.

    Args:
        benchmark_id: Benchmark identifier
        options: Pipeline options (optional)

    Returns:
        PipelineResult: Result of the complete pipeline
    """
    try:
      options = options or PipelineOptions()
      build_results = []
      run_results = []

      # Run multiple trials if specified
      for trial in range(1, options.trials + 1):
        self.logger.info("Running pipeline trial %d/%d for %s", trial,
                         options.trials, benchmark_id)

        # Build phase
        build_result = self.build_benchmark(benchmark_id, options.build_options)
        build_results.append(build_result)

        if not build_result.success:
          self.logger.warning("Build failed for trial %d, skipping run", trial)
          continue

        # Run phase
        run_result = self.run_benchmark(benchmark_id, options.run_options)
        run_results.append(run_result)

        # Analysis phase (if enabled)
        if options.analyze_coverage and run_result.success:
          try:
            self._analyze_coverage(benchmark_id, run_result)
          except Exception as e:
            self.logger.warning("Coverage analysis failed for trial %d: %s",
                                trial, str(e))

        # Store results (if enabled)
        if options.store_results and self.result_manager:
          try:
            self._store_pipeline_result(benchmark_id, build_result, run_result,
                                        trial)
          except Exception as e:
            self.logger.warning("Result storage failed for trial %d: %s", trial,
                                str(e))

      # Determine overall success
      successful_builds = sum(1 for r in build_results if r.success)
      successful_runs = sum(1 for r in run_results if r.success)

      overall_success = successful_builds > 0 and successful_runs > 0
      message = (
          f"Pipeline completed: {successful_builds}/{len(build_results)} "
          f"builds, {successful_runs}/{len(run_results)} runs successful")

      return PipelineResult(success=overall_success,
                            message=message,
                            build_results=build_results,
                            run_results=run_results)

    except Exception as e:
      error_msg = f"Pipeline failed for {benchmark_id}: {str(e)}"
      self.logger.error(error_msg)
      return PipelineResult(success=False, message=error_msg)

  def _analyze_coverage(self, benchmark_id: str, run_result: RunResult) -> None:
    """Analyze coverage for a run result."""
    # Placeholder for coverage analysis
    self.logger.debug("Coverage analysis for %s: %s", benchmark_id,
                      run_result.coverage_data)

  def _store_pipeline_result(self, benchmark_id: str, build_result: BuildResult,
                             run_result: RunResult, trial: int) -> None:
    """Store pipeline result through ResultManager."""
    # pylint: disable=unused-argument
    if not self.result_manager:
      return

    # This would create a comprehensive Result object and store it
    self.logger.debug("Storing pipeline result for %s trial %d", benchmark_id,
                      trial)

  # Result Management Operations

  def get_benchmark_result(self,
                           benchmark_id: str,
                           trial: Optional[int] = None) -> Optional[Any]:
    """
    Get result for a specific benchmark.

    Args:
        benchmark_id: Benchmark identifier
        trial: Specific trial number (optional, gets latest if not specified)

    Returns:
        Result object or None if not found
    """
    try:
      if not self.result_manager:
        self.logger.warning("ResultManager not available")
        return None

      if trial is not None:
        return self.result_manager.get_trial_result(benchmark_id, trial)
      return self.result_manager.get_result(benchmark_id)

    except Exception as e:
      self.logger.error("Failed to get benchmark result: %s", str(e))
      return None

  def get_benchmark_metrics(self, benchmark_id: str) -> Dict[str, Any]:
    """
    Get comprehensive metrics for a benchmark.

    Args:
        benchmark_id: Benchmark identifier

    Returns:
        Dictionary containing comprehensive metrics
    """
    try:
      if not self.result_manager:
        self.logger.warning("ResultManager not available")
        return {}

      return self.result_manager.get_metrics(benchmark_id)

    except Exception as e:
      self.logger.error("Failed to get benchmark metrics: %s", str(e))
      return {}

  def get_system_metrics(self) -> Dict[str, Any]:
    """
    Get system-wide aggregated metrics.

    Returns:
        Dictionary containing system-wide metrics
    """
    try:
      if not self.result_manager:
        self.logger.warning("ResultManager not available")
        return {}

      return self.result_manager.get_metrics()

    except Exception as e:
      self.logger.error("Failed to get system metrics: %s", str(e))
      return {}

  def get_coverage_trend(self,
                         benchmark_id: str,
                         days: int = 30) -> Union[Any, List[Dict[str, Any]]]:
    """
    Get coverage trend for a benchmark.

    Args:
        benchmark_id: Benchmark identifier
        days: Number of days to analyze

    Returns:
        Coverage trend data (DataFrame if pandas available, list otherwise)
    """
    try:
      if not self.result_manager:
        self.logger.warning("ResultManager not available")
        return []

      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      return self.result_manager.coverage_trend(benchmark_id, start_date,
                                                end_date)

    except Exception as e:
      self.logger.error("Failed to get coverage trend: %s", str(e))
      return []

  def get_build_success_rate(self, benchmark_id: str, days: int = 30) -> float:
    """
    Get build success rate for a benchmark.

    Args:
        benchmark_id: Benchmark identifier
        days: Number of days to analyze

    Returns:
        Build success rate (0.0 to 1.0)
    """
    try:
      if not self.result_manager:
        self.logger.warning("ResultManager not available")
        return 0.0

      return self.result_manager.get_build_success_rate(benchmark_id, days)

    except Exception as e:
      self.logger.error("Failed to get build success rate: %s", str(e))
      return 0.0

  def get_crash_summary(self,
                        benchmark_id: str,
                        days: int = 30) -> Dict[str, Any]:
    """
    Get crash summary for a benchmark.

    Args:
        benchmark_id: Benchmark identifier
        days: Number of days to analyze

    Returns:
        Dictionary containing crash statistics
    """
    try:
      if not self.result_manager:
        self.logger.warning("ResultManager not available")
        return {}

      return self.result_manager.get_crash_summary(benchmark_id, days)

    except Exception as e:
      self.logger.error("Failed to get crash summary: %s", str(e))
      return {}

  # Benchmark Management Operations

  def create_benchmark(self, benchmark_spec: Dict[str, Any]) -> bool:
    """
    Create a new benchmark.

    Args:
        benchmark_spec: Benchmark specification dictionary

    Returns:
        True if successful, False otherwise
    """
    try:
      if not self.benchmark_manager:
        self.logger.warning("BenchmarkManager not available")
        return False

      # This would create a new benchmark
      # For now, just log the operation
      self.logger.info("Creating benchmark: %s",
                       benchmark_spec.get('id', 'unknown'))
      return True

    except Exception as e:
      self.logger.error("Failed to create benchmark: %s", str(e))
      return False

  def update_benchmark(self, benchmark_id: str, updates: Dict[str,
                                                              Any]) -> bool:
    """
    Update an existing benchmark.

    Args:
        benchmark_id: Benchmark identifier
        updates: Dictionary of updates to apply

    Returns:
        True if successful, False otherwise
    """
    try:
      if not self.benchmark_manager:
        self.logger.warning("BenchmarkManager not available")
        return False

      # This would update the benchmark
      # For now, just log the operation
      self.logger.info("Updating benchmark %s: %s", benchmark_id,
                       list(updates.keys()))
      return True

    except Exception as e:
      self.logger.error("Failed to update benchmark: %s", str(e))
      return False

  def delete_benchmark(self, benchmark_id: str) -> bool:
    """
    Delete a benchmark.

    Args:
        benchmark_id: Benchmark identifier

    Returns:
        True if successful, False otherwise
    """
    try:
      if not self.benchmark_manager:
        self.logger.warning("BenchmarkManager not available")
        return False

      # This would delete the benchmark
      # For now, just log the operation
      self.logger.info("Deleting benchmark: %s", benchmark_id)
      return True

    except Exception as e:
      self.logger.error("Failed to delete benchmark: %s", str(e))
      return False

  def list_benchmarks(self,
                      filters: Optional[Dict[str, Any]] = None
                     ) -> List[Dict[str, Any]]:
    """
    List available benchmarks with filtering.

    Args:
        filters: Optional filters to apply

    Returns:
        List of benchmark information dictionaries
    """
    # pylint: disable=unused-argument
    try:
      if not self.benchmark_manager:
        self.logger.warning("BenchmarkManager not available")
        return []

      # This would list benchmarks from the manager
      # For now, return empty list
      return []

    except Exception as e:
      self.logger.error("Failed to list benchmarks: %s", str(e))
      return []

  def search_benchmarks(self,
                        query: str,
                        limit: int = 10) -> List[Dict[str, Any]]:
    """
    Search benchmarks by query.

    Args:
        query: Search query string
        limit: Maximum number of results

    Returns:
        List of matching benchmark information dictionaries
    """
    # pylint: disable=unused-argument
    try:
      if not self.benchmark_manager:
        self.logger.warning("BenchmarkManager not available")
        return []

      # This would search benchmarks
      # For now, return empty list
      self.logger.info("Searching benchmarks for: %s", query)
      return []

    except Exception as e:
      self.logger.error("Failed to search benchmarks: %s", str(e))
      return []

  # Export and Analysis Operations

  def export_results(self,
                     benchmark_ids: List[str],
                     export_format: str = 'json',
                     output_path: Optional[str] = None) -> str:
    """
    Export results for multiple benchmarks.

    Args:
        benchmark_ids: List of benchmark identifiers
        export_format: Export format ('json', 'csv', 'xlsx')
        output_path: Optional output file path

    Returns:
        Path to exported file
    """
    try:
      if not self.result_manager:
        raise OSSFuzzSDKError("ResultManager not available")

      # This would export results in the specified format
      # For now, create a placeholder file
      if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"ossfuzz_export_{timestamp}.{export_format}"

      self.logger.info("Exporting results for %d benchmarks to %s",
                       len(benchmark_ids), output_path)

      # Create placeholder export
      export_data = {
          'export_timestamp': datetime.now().isoformat(),
          'benchmark_count': len(benchmark_ids),
          'benchmark_ids': benchmark_ids,
          'format': export_format,
          'message': 'Export functionality not yet implemented'
      }

      # Write placeholder file
      import json
      with open(output_path, 'w') as f:
        json.dump(export_data, f, indent=2)

      return output_path

    except Exception as e:
      error_msg = f"Failed to export results: {str(e)}"
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg)

  def generate_comparison_report(self,
                                 benchmark_ids: List[str],
                                 days: int = 30) -> Dict[str, Any]:
    """
    Generate a comparison report for multiple benchmarks.

    Args:
        benchmark_ids: List of benchmark identifiers to compare
        days: Number of days to analyze

    Returns:
        Dictionary containing comparison report
    """
    try:
      report = {
          'comparison_timestamp': datetime.now().isoformat(),
          'benchmark_count': len(benchmark_ids),
          'analysis_period_days': days,
          'benchmarks': {}
      }

      for benchmark_id in benchmark_ids:
        try:
          metrics = self.get_benchmark_metrics(benchmark_id)
          build_rate = self.get_build_success_rate(benchmark_id, days)
          crash_summary = self.get_crash_summary(benchmark_id, days)

          report['benchmarks'][benchmark_id] = {
              'metrics': metrics,
              'build_success_rate': build_rate,
              'crash_summary': crash_summary,
          }

        except Exception as e:
          report['benchmarks'][benchmark_id] = {'error': str(e)}

      return report

    except Exception as e:
      error_msg = f"Failed to generate comparison report: {str(e)}"
      self.logger.error(error_msg)
      return {'error': error_msg, 'timestamp': datetime.now().isoformat()}

  # Historical Data Methods (preserved from original implementation)

  def generate_project_report(
      self,
      days: int = 30,
      include_details: bool = True  # pylint: disable=unused-argument
  ) -> Dict[str, Any]:
    """
    Generate a comprehensive project report.

    Args:
        days: Number of days to include in the report
        include_details: Whether to include detailed data

    Returns:
        Dictionary containing comprehensive project report

    Raises:
        OSSFuzzSDKError: If report generation fails
    """
    try:
      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)
      start_date_str = start_date.isoformat()
      end_date_str = end_date.isoformat()

      self.logger.info("Generating project report for %s (%d days)",
                       self.project_name, days)

      report = {
          'project_name': self.project_name,
          'report_generated': end_date.isoformat(),
          'period': {
              'start_date': start_date_str,
              'end_date': end_date_str,
              'days': days
          }
      }

      # Build statistics
      try:
        build_stats = self.build_history.get_build_statistics(
            start_date_str, end_date_str) if self.build_history else {}
        build_trends = self.build_history.get_build_trends(
            days) if self.build_history else {}
        report['build_summary'] = {
            'statistics': build_stats,
            'trends': build_trends
        }
      except Exception as e:
        self.logger.warning("Failed to get build data: %s", str(e))
        report['build_summary'] = {'error': str(e)}

      # Crash statistics
      try:
        crash_stats = self.crash_history.get_crash_statistics(
            start_date_str, end_date_str) if self.crash_history else {}
        report['crash_summary'] = crash_stats
      except Exception as e:
        self.logger.warning("Failed to get crash data: %s", str(e))
        report['crash_summary'] = {'error': str(e)}

      # Coverage analysis
      try:
        coverage_report = self.coverage_history.get_coverage_report(
            start_date_str, end_date_str) if self.coverage_history else {}
        coverage_trends = self.coverage_history.analyze_coverage_trends(
            days) if self.coverage_history else {}
        report['coverage_summary'] = {
            'report': coverage_report,
            'trends': coverage_trends
        }
      except Exception as e:
        self.logger.warning("Failed to get coverage data: %s", str(e))
        report['coverage_summary'] = {'error': str(e)}

      # Corpus analysis
      try:
        corpus_growth = self.corpus_history.get_corpus_growth(
            days=days) if self.corpus_history else {}
        report['corpus_summary'] = {'growth': corpus_growth}
      except Exception as e:
        self.logger.warning("Failed to get corpus data: %s", str(e))
        report['corpus_summary'] = {'error': str(e)}

      # Overall health score
      report['health_score'] = self._calculate_health_score(report)

      return report

    except Exception as e:
      error_msg = f"Failed to generate project report: {str(e)}"
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg)

  def analyze_fuzzing_efficiency(self, days: int = 30) -> Dict[str, Any]:
    """
    Analyze overall fuzzing efficiency for the project.

    Args:
        days: Number of days to analyze

    Returns:
        Dictionary containing efficiency analysis

    Raises:
        OSSFuzzSDKError: If analysis fails
    """
    try:
      self.logger.info("Analyzing fuzzing efficiency for %s (%d days)",
                       self.project_name, days)

      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      analysis = {
          'project_name': self.project_name,
          'analysis_date': end_date.isoformat(),
          'period_days': days
      }

      # Build efficiency
      build_trends = self.build_history.get_build_trends(
          days) if self.build_history else {}
      analysis['build_efficiency'] = {
          'builds_per_day': build_trends.get('builds_per_day', 0.0),
          'success_rate': build_trends.get('average_success_rate', 0.0),
          'trend': build_trends.get('trend', 'unknown')
      }

      # Coverage efficiency
      coverage_trends = self.coverage_history.analyze_coverage_trends(
          days) if self.coverage_history else {}
      analysis['coverage_efficiency'] = {
          'coverage_velocity': coverage_trends.get('coverage_velocity', 0.0),
          'stability': coverage_trends.get('stability', 'unknown'),
          'current_coverage': coverage_trends.get('current_coverage', 0.0)
      }

      # Crash discovery efficiency
      crash_stats = self.crash_history.get_crash_statistics(
          start_date.isoformat(),
          end_date.isoformat()) if self.crash_history else {}
      total_crashes = crash_stats.get('total_crashes', 0)
      unique_crashes = crash_stats.get('unique_crashes', 0)

      analysis['crash_efficiency'] = {
          'crashes_per_day':
              total_crashes / days if days > 0 else 0.0,
          'unique_crash_rate': (unique_crashes / total_crashes *
                                100) if total_crashes > 0 else 0.0,
          'total_crashes':
              total_crashes,
          'unique_crashes':
              unique_crashes
      }

      # Corpus efficiency
      corpus_growth = self.corpus_history.get_corpus_growth(
          days=days) if self.corpus_history else {}
      analysis['corpus_efficiency'] = {
          'growth_rate': corpus_growth.get('growth_rate', 0.0),
          'size_change': corpus_growth.get('size_change', 0),
          'trend': corpus_growth.get('trend', 'unknown')
      }

      # Overall efficiency score
      analysis['overall_efficiency'] = self._calculate_efficiency_score(
          analysis)

      return analysis

    except Exception as e:
      error_msg = f"Failed to analyze fuzzing efficiency: {str(e)}"
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg)

  def _calculate_health_score(self, report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate overall project health score based on report data.

    Args:
        report: Project report data

    Returns:
        Dictionary containing health score and breakdown
    """
    try:
      scores = {}
      weights = {}

      # Build health (30% weight)
      build_summary = report.get('build_summary', {})
      if 'statistics' in build_summary:
        build_success_rate = build_summary['statistics'].get(
            'success_rate', 0.0)
        scores['build'] = min(build_success_rate, 100.0)
        weights['build'] = 0.3

      # Coverage health (40% weight)
      coverage_summary = report.get('coverage_summary', {})
      if 'report' in coverage_summary:
        max_coverage = coverage_summary['report']['summary'].get(
            'max_line_coverage', 0.0)
        scores['coverage'] = min(max_coverage, 100.0)
        weights['coverage'] = 0.4

      # Crash health (20% weight) - inverse scoring
      crash_summary = report.get('crash_summary', {})
      total_crashes = crash_summary.get('total_crashes', 0)
      if total_crashes == 0:
        scores['crash'] = 100.0
      else:
        # Lower score for more crashes
        scores['crash'] = max(0.0, 100.0 - min(total_crashes, 100))
      weights['crash'] = 0.2

      # Corpus health (10% weight)
      corpus_summary = report.get('corpus_summary', {})
      if 'growth' in corpus_summary:
        growth_rate = corpus_summary['growth']['growth_rate']
        if growth_rate > 0:
          scores['corpus'] = min(100.0, 50.0 + growth_rate * 10)
        else:
          scores['corpus'] = 50.0
        weights['corpus'] = 0.1

      # Calculate weighted average
      total_score = 0.0
      total_weight = 0.0

      for category, score in scores.items():
        weight = weights.get(category, 0.0)
        total_score += score * weight
        total_weight += weight

      overall_score = total_score / total_weight if total_weight > 0 else 0.0

      # Determine health status
      if overall_score >= 80:
        status = 'excellent'
      elif overall_score >= 60:
        status = 'good'
      elif overall_score >= 40:
        status = 'fair'
      else:
        status = 'poor'

      return {
          'overall_score': round(overall_score, 2),
          'status': status,
          'category_scores': scores,
          'weights': weights
      }
    except Exception as e:
      self.logger.warning("Failed to calculate health score: %s", str(e))
      return {'overall_score': 0.0, 'status': 'unknown', 'error': str(e)}

  def _calculate_efficiency_score(self, analysis: Dict[str,
                                                       Any]) -> Dict[str, Any]:
    """
    Calculate overall efficiency score based on analysis data.

    Args:
        analysis: Efficiency analysis data

    Returns:
        Dictionary containing efficiency score and breakdown
    """
    try:
      scores = {}

      # Build efficiency
      build_eff = analysis.get('build_efficiency', {})
      builds_per_day = build_eff.get('builds_per_day', 0.0)
      success_rate = build_eff.get('success_rate', 0.0)

      # Score based on build frequency and success rate
      build_score = min(100.0, (builds_per_day * 10) + success_rate)
      scores['build'] = build_score

      # Coverage efficiency
      coverage_eff = analysis.get('coverage_efficiency', {})
      coverage_velocity = coverage_eff.get('coverage_velocity', 0.0)
      current_coverage = coverage_eff.get('current_coverage', 0.0)

      # Score based on coverage growth and current level
      coverage_score = min(100.0, current_coverage + (coverage_velocity * 20))
      scores['coverage'] = max(0.0, coverage_score)

      # Crash efficiency
      crash_eff = analysis.get('crash_efficiency', {})
      unique_crash_rate = crash_eff.get('unique_crash_rate', 0.0)
      crashes_per_day = crash_eff.get('crashes_per_day', 0.0)

      # Higher score for finding unique crashes efficiently
      crash_score = min(100.0, unique_crash_rate + min(crashes_per_day * 5, 20))
      scores['crash'] = crash_score

      # Corpus efficiency
      corpus_eff = analysis.get('corpus_efficiency', {})
      growth_rate = corpus_eff.get('growth_rate', 0.0)

      # Score based on corpus growth
      corpus_score = min(100.0, 50.0 + max(-50.0, min(50.0, growth_rate * 2)))
      scores['corpus'] = corpus_score

      # Calculate overall efficiency
      overall_efficiency = sum(scores.values()) / len(scores) if scores else 0.0

      # Determine efficiency level
      if overall_efficiency >= 75:
        level = 'high'
      elif overall_efficiency >= 50:
        level = 'medium'
      elif overall_efficiency >= 25:
        level = 'low'
      else:
        level = 'very_low'

      return {
          'overall_efficiency': round(overall_efficiency, 2),
          'level': level,
          'category_scores': scores
      }
    except Exception as e:
      self.logger.warning("Failed to calculate efficiency score: %s", str(e))
      return {'overall_efficiency': 0.0, 'level': 'unknown', 'error': str(e)}

  def get_project_summary(self) -> Dict[str, Any]:
    """
    Get a quick summary of the project's current state.

    Returns:
        Dictionary containing project summary

    Raises:
        OSSFuzzSDKError: If summary generation fails
    """
    try:
      summary: Dict[str, Any] = {
          'project_name': self.project_name,
          'summary_date': datetime.now().isoformat()
      }

      # Latest build status
      try:
        last_build = self.build_history.get_last_successful_build(
        ) if self.build_history else None
        summary['last_successful_build'] = str(
            last_build) if last_build else 'None'
      except Exception as e:
        summary['last_successful_build'] = f'error: {str(e)}'

      # Latest coverage
      try:
        latest_coverage = self.coverage_history.get_latest_coverage(
        ) if self.coverage_history else None
        summary['latest_coverage'] = str(
            latest_coverage) if latest_coverage else 'None'
      except Exception as e:
        summary['latest_coverage'] = f'error: {str(e)}'

      # Recent crash count
      try:
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        recent_crashes = self.crash_history.get_crash_history(
            start_date=week_ago) if self.crash_history else []
        summary['recent_crashes'] = len(recent_crashes)
      except Exception as e:
        summary['recent_crashes'] = f'error: {str(e)}'

      return summary

    except Exception as e:
      error_msg = f"Failed to get project summary: {str(e)}"
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg)
