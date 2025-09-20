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
"""Unified benchmark loading logic for both agent_test.py and LangGraph."""

import argparse
import logging
import os
from typing import List, Optional
from experiment import benchmark as benchmarklib
from .workdir import LangGraphWorkDirs
from .benchmark import LangGraphBenchmark

logger = logging.getLogger(__name__)
import run_one_experiment


def load_benchmark_from_args(args: argparse.Namespace) -> LangGraphBenchmark:
    """Load benchmark from command line arguments.
    
    This replicates the exact logic from agent_test.py lines 243-244.
    """
    # Prepare the environment (equivalent to run_one_experiment.prepare)
    run_one_experiment.prepare(args.oss_fuzz_dir)
    
    # Initialize test benchmark (exact replica of agent_test.py:244)
    benchmarks = benchmarklib.Benchmark.from_yaml(args.benchmark_yaml)
    
    # Handle function selection
    if args.function_name:
        # Find the specific benchmark for the function
        test_benchmark = [
            benchmark for benchmark in benchmarks
            if benchmark.function_name == args.function_name
        ]
        
        if not test_benchmark:
            raise ValueError(f"No benchmark found for function '{args.function_name}' "
                            f"in {args.benchmark_yaml}")
        
        if len(test_benchmark) > 1:
            raise ValueError(f"Multiple benchmarks found for function '{args.function_name}' "
                            f"in {args.benchmark_yaml}")
        
        benchmark = test_benchmark[0]
    else:
        # No specific function specified - use the first function
        if not benchmarks:
            raise ValueError(f"No benchmarks found in {args.benchmark_yaml}")
        
        benchmark = benchmarks[0]
        logger.info(f"No function specified, using first function: {benchmark.function_name}")
    
    # Apply context configuration if specified
    if hasattr(args, 'context') and args.context:
        benchmark.use_context = True
    
    # Convert to LangGraphBenchmark for consistent interface
    langgraph_benchmark = LangGraphBenchmark(
        id=benchmark.id,
        project=benchmark.project,
        function_name=benchmark.function_name,
        signature=benchmark.function_signature,
        filepath=benchmark.target_path,  # Use target_path as filepath
        begin_line=0,  # Default values
        end_line=0,    # Default values
        params=[{'name': p.get('name', ''), 'type': p.get('type', '')} for p in benchmark.params],
        return_type=benchmark.return_type,
        target_path=benchmark.target_path,
        build_script='',  # Default value
        language=benchmark.language,
        additional_info={'use_context': getattr(benchmark, 'use_context', False)}
    )
    
    return langgraph_benchmark


def setup_work_dirs(args: argparse.Namespace) -> LangGraphWorkDirs:
    """Setup work directories based on arguments."""
    work_dirs = LangGraphWorkDirs(args.work_dir)
    
    # Store work_dirs in args for compatibility with existing code
    args.work_dirs = work_dirs
    
    return work_dirs


def prepare_experiment_environment(args: argparse.Namespace) -> tuple[benchmarklib.Benchmark, LangGraphWorkDirs]:
    """Prepare the complete experiment environment.
    
    This function combines benchmark loading and work directory setup,
    providing a single entry point for both agent_test.py and LangGraph modes.
    """
    # Setup work directories
    work_dirs = setup_work_dirs(args)
    
    # Load benchmark
    benchmark = load_benchmark_from_args(args)
    
    return benchmark, work_dirs


def validate_benchmark_args(args: argparse.Namespace) -> None:
    """Validate benchmark-related arguments."""
    if not os.path.exists(args.benchmark_yaml):
        raise FileNotFoundError(f"Benchmark YAML file not found: {args.benchmark_yaml}")
    
    if not args.function_name:
        raise ValueError("Function name is required")
    
    if args.additional_files_path and not os.path.exists(args.additional_files_path):
        raise FileNotFoundError(f"Additional files path not found: {args.additional_files_path}")
