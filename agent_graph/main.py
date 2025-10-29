#!/usr/bin/env python3
"""
LangGraph-based fuzzing workflow main entry point.

Architecture:
  agent_graph/main.py  →  run_logicfuzz.py  →  run_single_fuzz.py
                                             ↓
                                       LangGraph workflow
                                             ↓
                                       Standard result saving

This ensures a single source of truth for workflow execution, consistent result format, and no code duplication for result saving logic.
"""

import argparse
import logging
import os
import sys
import subprocess
from typing import List

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_graph.common_args import add_langgraph_only_arguments, add_langgraph_specific_arguments

logger = logging.getLogger(__name__)

def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def build_run_logicfuzz_command(args: argparse.Namespace) -> List[str]:
    """
    Convert agent_graph/main.py arguments to run_logicfuzz.py arguments.
    
    This function maps the LangGraph CLI to the standard run_logicfuzz.py interface,
    ensuring all experiments flow through the same execution path.
    """
    # Get path to run_logicfuzz.py (one directory up from agent_graph)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    run_logicfuzz_path = os.path.join(project_root, 'run_logicfuzz.py')
    
    cmd = [sys.executable, run_logicfuzz_path]
    
    # Agent mode is now the default, no need to specify --agent flag
    
    # Required arguments - either single YAML or directory
    if args.benchmark_yaml:
        cmd.extend(['-y', args.benchmark_yaml])
    elif hasattr(args, 'benchmarks_directory') and args.benchmarks_directory:
        cmd.extend(['-b', args.benchmarks_directory])
    
    if args.function_name:
        cmd.extend(['-f', args.function_name])
    
    if args.model:
        cmd.extend(['--model', args.model])
    
    # LLM configuration
    if hasattr(args, 'max_tokens') and args.max_tokens:
        cmd.extend(['--max-tokens', str(args.max_tokens)])
    
    if hasattr(args, 'num_samples') and args.num_samples:
        cmd.extend(['--num-samples', str(args.num_samples)])
    
    if hasattr(args, 'temperature') and args.temperature is not None:
        cmd.extend(['--temperature', str(args.temperature)])
    
    # Execution configuration
    if hasattr(args, 'run_timeout') and args.run_timeout:
        cmd.extend(['--run-timeout', str(args.run_timeout)])
    
    # Max round configuration
    if hasattr(args, 'max_round') and args.max_round:
        cmd.extend(['--max-round', str(args.max_round)])
    
    # Context and examples
    if hasattr(args, 'use_context') and args.use_context:
        cmd.append('--context')
    
    if hasattr(args, 'example_pair') and args.example_pair:
        cmd.extend(['--example-pair', str(args.example_pair)])
    
    if hasattr(args, 'use_project_examples') and args.use_project_examples:
        cmd.append('--use-project-examples')
    
    # Trial configuration
    if hasattr(args, 'trial') and args.trial:
        cmd.extend(['--trial', str(args.trial)])
    
    # Other options
    if hasattr(args, 'cloud_experiment_name') and args.cloud_experiment_name:
        cmd.extend(['--cloud-experiment-name', args.cloud_experiment_name])
    
    if hasattr(args, 'cloud_experiment_bucket') and args.cloud_experiment_bucket:
        cmd.extend(['--cloud-experiment-bucket', args.cloud_experiment_bucket])
    
    # Introspector endpoint configuration
    if hasattr(args, 'introspector_endpoint') and args.introspector_endpoint:
        cmd.extend(['-e', args.introspector_endpoint])
    
    # Infrastructure configuration
    if hasattr(args, 'oss_fuzz_dir') and args.oss_fuzz_dir:
        cmd.extend(['-of', args.oss_fuzz_dir])
    
    if hasattr(args, 'work_dir') and args.work_dir:
        cmd.extend(['-w', args.work_dir])
    
    # Note: -td (template_directory) is not passed because LangGraph
    # uses hardcoded paths in prompt_loader.py
    
    if hasattr(args, 'log_level') and args.log_level:
        cmd.extend(['-lo', args.log_level])
    
    # Prompt and context configuration
    if hasattr(args, 'prompt_file') and args.prompt_file:
        cmd.extend(['-pf', args.prompt_file])
    
    if hasattr(args, 'no_prompt_file') and args.no_prompt_file:
        cmd.append('-npf')
    
    if hasattr(args, 'additional_files_path') and args.additional_files_path:
        cmd.extend(['-afp', args.additional_files_path])
    
    # Benchmark generation parameters
    if hasattr(args, 'generate_benchmarks') and args.generate_benchmarks:
        cmd.extend(['-g', args.generate_benchmarks])
    
    if hasattr(args, 'generate_benchmarks_projects') and args.generate_benchmarks_projects:
        cmd.extend(['-gp', args.generate_benchmarks_projects])
    
    if hasattr(args, 'generate_benchmarks_max') and args.generate_benchmarks_max:
        cmd.extend(['-gm', str(args.generate_benchmarks_max)])
    
    # Execution control
    if hasattr(args, 'delay') and args.delay:
        cmd.extend(['--delay', str(args.delay)])
    
    if hasattr(args, 'prompt_builder') and args.prompt_builder:
        cmd.extend(['-p', args.prompt_builder])
    
    if hasattr(args, 'custom_pipeline') and args.custom_pipeline:
        cmd.extend(['--custom-pipeline', args.custom_pipeline])
    
    # Model configuration
    if hasattr(args, 'ai_binary') and args.ai_binary:
        cmd.extend(['-a', args.ai_binary])
    
    return cmd

def run_via_wrapper(args: argparse.Namespace) -> bool:
    """
    Execute the LangGraph workflow by calling run_logicfuzz.py.
    
    This delegates all execution to the standard pipeline, ensuring:
    - Consistent result format
    - Single source of truth for workflow logic
    - No code duplication
    """
    logger.info("=== LangGraph Fuzzing Workflow (via run_logicfuzz.py) ===")
    if args.benchmark_yaml:
        logger.info(f"Benchmark: {args.benchmark_yaml}")
    elif args.benchmarks_directory:
        logger.info(f"Benchmarks directory: {args.benchmarks_directory}")
    logger.info(f"Function: {args.function_name or 'auto-select from YAML'}")
    logger.info(f"Model: {args.model}")
    
    # Build command
    cmd = build_run_logicfuzz_command(args)
    
    # Log the command being executed
    logger.info(f"Executing: {' '.join(cmd)}")
    logger.info("=" * 60)
    
    try:
        # Execute run_logicfuzz.py (agent mode is now the default)
        # Use subprocess.run to get real-time output
        result = subprocess.run(
            cmd,
            check=False,  # Don't raise exception on non-zero exit
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        
        logger.info("=" * 60)
        if result.returncode == 0:
            logger.info("✅ Workflow completed successfully!")
            return True
        else:
            logger.error(f"❌ Workflow failed with exit code {result.returncode}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to execute workflow: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return False

def create_argument_parser() -> argparse.ArgumentParser:
    """Create argument parser for LangGraph main entry point."""
    parser = argparse.ArgumentParser(
        description="LangGraph-based fuzzing workflow (wrapper for run_logicfuzz.py)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process first function in YAML automatically
  python agent_graph/main.py -y conti-benchmark/cjson.yaml \\
    --model gpt-5
  
  # Process specific function
  python agent_graph/main.py -y conti-benchmark/cjson.yaml \\
    -f cJSON_Parse --model gpt-5
    
  # Run with custom iterations and context
  python agent_graph/main.py -y conti-benchmark/cjson.yaml \\
    --model gpt-5 --context \\
    --max-round 5 --run-timeout 600

Note: This script is a convenience wrapper around:
  python run_logicfuzz.py -y <benchmark> --model <model> ...

All entry points produce identical results using the standard pipeline.
        """
    )
    
    # Add LangGraph-specific arguments only (no pipeline requirement)
    add_langgraph_only_arguments(parser)
    
    # Add LangGraph-specific arguments
    add_langgraph_specific_arguments(parser)
    
    # LangGraph main-specific arguments
    parser.add_argument('--trial',
                        type=int,
                        default=0,
                        help='Trial number for this run (default: 0)')
                        
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Enable verbose logging')
    
    return parser

def main() -> int:
    """Main entry point for LangGraph fuzzing workflow."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Validate required arguments - need either YAML file or directory
    if not args.benchmark_yaml and not args.benchmarks_directory:
        logger.error("Either benchmark YAML file (-y/--benchmark-yaml) or "
                    "benchmarks directory (-b/--benchmarks-directory) is required")
        return 1
    
    if args.benchmark_yaml and args.benchmarks_directory:
        logger.error("Cannot specify both -y/--benchmark-yaml and "
                    "-b/--benchmarks-directory at the same time")
        return 1
        
    # Function name is optional - if not provided, process all functions in YAML
    if args.function_name:
        logger.info(f"Processing specific function: {args.function_name}")
    else:
        if args.benchmark_yaml:
            logger.info("No specific function specified - will process first function in YAML")
        else:
            logger.info("No specific function specified - will process all benchmarks in directory")
        
    if not args.model:
        logger.error("Model name is required (--model)")
        return 1
    
    # Run the workflow via wrapper
    success = run_via_wrapper(args)
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
