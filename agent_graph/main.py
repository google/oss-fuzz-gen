#!/usr/bin/env python3
"""
LangGraph模式的正式入口点。

这是运行LangGraph fuzzing workflow的主要命令行接口，
与run_logicfuzz.py并行存在，提供基于LangGraph的实验执行。
"""

import argparse
import logging
import os
import sys
import traceback
from typing import Optional

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_graph import FuzzingWorkflow
from agent_graph.benchmark_loader import load_benchmark_from_args, prepare_experiment_environment
from agent_graph.common_args import add_langgraph_only_arguments, add_langgraph_specific_arguments
from llm_toolkit.models import LLM

logger = logging.getLogger(__name__)

def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def create_llm_instance(args: argparse.Namespace) -> LLM:
    """Create and configure LLM instance."""
    try:
        llm = LLM.setup(
            ai_binary=args.ai_binary or "",
            name=args.model,
            max_tokens=getattr(args, 'max_tokens', 2000),
            num_samples=getattr(args, 'num_samples', 1),
            temperature=getattr(args, 'temperature', 0.4)
        )
        llm.cloud_setup()
        return llm
    except Exception as e:
        logger.error(f"Failed to setup LLM '{args.model}': {e}")
        raise

def run_single_benchmark(args: argparse.Namespace) -> bool:
    """运行单个benchmark的LangGraph workflow."""
    logger.info("=== LangGraph Fuzzing Workflow ===")
    logger.info(f"Benchmark: {args.benchmark_yaml}")
    logger.info(f"Function: {args.function_name or 'auto-select from YAML'}")
    logger.info(f"Model: {args.model}")
    
    try:
        # Prepare experiment environment
        benchmark, work_dirs = prepare_experiment_environment(args)
        logger.info(f"✅ Loaded benchmark: {benchmark.project} ({benchmark.function_name})")
        
        # Create LLM instance
        llm = create_llm_instance(args)
        logger.info(f"✅ LLM setup complete: {args.model}")
        
        # Update args with work_dirs
        args.work_dirs = work_dirs
        
        # Create and run workflow
        workflow = FuzzingWorkflow(llm, args)
        logger.info(f"✅ Workflow created")
        
        # Determine workflow type
        workflow_type = getattr(args, 'workflow_type', 'full')
        logger.info(f"🚀 Starting {workflow_type} workflow...")
        
        # Run the workflow
        final_state = workflow.run(
            benchmark=benchmark,
            trial=getattr(args, 'trial', 0),
            workflow_type=workflow_type
        )
        
        # Report results
        logger.info("🎉 Workflow completed successfully!")
        logger.info(f"📊 Final state keys: {list(final_state.keys())}")
        
        # Check for errors or warnings
        if 'errors' in final_state and final_state['errors']:
            logger.warning(f"⚠️  Workflow completed with {len(final_state['errors'])} errors")
            
        if 'warnings' in final_state and final_state['warnings']:
            logger.info(f"💡 Workflow generated {len(final_state['warnings'])} warnings")
            
        logger.info(f"📂 Work directory: {work_dirs.base}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Workflow failed: {e}")
        if args.verbose:
            traceback.print_exc()
        return False

def create_argument_parser() -> argparse.ArgumentParser:
    """Create argument parser for LangGraph main entry point."""
    parser = argparse.ArgumentParser(
        description="LangGraph-based fuzzing workflow execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process first function in YAML automatically
  python agent_graph/main.py -y benchmark-sets/0-conti/cjson.yaml \\
    --model vertex_ai_gemini-2-5-pro-chat
  
  # Process specific function
  python agent_graph/main.py -y benchmark-sets/0-conti/cjson.yaml \\
    -f cJSON_Parse --model vertex_ai_gemini-2-5-pro-chat
    
  # Run with custom iterations and context
  python agent_graph/main.py -y benchmark-sets/0-conti/cjson.yaml \\
    --model vertex_ai_gemini-2-5-pro-chat --context \\
    --max-iterations 5 --run-timeout 600
        """
    )
    
    # Add LangGraph-specific arguments only (no pipeline requirement)
    add_langgraph_only_arguments(parser)
    
    # Add LangGraph-specific arguments
    add_langgraph_specific_arguments(parser)
    
    # LangGraph main-specific arguments
    parser.add_argument('--workflow-type',
                        choices=['full', 'simple', 'test'],
                        default='full',
                        help='Type of workflow to run (default: full)')
    
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
    
    # Validate required arguments
    if not args.benchmark_yaml:
        logger.error("Benchmark YAML file is required (-y/--benchmark-yaml)")
        return 1
        
    # Function name is optional - if not provided, process all functions in YAML
    if args.function_name:
        logger.info(f"Processing specific function: {args.function_name}")
    else:
        logger.info("No specific function specified - will process all functions in YAML")
        
    if not args.model:
        logger.error("Model name is required (--model)")
        return 1
    
    # Run the workflow
    success = run_single_benchmark(args)
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
