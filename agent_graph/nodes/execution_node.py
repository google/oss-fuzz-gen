"""
Execution node for LangGraph workflow.

This module provides the LangGraph-compatible node wrapper for the original
ExecutionStage functionality.
"""
import os
from typing import Dict, Any

import logger
from agent_graph.adapters import StateAdapter
from agent_graph.state import FuzzingWorkflowState
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as evaluator_lib
from experiment import oss_fuzz_checkout
from ..benchmark import LangGraphBenchmark as Benchmark
from experiment.evaluator import Evaluator
from ..workdir import LangGraphWorkDirs

def execution_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node that wraps the original ExecutionStage functionality.
    
    This node executes fuzz targets by:
    1. Converting LangGraph state to Result objects
    2. Running the fuzz target using OSS-Fuzz infrastructure
    3. Converting the RunResult back to state updates
    
    Args:
        state: Current LangGraph workflow state
        config: Configuration containing args, etc.
        
    Returns:
        Dictionary of state updates
    """
    try:
        # Extract configuration from LangGraph's configurable system
        configurable = config.get("configurable", {})
        args = configurable["args"]
        benchmark = Benchmark.from_dict(state["benchmark"])
        trial = state["trial"]
        work_dirs = LangGraphWorkDirs.from_dict(state["work_dirs"])
        
        logger.info('Starting Execution node', trial=trial)
        
        # Check if we have a fuzz target to execute
        fuzz_target_source = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        
        if not fuzz_target_source:
            raise ValueError("No fuzz target source available for execution")
        
        # Set up builder runner
        if args.cloud_experiment_name:
            builder_runner = builder_runner_lib.CloudBuilderRunner(
                benchmark=benchmark,
                work_dirs=work_dirs,
                run_timeout=args.run_timeout,
                experiment_name=args.cloud_experiment_name,
                experiment_bucket=args.cloud_experiment_bucket,
            )
        else:
            builder_runner = builder_runner_lib.BuilderRunner(
                benchmark=benchmark,
                work_dirs=work_dirs,
                run_timeout=args.run_timeout,
            )
        
        # Set up evaluator
        evaluator = Evaluator(builder_runner, benchmark, work_dirs)
        generated_target_name = os.path.basename(benchmark.target_path)
        generated_oss_fuzz_project = f'{benchmark.id}-{trial}'
        generated_oss_fuzz_project = oss_fuzz_checkout.rectify_docker_tag(
            generated_oss_fuzz_project)
        
        # Write fuzz target and build script to files
        fuzz_target_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.fuzz_target')
        build_script_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.build_script')
        
        with open(fuzz_target_path, 'w') as f:
            f.write(fuzz_target_source)
        
        if build_script_source:
            with open(build_script_path, 'w') as f:
                f.write(build_script_source)
        
        # Create OSS-Fuzz project
        generated_project_path = evaluator.create_ossfuzz_project(
            benchmark, generated_oss_fuzz_project, fuzz_target_path,
            build_script_path if build_script_source else None)
        
        # Create status directory
        status_path = os.path.join(work_dirs.status, f'{trial:02d}')
        os.makedirs(status_path, exist_ok=True)
        
        # Execute the fuzz target
        logger.info('Executing fuzz target', trial=trial)
        
        # Convert state to result history for evaluator
        result_history = StateAdapter.state_to_result_history(state)
        
        # Run the evaluation
        run_result = evaluator.evaluate(
            result_history=result_history,
            cycle_count=1,  # Single cycle for now
            status_path=status_path
        )
        
        # Convert RunResult back to state updates
        state_update = StateAdapter.result_to_state_update(run_result)
        
        logger.info('Execution node completed successfully', trial=trial)
        
        return state_update
        
    except Exception as e:
        # Handle errors gracefully
        logger.error(f'Error in Execution node: {str(e)}', 
                    trial=state.get("trial", 0))
        return {
            "errors": [{
                "node": "Execution",
                "message": str(e),
                "type": type(e).__name__
            }],
            "messages": [{
                "role": "assistant",
                "content": f"Execution failed: {str(e)}"
            }]
        }

def build_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node for building fuzz targets without execution.
    
    This node only builds the fuzz target to check compilation success.
    
    Args:
        state: Current LangGraph workflow state
        config: Configuration containing args, etc.
        
    Returns:
        Dictionary of state updates
    """
    try:
        # Extract configuration from LangGraph's configurable system
        configurable = config.get("configurable", {})
        args = configurable["args"]
        benchmark = Benchmark.from_dict(state["benchmark"])
        trial = state["trial"]
        work_dirs = LangGraphWorkDirs.from_dict(state["work_dirs"])
        
        logger.info('Starting Build node', trial=trial)
        
        # Check if we have a fuzz target to build
        fuzz_target_source = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        
        if not fuzz_target_source:
            raise ValueError("No fuzz target source available for building")
        
        # Set up builder runner for build-only
        builder_runner = builder_runner_lib.BuilderRunner(
            benchmark=benchmark,
            work_dirs=work_dirs,
            run_timeout=args.run_timeout,
        )
        
        # Set up evaluator
        evaluator = Evaluator(builder_runner, benchmark, work_dirs)
        generated_oss_fuzz_project = f'{benchmark.id}-{trial}-build'
        generated_oss_fuzz_project = oss_fuzz_checkout.rectify_docker_tag(
            generated_oss_fuzz_project)
        
        # Write fuzz target and build script to files
        fuzz_target_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.fuzz_target')
        build_script_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.build_script')
        
        with open(fuzz_target_path, 'w') as f:
            f.write(fuzz_target_source)
        
        if build_script_source:
            with open(build_script_path, 'w') as f:
                f.write(build_script_source)
        
        # Create OSS-Fuzz project
        generated_project_path = evaluator.create_ossfuzz_project(
            benchmark, generated_oss_fuzz_project, fuzz_target_path,
            build_script_path if build_script_source else None)
        
        # Only build, don't run
        logger.info('Building fuzz target', trial=trial)
        
        build_result = evaluator.build_only(generated_project_path)
        
        # Create state update based on build result
        state_update = {
            "compile_success": build_result.get("success", False),
            "build_errors": build_result.get("errors", []),
            "compile_log": build_result.get("log", ""),
            "binary_exists": build_result.get("binary_exists", False),
            "messages": [{
                "role": "assistant",
                "content": f"Build {'successful' if build_result.get('success') else 'failed'}"
            }]
        }
        
        logger.info('Build node completed successfully', trial=trial)
        
        return state_update
        
    except Exception as e:
        # Handle errors gracefully
        logger.error(f'Error in Build node: {str(e)}', 
                    trial=state.get("trial", 0))
        return {
            "errors": [{
                "node": "Build",
                "message": str(e),
                "type": type(e).__name__
            }],
            "messages": [{
                "role": "assistant",
                "content": f"Build failed: {str(e)}"
            }]
        }

__all__ = ['execution_node', 'build_node']
