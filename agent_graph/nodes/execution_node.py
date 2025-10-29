"""
Execution node for LangGraph workflow.

This module provides the LangGraph-compatible node wrapper for the original
ExecutionStage functionality.
"""
import os
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.adapters import StateAdapter
from agent_graph.state import FuzzingWorkflowState
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as evaluator_lib
from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from experiment.evaluator import Evaluator
from experiment.workdir import WorkDirs

def execution_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
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
        
        # Deserialize benchmark and work_dirs from dicts
        from experiment.benchmark import Benchmark
        from experiment.workdir import WorkDirs
        benchmark = Benchmark.from_dict(state["benchmark"])
        trial = state["trial"]
        work_dirs = WorkDirs.from_dict(state["work_dirs"])
        
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
        
        # Build and run the target
        build_result, run_result = builder_runner.build_and_run(
            generated_oss_fuzz_project,
            fuzz_target_path,
            0,  # iteration
            benchmark.language,
            cloud_build_tags=[
                str(trial),
                'Execution',
                'ofg',
                benchmark.project,
            ] if args.cloud_experiment_name else None,
            trial=trial
        )
        
        if not run_result:
            raise Exception('No RunResult received from build_and_run')
        
        # Process coverage information
        coverage_percent = 0.0
        coverage_diff = 0.0
        
        if run_result.total_pcs:
            coverage_percent = run_result.cov_pcs / run_result.total_pcs
            logger.info(f'Coverage: {coverage_percent:.2%} ({run_result.cov_pcs}/{run_result.total_pcs})', 
                       trial=trial)
        
        if run_result.coverage_summary:
            generated_target_name = os.path.basename(benchmark.target_path)
            from experiment import evaluator as evaluator_lib
            total_lines = evaluator_lib.compute_total_lines_without_fuzz_targets(
                run_result.coverage_summary, generated_target_name)
            
            # Load existing textcov and compute diff
            existing_textcov = evaluator.load_existing_textcov()
            run_result.coverage.subtract_covered_lines(existing_textcov)
            
            if total_lines:
                coverage_diff = run_result.coverage.covered_lines / total_lines
                logger.info(f'Coverage diff: {coverage_diff:.2%}', trial=trial)
        
        # Extract crash information if any
        crash_info = {}
        if run_result.crashes:
            crash_info = {
                "error_message": run_result.crash_info if hasattr(run_result, 'crash_info') else "",
                "stack_trace": run_result.crash_info if hasattr(run_result, 'crash_info') else "",
                "artifact_path": run_result.artifact_path if hasattr(run_result, 'artifact_path') else "",
                "artifact_name": run_result.artifact_name if hasattr(run_result, 'artifact_name') else "",
                "crash_func": run_result.semantic_check.crash_func if (hasattr(run_result, 'semantic_check') and run_result.semantic_check) else "",
                "sanitizer": run_result.sanitizer if hasattr(run_result, 'sanitizer') else "",
            }
        
        # Track consecutive iterations without coverage improvement
        IMPROVEMENT_THRESHOLD = 0.01  # At least 1% improvement
        prev_no_improvement_count = state.get("no_coverage_improvement_count", 0)
        
        if coverage_diff > IMPROVEMENT_THRESHOLD:
            # Coverage improved, reset the counter
            no_improvement_count = 0
            logger.debug(f'Coverage improved by {coverage_diff:.2%}, resetting no_improvement_count', 
                        trial=trial)
        else:
            # No significant improvement, increment counter
            no_improvement_count = prev_no_improvement_count + 1
            logger.debug(f'Coverage did not improve (diff={coverage_diff:.2%}), '
                        f'no_improvement_count={no_improvement_count}', 
                        trial=trial)
        
        # Create state update
        state_update = {
            "run_success": run_result.succeeded if hasattr(run_result, 'succeeded') else True,
            "run_error": run_result.crash_info if hasattr(run_result, 'crash_info') else "",
            "crashes": run_result.crashes if hasattr(run_result, 'crashes') else False,
            "crash_info": crash_info,
            "crash_func": run_result.semantic_check.crash_func if (hasattr(run_result, 'semantic_check') and run_result.semantic_check) else "",
            "coverage_summary": run_result.coverage_summary,
            "coverage_percent": coverage_percent,
            "line_coverage_diff": coverage_diff,
            "no_coverage_improvement_count": no_improvement_count,  # Track consecutive iterations without improvement
            "reproducer_path": run_result.reproducer_path if hasattr(run_result, 'reproducer_path') else "",
            "artifact_path": run_result.artifact_path if hasattr(run_result, 'artifact_path') else "",
            "coverage_report_path": run_result.coverage_report_path if hasattr(run_result, 'coverage_report_path') else "",
            "cov_pcs": run_result.cov_pcs if hasattr(run_result, 'cov_pcs') else 0,
            "total_pcs": run_result.total_pcs if hasattr(run_result, 'total_pcs') else 0,
            # Clear old analysis results to force re-analysis of new crashes/coverage
            # This ensures each execution's results are analyzed fresh
            "crash_analysis": None,
            "context_analysis": None,
            "coverage_analysis": None,
            "messages": [{
                "role": "assistant",
                "content": f"Execution {'successful' if run_result.succeeded else 'failed'}"
            }]
        }
        
        logger.info(f'Execution completed: success={state_update["run_success"]}, '
                   f'crashes={state_update["crashes"]}, coverage={coverage_percent:.2%}',
                   trial=trial)
        
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

def build_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
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
        
        # Deserialize benchmark and work_dirs from dicts
        from experiment.benchmark import Benchmark
        from experiment.workdir import WorkDirs
        benchmark = Benchmark.from_dict(state["benchmark"])
        trial = state["trial"]
        work_dirs = WorkDirs.from_dict(state["work_dirs"])
        
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
        
        # Log build result details
        logger.info(f"Build result: success={build_result.get('success')}, "
                   f"binary_exists={build_result.get('binary_exists')}, "
                   f"errors={len(build_result.get('errors', []))}",
                   trial=trial)
        
        # Create state update based on build result
        compile_success = build_result.get("success", False)
        state_update = {
            "compile_success": compile_success,
            "build_errors": build_result.get("errors", []),
            "compile_log": build_result.get("log", ""),
            "binary_exists": build_result.get("binary_exists", False),
            "is_function_referenced": True,  # Assume function is referenced; real check happens during execution
            "messages": [{
                "role": "assistant",
                "content": f"Build {'successful' if compile_success else 'failed'}"
            }]
        }
        
        # If compilation successful and we're in compilation phase, switch to optimization phase
        if compile_success and state.get("workflow_phase") == "compilation":
            logger.info('Compilation successful, switching workflow_phase to optimization', trial=trial)
            state_update["workflow_phase"] = "optimization"
            state_update["compilation_retry_count"] = 0  # Reset for potential future use
        
        logger.info('Build node completed', trial=trial)
        
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
