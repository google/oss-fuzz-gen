"""
Supervisor node for LangGraph workflow routing.

This module provides the routing logic for the fuzzing workflow,
determining which agents to execute next based on the current state.
"""
from typing import Dict, Any, List

import logger
from agent_graph.state import FuzzingWorkflowState

def supervisor_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Supervisor node that determines the next action in the workflow.
    
    This node implements the routing logic based on:
    1. Current workflow state
    2. Success/failure of previous steps
    3. Available analysis results
    4. Maximum retry limits
    
    Args:
        state: Current LangGraph workflow state
        config: Configuration containing workflow parameters
        
    Returns:
        Dictionary with next_action and routing decisions
    """
    try:
        trial = state["trial"]
        logger.info('Starting Supervisor node', trial=trial)
        
        # Check for errors that should terminate the workflow
        errors = state.get("errors", [])
        if len(errors) >= config.get("max_errors", 5):
            logger.warning('Too many errors, terminating workflow', trial=trial)
            return {
                "next_action": "END",
                "termination_reason": "too_many_errors",
                "messages": [{
                    "role": "assistant",
                    "content": f"Workflow terminated due to {len(errors)} errors"
                }]
            }
        
        # Check retry count
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", config.get("max_retries", 3))
        
        if retry_count >= max_retries:
            logger.warning('Maximum retries reached, terminating workflow', trial=trial)
            return {
                "next_action": "END",
                "termination_reason": "max_retries_reached",
                "messages": [{
                    "role": "assistant",
                    "content": f"Workflow terminated after {retry_count} retries"
                }]
            }
        
        # Routing logic based on current state
        next_action = _determine_next_action(state)
        
        logger.info(f'Supervisor determined next action: {next_action}', trial=trial)
        
        return {
            "next_action": next_action,
            "messages": [{
                "role": "assistant",
                "content": f"Supervisor routing to: {next_action}"
            }]
        }
        
    except Exception as e:
        logger.error(f'Error in Supervisor node: {str(e)}', 
                    trial=state.get("trial", 0))
        return {
            "next_action": "END",
            "termination_reason": "supervisor_error",
            "errors": [{
                "node": "Supervisor",
                "message": str(e),
                "type": type(e).__name__
            }]
        }

def _determine_next_action(state: FuzzingWorkflowState) -> str:
    """
    Determine the next action based on current workflow state.
    
    This implements the core routing logic of the fuzzing workflow:
    1. Function analysis -> Prototyper
    2. Prototyper -> Build/Execution
    3. Build success -> Execution
    4. Execution with crashes -> CrashAnalyzer -> ContextAnalyzer
    5. Execution with low coverage -> CoverageAnalyzer
    6. Analysis results -> Enhancer or END
    7. Multiple cycles until success or max iterations
    
    Args:
        state: Current workflow state
        
    Returns:
        Next action to take
    """
    # Step 1: Check if we need function analysis
    if not state.get("function_analysis"):
        return "function_analyzer"
    
    # Step 2: Check if we need a fuzz target
    fuzz_target_source = state.get("fuzz_target_source")
    if not fuzz_target_source:
        logger.debug(f'No fuzz_target_source found, routing to prototyper', trial=state.get("trial", 0))
        return "prototyper"
    else:
        logger.debug(f'fuzz_target_source exists (length={len(fuzz_target_source)})', trial=state.get("trial", 0))
    
    # Step 3: Check if we've built successfully
    compile_success = state.get("compile_success")
    logger.debug(f'compile_success={compile_success}', trial=state.get("trial", 0))
    if compile_success is None:
        # Haven't tried building yet
        return "build"
    elif not compile_success:
        # Build failed, need to enhance or retry
        retry_count = state.get("retry_count", 0)
        logger.debug(f'Build failed, retry_count={retry_count}', trial=state.get("trial", 0))
        max_retries = state.get("max_retries", 3)
        if retry_count < max_retries:
            return "enhancer"
        else:
            # Exceeded retries, end workflow
            logger.warning(f'Build failed after {retry_count} retries, ending workflow', 
                         trial=state.get("trial", 0))
            return "END"
    
    # Step 4: Build succeeded, check if we've run
    run_success = state.get("run_success")
    logger.debug(f'Build succeeded, run_success={run_success}', trial=state.get("trial", 0))
    if run_success is None:
        # Haven't tried running yet
        return "execution"
    
    # Step 5: We've run, analyze the results
    if not run_success:
        # Execution failed/crashed
        run_error = state.get("run_error", "")
        crashes = state.get("crashes", False)
        
        if crashes or (run_error and "crash" in run_error.lower()):
            # We have a crash to analyze
            crash_analysis = state.get("crash_analysis")
            if not crash_analysis:
                logger.debug('Crash detected, routing to crash_analyzer', trial=state.get("trial", 0))
                return "crash_analyzer"
            
            # We have crash analysis, check if we need context analysis
            context_analysis = state.get("context_analysis")
            if not context_analysis:
                logger.debug('Crash analyzed, routing to context_analyzer', trial=state.get("trial", 0))
                return "context_analyzer"
            
            # Both crash and context analysis done
            # If crash is feasible (true bug), we're done successfully
            if context_analysis.get("feasible", False):
                logger.info('Found a feasible crash (true bug)!', trial=state.get("trial", 0))
                return "END"
            else:
                # False positive, try to enhance the target based on recommendations
                logger.info('Crash is not feasible, enhancing target', trial=state.get("trial", 0))
                return "enhancer"
        
        # Execution failed but not a crash, enhance the target
        logger.debug('Execution failed (not a crash), enhancing target', trial=state.get("trial", 0))
        return "enhancer"
    
    # Step 6: Execution succeeded, check coverage results
    coverage_percent = state.get("coverage_percent", 0.0)
    coverage_diff = state.get("line_coverage_diff", 0.0)
    logger.debug(f'Execution succeeded: coverage={coverage_percent:.2%}, diff={coverage_diff:.2%}', 
                trial=state.get("trial", 0))
    
    # Check iteration count to avoid infinite loops
    current_iteration = state.get("current_iteration", 0)
    max_iterations = state.get("max_iterations", 5)
    
    # Track consecutive iterations without coverage improvement
    no_improvement_count = state.get("no_coverage_improvement_count", 0)
    NO_IMPROVEMENT_THRESHOLD = 3  # If coverage doesn't improve for 3 consecutive checks, consider it done
    
    # Check if coverage improved significantly
    IMPROVEMENT_THRESHOLD = 0.01  # At least 1% improvement
    if coverage_diff > IMPROVEMENT_THRESHOLD:
        # Coverage improved, reset the no-improvement counter
        logger.debug(f'Coverage improved by {coverage_diff:.2%}, resetting no-improvement counter', 
                    trial=state.get("trial", 0))
        # Note: The counter will be reset in execution_node when it updates the state
    
    # Check if coverage has been stagnant for too long
    if no_improvement_count >= NO_IMPROVEMENT_THRESHOLD:
        logger.info(f'Coverage stagnant for {no_improvement_count} iterations ({coverage_percent:.2%}), '
                   f'considering workflow complete and ready for delivery', 
                   trial=state.get("trial", 0))
        return "END"
    
    # Check if we should analyze coverage (low coverage AND no improvement)
    COVERAGE_THRESHOLD = 0.5  # 50% coverage threshold
    SIGNIFICANT_IMPROVEMENT = 0.05  # 5% is considered significant improvement
    
    # Only analyze if coverage is low AND there's no significant improvement
    # If there's significant improvement, continue the current strategy even if absolute coverage is low
    if coverage_percent < COVERAGE_THRESHOLD and coverage_diff <= SIGNIFICANT_IMPROVEMENT:
        coverage_analysis = state.get("coverage_analysis")
        if not coverage_analysis and current_iteration < max_iterations:
            logger.debug(f'Low coverage ({coverage_percent:.2%}) and no significant improvement (diff={coverage_diff:.2%}, '
                        f'no_improvement_count={no_improvement_count}), routing to coverage_analyzer', 
                        trial=state.get("trial", 0))
            return "coverage_analyzer"
        
        # We have coverage analysis or reached max iterations
        if coverage_analysis and coverage_analysis.get("improve_required", False):
            # Coverage analyzer suggests improvement is possible
            if current_iteration < max_iterations and no_improvement_count < NO_IMPROVEMENT_THRESHOLD:
                logger.info('Coverage can be improved, enhancing target', trial=state.get("trial", 0))
                return "enhancer"
    
    # Good coverage or max iterations reached - we're done
    logger.info(f'Workflow complete: coverage={coverage_percent:.2%}, iterations={current_iteration}, '
               f'no_improvement_count={no_improvement_count}', 
               trial=state.get("trial", 0))
    return "END"

def route_condition(state: FuzzingWorkflowState) -> str:
    """
    LangGraph conditional routing function.
    
    This function is used by LangGraph's conditional edges to determine
    which node to execute next.
    
    Args:
        state: Current workflow state
        
    Returns:
        Name of the next node to execute
    """
    next_action = state.get("next_action", "function_analyzer")
    
    # Map actions to node names
    action_to_node = {
        "function_analyzer": "function_analyzer",
        "prototyper": "prototyper", 
        "enhancer": "enhancer",
        "build": "build",
        "execution": "execution",
        "crash_analyzer": "crash_analyzer",
        "coverage_analyzer": "coverage_analyzer",
        "context_analyzer": "context_analyzer",
        "END": "__end__"
    }
    
    return action_to_node.get(next_action, "__end__")

__all__ = ['supervisor_node', 'route_condition']
