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
    4. Execution with crashes -> CrashAnalyzer
    5. Execution with coverage -> CoverageAnalyzer (if available)
    6. Analysis results -> Enhancer
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
        if run_error and "crash" in run_error.lower():
            # We have a crash to analyze
            if not state.get("crash_analysis"):
                return "crash_analyzer"
        
        # After crash analysis or if no crash, enhance the target
        return "enhancer"
    
    # Step 6: Execution succeeded, check if we should continue enhancing
    # Check coverage diff - if it's 0, we're not discovering new code paths
    coverage_diff = state.get("line_coverage_diff", 0.0)
    
    # Check iteration count to avoid infinite loops
    current_iteration = state.get("current_iteration", 0)
    max_iterations = state.get("max_iterations", 5)
    
    if coverage_diff == 0.0 and current_iteration < max_iterations:
        # No new coverage discovered, try to enhance the target
        logger.info(f'No new coverage (diff={coverage_diff:.2%}), enhancing target', 
                   trial=state.get("trial", 0))
        return "enhancer"
    
    # Either we found new coverage or reached max iterations - we're done
    logger.info(f'Execution succeeded with coverage diff={coverage_diff:.2%}, workflow complete', 
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
        "END": "__end__"
    }
    
    return action_to_node.get(next_action, "__end__")

__all__ = ['supervisor_node', 'route_condition']
