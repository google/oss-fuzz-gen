"""
Supervisor node for LangGraph workflow routing.

This module provides the routing logic for the fuzzing workflow,
determining which agents to execute next based on the current state.
"""
from typing import Dict, Any, List

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState, consolidate_session_memory

def supervisor_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
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
        
        # Increment and check global supervisor call count (similar to no_coverage_improvement_count)
        supervisor_call_count = state.get("supervisor_call_count", 0) + 1
        MAX_SUPERVISOR_CALLS = 50  # Absolute upper bound to prevent infinite loops
        
        if supervisor_call_count > MAX_SUPERVISOR_CALLS:
            logger.warning(f'Global loop limit reached: supervisor called {supervisor_call_count} times', 
                          trial=trial)
            return {
                "next_action": "END",
                "termination_reason": "global_loop_limit",
                "supervisor_call_count": supervisor_call_count,
                "messages": [{
                    "role": "assistant",
                    "content": f"Workflow terminated: supervisor called {supervisor_call_count} times (safety limit)"
                }]
            }
        
        # Check for errors that should terminate the workflow
        errors = state.get("errors", [])
        configurable = config.get("configurable", {})
        max_errors = configurable.get("max_errors", 5)
        if len(errors) >= max_errors:
            logger.warning('Too many errors, terminating workflow', trial=trial)
            return {
                "next_action": "END",
                "termination_reason": "too_many_errors",
                "supervisor_call_count": supervisor_call_count,
                "messages": [{
                    "role": "assistant",
                    "content": f"Workflow terminated due to {len(errors)} errors"
                }]
            }
        
        # Check retry count
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", configurable.get("max_retries", 3))
        
        if retry_count >= max_retries:
            logger.warning('Maximum retries reached, terminating workflow', trial=trial)
            return {
                "next_action": "END",
                "termination_reason": "max_retries_reached",
                "supervisor_call_count": supervisor_call_count,
                "messages": [{
                    "role": "assistant",
                    "content": f"Workflow terminated after {retry_count} retries"
                }]
            }
        
        # Routing logic based on current state
        next_action = _determine_next_action(state)
        
        # Track per-node visit counts (similar to no_coverage_improvement_count)
        node_visit_counts = state.get("node_visit_counts", {}).copy()
        if next_action != "END":
            node_visit_counts[next_action] = node_visit_counts.get(next_action, 0) + 1
            
            # Check if a single node is being visited too many times
            MAX_NODE_VISITS = 10
            if node_visit_counts[next_action] > MAX_NODE_VISITS:
                logger.warning(f'Node {next_action} visited {node_visit_counts[next_action]} times, '
                              f'possible loop detected', trial=trial)
                return {
                    "next_action": "END",
                    "termination_reason": "node_loop_detected",
                    "supervisor_call_count": supervisor_call_count,
                    "node_visit_counts": node_visit_counts,
                    "messages": [{
                        "role": "assistant",
                        "content": f"Workflow terminated: {next_action} visited {node_visit_counts[next_action]} times"
                    }]
                }
        
        logger.info(f'Supervisor determined next action: {next_action} '
                   f'(call #{supervisor_call_count}, node visits: {node_visit_counts.get(next_action, 0)})', 
                   trial=trial)
        
        # 整理和清理session_memory，确保下游agent获得干净的共识约束
        session_memory = consolidate_session_memory(state)
        
        return {
            "next_action": next_action,
            "supervisor_call_count": supervisor_call_count,
            "node_visit_counts": node_visit_counts,
            "session_memory": session_memory,  # 注入清理后的共识
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
    
    This implements TWO-PHASE routing logic:
    
    PHASE 1: COMPILATION (focus on getting code to compile)
    1. Function analysis -> Prototyper
    2. Prototyper -> Build
    3. Build failed -> Enhancer (max 3 retries)
    4. Still failing after 3 retries -> Regenerate with Prototyper (once)
    5. Compilation succeeds -> Switch to OPTIMIZATION phase
    
    PHASE 2: OPTIMIZATION (focus on coverage improvement)
    1. Execution -> Analyze results
    2. Crashes -> CrashAnalyzer -> ContextAnalyzer
    3. Low coverage -> CoverageAnalyzer
    4. Based on analysis -> Enhancer for improvement
    5. Multiple cycles until good coverage or max iterations
    
    Args:
        state: Current workflow state
        
    Returns:
        Next action to take
    """
    workflow_phase = state.get("workflow_phase", "compilation")
    trial = state.get("trial", 0)
    
    # Step 1: Check if we need function analysis (required for both phases)
    if not state.get("function_analysis"):
        return "function_analyzer"
    
    # Step 2: Check if we need a fuzz target
    fuzz_target_source = state.get("fuzz_target_source")
    if not fuzz_target_source:
        logger.debug(f'No fuzz_target_source found, routing to prototyper', trial=trial)
        return "prototyper"
    else:
        logger.debug(f'fuzz_target_source exists (length={len(fuzz_target_source)})', trial=trial)
    
    # ===== PHASE 1: COMPILATION =====
    if workflow_phase == "compilation":
        logger.debug(f'In COMPILATION phase', trial=trial)
        
        # Check if we've built successfully
        compile_success = state.get("compile_success")
        logger.debug(f'compile_success={compile_success}', trial=trial)
        
        if compile_success is None:
            # Haven't tried building yet
            return "build"
        
        elif not compile_success:
            # Build failed - handle compilation retry logic
            compilation_retry_count = state.get("compilation_retry_count", 0)
            prototyper_regenerate_count = state.get("prototyper_regenerate_count", 0)
            
            logger.debug(f'Build failed, compilation_retry_count={compilation_retry_count}, '
                        f'prototyper_regenerate_count={prototyper_regenerate_count}', trial=trial)
            
            # Strategy: Try enhancer up to 3 times, then regenerate with prototyper once
            MAX_COMPILATION_RETRIES = 3
            MAX_PROTOTYPER_REGENERATIONS = 1
            
            if compilation_retry_count < MAX_COMPILATION_RETRIES:
                # Try to fix with enhancer
                logger.info(f'Compilation failed (attempt {compilation_retry_count + 1}/{MAX_COMPILATION_RETRIES}), '
                           f'routing to enhancer', trial=trial)
                return "enhancer"
            
            elif prototyper_regenerate_count < MAX_PROTOTYPER_REGENERATIONS:
                # Enhancer failed 3 times, try regenerating from scratch
                logger.warning(f'Enhancer failed {MAX_COMPILATION_RETRIES} times, '
                              f'regenerating code with prototyper (regeneration {prototyper_regenerate_count + 1})', 
                              trial=trial)
                # Note: prototyper_node should increment prototyper_regenerate_count and reset compilation_retry_count
                return "prototyper"
            
            else:
                # Both strategies exhausted - give up
                logger.error(f'Compilation failed after {MAX_COMPILATION_RETRIES} enhancer retries '
                            f'and {MAX_PROTOTYPER_REGENERATIONS} prototyper regenerations. Ending workflow.', 
                            trial=trial)
                return "END"
        
        else:
            # Compilation succeeded! Switch to optimization phase
            logger.info(f'✓ Compilation successful! Switching to OPTIMIZATION phase', trial=trial)
            # Note: The phase switch will be handled by build_node when it updates state
            return "execution"
    
    # ===== PHASE 2: OPTIMIZATION =====
    elif workflow_phase == "optimization":
        logger.debug(f'In OPTIMIZATION phase', trial=trial)
        
        # Build succeeded, check if we've run
        run_success = state.get("run_success")
        logger.debug(f'Build succeeded, run_success={run_success}', trial=trial)
        if run_success is None:
            # Haven't tried running yet
            return "execution"
        
        # We've run, analyze the results
        if not run_success:
            # Execution failed/crashed
            run_error = state.get("run_error", "")
            crashes = state.get("crashes", False)
            
            if crashes or (run_error and "crash" in run_error.lower()):
                # We have a crash to analyze
                crash_analysis = state.get("crash_analysis")
                if not crash_analysis:
                    logger.debug('Crash detected, routing to crash_analyzer', trial=trial)
                    return "crash_analyzer"
                
                # We have crash analysis, check if we need context analysis
                context_analysis = state.get("context_analysis")
                if not context_analysis:
                    logger.debug('Crash analyzed, routing to context_analyzer', trial=trial)
                    return "context_analyzer"
                
                # Both crash and context analysis done
                # If crash is feasible (true bug), we're done successfully
                if context_analysis.get("feasible", False):
                    logger.info('Found a feasible crash (true bug)!', trial=trial)
                    return "END"
                else:
                    # False positive, try to enhance the target based on recommendations
                    logger.info('Crash is not feasible, enhancing target', trial=trial)
                    return "enhancer"
            
            # Execution failed but not a crash, enhance the target
            logger.debug('Execution failed (not a crash), enhancing target', trial=trial)
            return "enhancer"
        
        # Execution succeeded, check coverage results
        coverage_percent = state.get("coverage_percent", 0.0)
        coverage_diff = state.get("line_coverage_diff", 0.0)
        logger.debug(f'Execution succeeded: coverage={coverage_percent:.2%}, diff={coverage_diff:.2%}', 
                    trial=trial)
        
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
                        trial=trial)
            # Note: The counter will be reset in execution_node when it updates the state
        
        # Check if coverage has been stagnant for too long
        if no_improvement_count >= NO_IMPROVEMENT_THRESHOLD:
            logger.info(f'Coverage stagnant for {no_improvement_count} iterations ({coverage_percent:.2%}), '
                       f'considering workflow complete and ready for delivery', 
                       trial=trial)
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
                            trial=trial)
                return "coverage_analyzer"
            
            # We have coverage analysis or reached max iterations
            if coverage_analysis and coverage_analysis.get("improve_required", False):
                # Coverage analyzer suggests improvement is possible
                if current_iteration < max_iterations and no_improvement_count < NO_IMPROVEMENT_THRESHOLD:
                    logger.info('Coverage can be improved, enhancing target', trial=trial)
                    return "enhancer"
        
        # Good coverage or max iterations reached - we're done
        logger.info(f'Workflow complete: coverage={coverage_percent:.2%}, iterations={current_iteration}, '
                   f'no_improvement_count={no_improvement_count}', 
                   trial=trial)
        return "END"
    
    # Unknown phase - shouldn't happen
    logger.error(f'Unknown workflow phase: {workflow_phase}', trial=trial)
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
