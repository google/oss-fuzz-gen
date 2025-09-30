"""
Enhancer node for LangGraph workflow.

This module provides the LangGraph-compatible node wrapper for the original
Enhancer agent.
"""
from typing import Dict, Any

import logger
from agent_graph.agents.enhancer import Enhancer
from agent_graph.adapters import StateAdapter
from agent_graph.state import FuzzingWorkflowState
from ..benchmark import LangGraphBenchmark as Benchmark

def enhancer_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node that wraps the original Enhancer agent.
    
    This node enhances existing fuzz targets by:
    1. Converting LangGraph state to Result objects (including AnalysisResult)
    2. Executing the original Enhancer agent
    3. Converting the BuildResult back to state updates
    
    Args:
        state: Current LangGraph workflow state
        config: Configuration containing LLM, args, etc.
        
    Returns:
        Dictionary of state updates
    """
    try:
        # Extract configuration from LangGraph's configurable system
        configurable = config.get("configurable", {})
        llm = configurable["llm"]
        args = configurable["args"]
        benchmark = Benchmark.from_dict(state["benchmark"])
        trial = state["trial"]
        
        logger.info('Starting Enhancer node', trial=trial)
        
        # Convert state to result history that Enhancer expects
        result_history = StateAdapter.state_to_result_history(state)
        
        # Enhancer expects the last result to be an AnalysisResult
        if not result_history or not hasattr(result_history[-1], 'coverage_result'):
            logger.warning('Enhancer expects AnalysisResult as last result, but got: %s', 
                         type(result_history[-1]) if result_history else 'empty history',
                         trial=trial)
        
        # Create the Enhancer instance
        enhancer = Enhancer(
            trial=trial,
            llm=llm,
            args=args,
            name='Enhancer'
        )
        
        # Execute the enhancer
        build_result = enhancer.execute(result_history)
        
        # Convert BuildResult back to state updates
        state_update = StateAdapter.result_to_state_update(build_result)
        
        logger.info('Enhancer node completed successfully', trial=trial)
        
        return state_update
        
    except Exception as e:
        # Handle errors gracefully
        logger.error(f'Error in Enhancer node: {str(e)}', 
                    trial=state.get("trial", 0))
        return {
            "errors": [{
                "node": "Enhancer",
                "message": str(e),
                "type": type(e).__name__
            }],
            "messages": [{
                "role": "assistant",
                "content": f"Enhancer failed: {str(e)}"
            }]
        }

__all__ = ['enhancer_node']
