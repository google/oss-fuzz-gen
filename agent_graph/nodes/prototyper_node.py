"""
Prototyper node for LangGraph workflow.

This module provides the LangGraph-compatible node wrapper for the original
Prototyper agent.
"""
from typing import Dict, Any

import logger
from agent_graph.agents.prototyper import Prototyper
from agent_graph.adapters import StateAdapter
from agent_graph.state import FuzzingWorkflowState
from ..benchmark import LangGraphBenchmark as Benchmark

def prototyper_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node that wraps the original Prototyper agent.
    
    This node generates fuzz target prototypes by:
    1. Converting LangGraph state to Result objects
    2. Executing the original Prototyper agent
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
        
        logger.info('Starting Prototyper node', trial=trial)
        
        # Convert state to result history that Prototyper expects
        result_history = StateAdapter.state_to_result_history(state)
        
        # Create the Prototyper instance
        prototyper = Prototyper(
            trial=trial,
            llm=llm,
            args=args,
            name='Prototyper'
        )
        
        # Execute the prototyper
        build_result = prototyper.execute(result_history)
        
        # Convert BuildResult back to state updates
        state_update = StateAdapter.result_to_state_update(build_result)
        
        logger.info('Prototyper node completed successfully', trial=trial)
        
        return state_update
        
    except Exception as e:
        # Handle errors gracefully
        logger.error(f'Error in Prototyper node: {str(e)}', 
                    trial=state.get("trial", 0))
        return {
            "errors": [{
                "node": "Prototyper",
                "message": str(e),
                "type": type(e).__name__
            }],
            "messages": [{
                "role": "assistant",
                "content": f"Prototyper failed: {str(e)}"
            }]
        }

__all__ = ['prototyper_node']
