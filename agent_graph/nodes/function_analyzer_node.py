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
"""
FunctionAnalyzer node for LangGraph workflow.

This module provides the LangGraph-compatible node wrapper for the original
FunctionAnalyzer agent.
"""
from typing import Dict, Any

import logger
from agent_graph.agents.function_analyzer import FunctionAnalyzer
from agent_graph.adapters import StateAdapter, AgentNodeWrapper
from agent_graph.state import FuzzingWorkflowState
from ..benchmark import LangGraphBenchmark as Benchmark


def function_analyzer_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node that wraps the original FunctionAnalyzer agent.
    
    This node performs function analysis by:
    1. Converting LangGraph state to Result objects
    2. Executing the original FunctionAnalyzer
    3. Converting the result back to state updates
    
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
        
        logger.info('Starting FunctionAnalyzer node', trial=trial)
        
        # Convert state to result history that FunctionAnalyzer expects
        result_history = StateAdapter.state_to_result_history(state)
        
        # Create the FunctionAnalyzer instance
        analyzer = FunctionAnalyzer(
            trial=trial,
            llm=llm,
            args=args,
            benchmark=benchmark,
            name='FunctionAnalyzer'
        )
        
        # Execute the analyzer
        result = analyzer.execute(result_history)
        
        # Convert result back to state updates
        state_update = StateAdapter.result_to_state_update(result)
        
        # Ensure logging is finalized (though analyzer.execute should handle this)
        try:
            analyzer.finalize()
        except Exception as log_error:
            logger.warning(f'Failed to finalize analyzer logging: {log_error}', trial=trial)
        
        logger.info('FunctionAnalyzer node completed successfully', trial=trial)
        
        return state_update
        
    except Exception as e:
        # Handle errors gracefully
        logger.error(f'Error in FunctionAnalyzer node: {str(e)}', 
                    trial=state.get("trial", 0))
        return {
            "errors": [{
                "node": "FunctionAnalyzer",
                "message": str(e),
                "type": type(e).__name__
            }],
            "messages": [{
                "role": "assistant",
                "content": f"FunctionAnalyzer failed: {str(e)}"
            }]
        }


# Alternative implementation using the generic wrapper
def create_function_analyzer_node():
    """
    Create a FunctionAnalyzer node using the generic AgentNodeWrapper.
    
    This demonstrates how to use the wrapper for consistent node creation.
    
    Returns:
        LangGraph node function for FunctionAnalyzer
    """
    return AgentNodeWrapper.create_agent_node(
        agent_class=FunctionAnalyzer,
        name='FunctionAnalyzer'
    )


# For backward compatibility and explicit control, we export the manual implementation
# but the wrapper version is available for other nodes
__all__ = ['function_analyzer_node', 'create_function_analyzer_node']
