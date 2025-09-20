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
CrashAnalyzer node for LangGraph workflow.

This module provides the LangGraph-compatible node wrapper for the original
CrashAnalyzer agent.
"""
from typing import Dict, Any

import logger
from agent_graph.agents.crash_analyzer import CrashAnalyzer
from agent_graph.adapters import StateAdapter
from agent_graph.state import FuzzingWorkflowState
from ..benchmark import LangGraphBenchmark as Benchmark


def crash_analyzer_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node that wraps the original CrashAnalyzer agent.
    
    This node analyzes crashes by:
    1. Converting LangGraph state to Result objects (including RunResult)
    2. Executing the original CrashAnalyzer agent
    3. Converting the AnalysisResult back to state updates
    
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
        
        logger.info('Starting CrashAnalyzer node', trial=trial)
        
        # Convert state to result history that CrashAnalyzer expects
        result_history = StateAdapter.state_to_result_history(state)
        
        # CrashAnalyzer expects the last result to be a RunResult with crash information
        if not result_history:
            raise ValueError("CrashAnalyzer requires result history")
        
        last_result = result_history[-1]
        if not hasattr(last_result, 'run_error') or not last_result.run_error:
            logger.warning('CrashAnalyzer expects RunResult with crash info, but got: %s', 
                         type(last_result), trial=trial)
        
        # Get artifact path from state
        artifact_path = state.get("artifact_path", "")
        
        # Create the CrashAnalyzer instance
        analyzer = CrashAnalyzer(
            trial=trial,
            llm=llm,
            args=args,
            name='CrashAnalyzer',
            artifact_path=artifact_path
        )
        
        # Execute the analyzer
        analysis_result = analyzer.execute(result_history)
        
        # Convert AnalysisResult back to state updates
        state_update = StateAdapter.result_to_state_update(analysis_result)
        
        logger.info('CrashAnalyzer node completed successfully', trial=trial)
        
        return state_update
        
    except Exception as e:
        # Handle errors gracefully
        logger.error(f'Error in CrashAnalyzer node: {str(e)}', 
                    trial=state.get("trial", 0))
        return {
            "errors": [{
                "node": "CrashAnalyzer",
                "message": str(e),
                "type": type(e).__name__
            }],
            "messages": [{
                "role": "assistant",
                "content": f"CrashAnalyzer failed: {str(e)}"
            }]
        }


__all__ = ['crash_analyzer_node']
