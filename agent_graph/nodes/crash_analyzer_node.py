"""
CrashAnalyzer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.langgraph_agent import LangGraphCrashAnalyzer


def crash_analyzer_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze crash information.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting CrashAnalyzer node', trial=trial)
    
    try:
        # Extract config
        configurable = config.get("configurable", {})
        llm = configurable["llm"]
        args = configurable["args"]
        
        # Create agent
        agent = LangGraphCrashAnalyzer(
            llm=llm,
            trial=trial,
            args=args
        )
        
        # Execute agent
        result = agent.execute(state)
        
        logger.info('CrashAnalyzer node completed', trial=trial)
        return result
        
    except Exception as e:
        logger.error(f'CrashAnalyzer failed: {e}', trial=trial)
        # Return a default crash_analysis to prevent infinite loops
        return {
            "crash_analysis": {
                "insight": f"Crash analysis failed: {str(e)}",
                "severity": "unknown",
                "root_cause": "",
                "analyzed": False,
                "error": str(e)
            },
            "errors": [{
                "node": "CrashAnalyzer",
                "message": str(e),
                "type": type(e).__name__
            }]
        }
