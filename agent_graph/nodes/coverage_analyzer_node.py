"""
CoverageAnalyzer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.langgraph_agent import LangGraphCoverageAnalyzer


def coverage_analyzer_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze coverage information to provide insights for improvement.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting CoverageAnalyzer node', trial=trial)
    
    try:
        # Extract config
        configurable = config.get("configurable", {})
        llm = configurable["llm"]
        args = configurable["args"]
        
        # Create agent
        agent = LangGraphCoverageAnalyzer(
            llm=llm,
            trial=trial,
            args=args
        )
        
        # Execute agent
        result = agent.execute(state)
        
        logger.info('CoverageAnalyzer node completed', trial=trial)
        return result
        
    except Exception as e:
        logger.error(f'CoverageAnalyzer failed: {e}', trial=trial)
        # Return a default coverage_analysis to prevent infinite loops
        return {
            "coverage_analysis": {
                "suggestions": f"Coverage analysis failed: {str(e)}",
                "improve_required": False,
                "analyzed": False,
                "error": str(e)
            },
            "errors": [{
                "node": "CoverageAnalyzer",
                "message": str(e),
                "type": type(e).__name__
            }]
        }

