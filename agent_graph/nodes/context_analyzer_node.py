"""
ContextAnalyzer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.langgraph_agent import LangGraphContextAnalyzer


def context_analyzer_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Analyze crash feasibility in the context of the project.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting ContextAnalyzer node', trial=trial)
    
    try:
        # Extract config
        configurable = config.get("configurable", {})
        llm = configurable["llm"]
        args = configurable["args"]
        
        # Create agent
        agent = LangGraphContextAnalyzer(
            llm=llm,
            trial=trial,
            args=args
        )
        
        # Execute agent
        result = agent.execute(state)
        
        logger.info('ContextAnalyzer node completed', trial=trial)
        return result
        
    except Exception as e:
        logger.error(f'ContextAnalyzer failed: {e}', trial=trial)
        # Return a default context_analysis to prevent infinite loops
        # (similar to how execution_node sets default coverage values)
        return {
            "context_analysis": {
                "feasible": False,
                "analysis": f"Analysis failed: {str(e)}",
                "source_code_evidence": "",
                "recommendations": "",
                "analyzed": False,
                "error": str(e)
            },
            "errors": [{
                "node": "ContextAnalyzer",
                "message": str(e),
                "type": type(e).__name__
            }]
        }

