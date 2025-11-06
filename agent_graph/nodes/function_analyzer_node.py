"""
FunctionAnalyzer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents import LangGraphFunctionAnalyzer


def function_analyzer_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Analyze the target function.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting FunctionAnalyzer node', trial=trial)
    
    try:
        # Extract config
        configurable = config.get("configurable", {})
        llm = configurable["llm"]
        args = configurable["args"]
        
        # Create agent
        agent = LangGraphFunctionAnalyzer(
            llm=llm,
            trial=trial,
            args=args
        )
        
        # Execute agent
        result = agent.execute(state)
        
        logger.info('FunctionAnalyzer node completed', trial=trial)
        return result
        
    except Exception as e:
        import traceback
        logger.error(f'FunctionAnalyzer failed: {e}', trial=trial)
        logger.error(f'Traceback: {traceback.format_exc()}', trial=trial)
        return {
            "errors": [{
                "node": "FunctionAnalyzer",
                "message": str(e),
                "type": type(e).__name__,
                "traceback": traceback.format_exc()
            }]
        }
