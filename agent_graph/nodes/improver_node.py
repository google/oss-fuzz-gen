"""
Improver node for LangGraph workflow.

This node is responsible for improving fuzz driver quality based on 
coverage analysis recommendations. Unlike enhancer (which fixes compilation errors),
improver rewrites the driver to increase code coverage.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.langgraph_agent import LangGraphImprover


def improver_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Improve fuzz driver based on coverage analysis recommendations.
    
    This node is called when:
    - Coverage analyzer has identified improvement opportunities
    - Current driver has low coverage
    - No compilation errors exist
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates with improved fuzz target
    """
    trial = state["trial"]
    logger.info('Starting Improver node', trial=trial)
    
    try:
        # Extract config
        configurable = config.get("configurable", {})
        llm = configurable["llm"]
        args = configurable["args"]
        
        # Create agent
        agent = LangGraphImprover(
            llm=llm,
            trial=trial,
            args=args
        )
        
        # Execute agent
        result = agent.execute(state)
        
        logger.info('Improver node completed', trial=trial)
        return result
        
    except Exception as e:
        logger.error(f'Improver failed: {e}', trial=trial)
        return {
            "errors": [{
                "node": "Improver",
                "message": str(e),
                "type": type(e).__name__
            }]
        }

