"""
Prototyper node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.langgraph_agent import LangGraphPrototyper


def prototyper_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate fuzz target code.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting Prototyper node', trial=trial)
    
    try:
        # Extract config
        configurable = config.get("configurable", {})
        llm = configurable["llm"]
        args = configurable["args"]
        
        # Create agent
        agent = LangGraphPrototyper(
            llm=llm,
            trial=trial,
            args=args
        )
        
        # Execute agent
        result = agent.execute(state)
        
        logger.info('Prototyper node completed', trial=trial)
        return result
        
    except Exception as e:
        logger.error(f'Prototyper failed: {e}', trial=trial)
        return {
            "errors": [{
                "node": "Prototyper",
                "message": str(e),
                "type": type(e).__name__
            }]
        }
