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
        
        # Debug: log what we're returning
        if "fuzz_target_source" in result:
            code_length = len(result["fuzz_target_source"])
            logger.info(f'Prototyper node completed, returning fuzz_target_source (length={code_length})', trial=trial)
        else:
            logger.warning('Prototyper node completed but no fuzz_target_source in result', trial=trial)
        
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
