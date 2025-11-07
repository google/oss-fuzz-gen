"""
Session Memory Injector - Inject consensus constraints into agent prompts.

This module provides standardized methods to inject session_memory into agent prompts,
ensuring all agents can see the consensus constraints for the current task without
relying on the entire message history.
"""

from typing import Dict, Any
from agent_graph.state import FuzzingWorkflowState, format_session_memory_for_prompt
from agent_graph.prompt_loader import get_prompt_manager


def build_prompt_with_session_memory(
    state: FuzzingWorkflowState,
    agent_specific_prompt: str,
    agent_name: str = "unknown"
) -> str:
    """
    Build complete prompt with session_memory included.
    
    This allows each agent to see all consensus constraints for the current task
    without relying on the conversation history in agent_messages.
    
    Args:
        state: Workflow state
        agent_specific_prompt: Agent-specific task prompt
        agent_name: Agent name (for logging)
    
    Returns:
        Complete prompt with consensus constraints
    """
    # Format session_memory
    consensus_context = format_session_memory_for_prompt(state)
    
    # Load prompt templates using PromptManager
    pm = get_prompt_manager()
    try:
        header_template = pm.get_session_memory_header()
    except FileNotFoundError:
        header_template = ""
    
    try:
        footer_template = pm.get_session_memory_footer()
    except FileNotFoundError:
        footer_template = ""
    
    # Combine: header + consensus + agent prompt + footer
    header = header_template.replace('{CONSENSUS_CONTEXT}', consensus_context)
    
    full_prompt = f"{header}{agent_specific_prompt}{footer_template}"
    
    return full_prompt


def extract_session_memory_updates_from_response(
    response: str,
    agent_name: str,
    current_iteration: int
) -> Dict[str, Any]:
    """
    Extract session_memory updates from agent response.
    
    Parse tags in agent's response to extract new constraints, fixes, etc.
    
    Args:
        response: Agent's LLM response
        agent_name: Agent name
        current_iteration: Current iteration number
    
    Returns:
        Dictionary containing session_memory updates
    """
    import re
    
    updates = {
        "api_constraints": [],
        "known_fixes": [],
        "decisions": [],
        "coverage_strategies": []
    }
    
    # 1. Extract API constraints
    api_constraint_pattern = r'<api_constraint>(.*?)</api_constraint>'
    for match in re.finditer(api_constraint_pattern, response, re.DOTALL):
        constraint_text = match.group(1).strip()
        if constraint_text:
            updates["api_constraints"].append({
                "constraint": constraint_text,
                "source": agent_name,
                "confidence": "medium",  # Default medium, can be adjusted based on keywords
                "iteration": current_iteration
            })
    
    # 2. Extract known fixes
    known_fix_pattern = r'<known_fix error="([^"]+)">(.*?)</known_fix>'
    for match in re.finditer(known_fix_pattern, response, re.DOTALL):
        error_pattern = match.group(1).strip()
        solution = match.group(2).strip()
        if error_pattern and solution:
            updates["known_fixes"].append({
                "error_pattern": error_pattern,
                "solution": solution,
                "source": agent_name,
                "iteration": current_iteration
            })
    
    # 3. Extract decisions
    decision_pattern = r'<decision reason="([^"]+)">(.*?)</decision>'
    for match in re.finditer(decision_pattern, response, re.DOTALL):
        reason = match.group(1).strip()
        decision = match.group(2).strip()
        if reason and decision:
            updates["decisions"].append({
                "decision": decision,
                "reason": reason,
                "source": agent_name,
                "iteration": current_iteration
            })
    
    # 4. Extract coverage strategies
    strategy_pattern = r'<coverage_strategy target="([^"]+)">(.*?)</coverage_strategy>'
    for match in re.finditer(strategy_pattern, response, re.DOTALL):
        target = match.group(1).strip()
        strategy = match.group(2).strip()
        if target and strategy:
            updates["coverage_strategies"].append({
                "strategy": strategy,
                "target": target,
                "source": agent_name,
                "iteration": current_iteration
            })
    
    return updates


def merge_session_memory_updates(
    state: FuzzingWorkflowState,
    updates: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Merge extracted updates into session_memory.
    
    Args:
        state: Workflow state
        updates: Updates extracted from agent response
    
    Returns:
        Updated session_memory
    """
    from agent_graph.state import (
        add_api_constraint,
        add_known_fix,
        add_decision,
        add_coverage_strategy
    )
    
    # Add API constraints
    for constraint in updates.get("api_constraints", []):
        add_api_constraint(
            state,
            constraint["constraint"],
            constraint["source"],
            constraint.get("confidence", "medium"),
            constraint.get("iteration")
        )
    
    # Add known fixes
    for fix in updates.get("known_fixes", []):
        add_known_fix(
            state,
            fix["error_pattern"],
            fix["solution"],
            fix["source"],
            fix.get("iteration")
        )
    
    # Add decisions
    for decision in updates.get("decisions", []):
        add_decision(
            state,
            decision["decision"],
            decision["reason"],
            decision["source"],
            decision.get("iteration")
        )
    
    # Add coverage strategies
    for strategy in updates.get("coverage_strategies", []):
        add_coverage_strategy(
            state,
            strategy["strategy"],
            strategy["target"],
            strategy["source"],
            strategy.get("iteration")
        )
    
    return state.get("session_memory", {})

