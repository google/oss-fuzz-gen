"""
Memory management utilities for LangGraph agents.

This module provides token-aware message trimming to prevent context overflow.
"""
import tiktoken
from typing import List, Dict, Any
from langgraph.checkpoint.memory import MemorySaver


def count_tokens(text: str, model: str = "gpt-4") -> int:
    """
    Count the number of tokens in a text string.
    
    Args:
        text: The text to count tokens for
        model: The model encoding to use (default: gpt-4)
    
    Returns:
        Number of tokens in the text
    """
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        # Fallback to cl100k_base for unknown models
        encoding = tiktoken.get_encoding("cl100k_base")
    
    return len(encoding.encode(text))


def trim_messages_by_tokens(
    messages: List[Dict[str, Any]], 
    max_tokens: int = 50000,
    keep_system: bool = True,
    system_max_tokens: int = 10000
) -> List[Dict[str, Any]]:
    """
    Trim messages to fit within token limit.
    
    Strategy:
    1. Always keep system message (if keep_system=True), truncate if too large
    2. Keep most recent messages that fit within max_tokens
    3. Remove oldest user/assistant pairs first
    
    Args:
        messages: List of message dicts with 'role' and 'content'
        max_tokens: Maximum tokens to keep (default: 50k)
        keep_system: Whether to always keep system message
        system_max_tokens: Maximum tokens for system message (default: 10k)
    
    Returns:
        Trimmed list of messages
    """
    if not messages:
        return []
    
    # Separate system message from others
    system_message = None
    other_messages = []
    
    for msg in messages:
        if msg.get("role") == "system" and keep_system:
            system_message = msg
        else:
            other_messages.append(msg)
    
    # Calculate tokens for system message
    system_tokens = 0
    if system_message:
        content = system_message.get("content", "")
        system_tokens = count_tokens(content)
        
        # Truncate system message if too large
        if system_tokens > system_max_tokens:
            encoding = tiktoken.get_encoding("cl100k_base")
            tokens = encoding.encode(content)
            truncated_tokens = tokens[:system_max_tokens]
            system_message = {
                "role": "system",
                "content": encoding.decode(truncated_tokens) + "\n\n[... system message truncated ...]"
            }
            system_tokens = system_max_tokens
    
    # If system message alone exceeds total limit, return just system
    if system_tokens >= max_tokens:
        return [system_message] if system_message else []
    
    # Calculate tokens for other messages from newest to oldest
    remaining_tokens = max_tokens - system_tokens
    kept_messages = []
    current_tokens = 0
    
    # Iterate from newest to oldest
    for msg in reversed(other_messages):
        msg_content = msg.get("content", "")
        msg_tokens = count_tokens(msg_content)
        
        # If single message is too large, truncate it
        if msg_tokens > remaining_tokens - current_tokens:
            # Try to fit truncated version
            tokens_available = remaining_tokens - current_tokens
            if tokens_available > 1000:  # Only truncate if we have at least 1k tokens
                encoding = tiktoken.get_encoding("cl100k_base")
                tokens = encoding.encode(msg_content)
                truncated_tokens = tokens[:tokens_available - 100]  # Leave some margin
                truncated_msg = msg.copy()
                truncated_msg["content"] = encoding.decode(truncated_tokens) + "\n\n[... truncated ...]"
                kept_messages.insert(0, truncated_msg)
            break
        
        kept_messages.insert(0, msg)
        current_tokens += msg_tokens
    
    # Combine system message (if any) with kept messages
    result = []
    if system_message:
        result.append(system_message)
    result.extend(kept_messages)
    
    return result


def get_agent_messages(
    state: Dict[str, Any],
    agent_name: str,
    system_message: str = None
) -> List[Dict[str, Any]]:
    """
    Get or initialize messages for a specific agent.
    
    Args:
        state: The workflow state dict
        agent_name: Name of the agent
        system_message: Optional system message to add on first access
    
    Returns:
        List of messages for this agent
    """
    # Initialize agent_messages dict if needed
    if "agent_messages" not in state:
        state["agent_messages"] = {}
    
    # Initialize this agent's messages if needed
    if agent_name not in state["agent_messages"]:
        state["agent_messages"][agent_name] = []
        
        # Add system message on first initialization
        if system_message:
            state["agent_messages"][agent_name].append({
                "role": "system",
                "content": system_message
            })
    
    return state["agent_messages"][agent_name]


def add_agent_message(
    state: Dict[str, Any],
    agent_name: str,
    role: str,
    content: str
) -> None:
    """
    Add a message to an agent's conversation history.
    
    Args:
        state: The workflow state dict
        agent_name: Name of the agent
        role: Message role ('user' or 'assistant')
        content: Message content
    """
    messages = get_agent_messages(state, agent_name)
    messages.append({
        "role": role,
        "content": content
    })
    
    # Trim after adding - use larger limit to accommodate code and context
    state["agent_messages"][agent_name] = trim_messages_by_tokens(
        messages,
        max_tokens=100000,  # Increase to 100k tokens per agent
        keep_system=True,
        system_max_tokens=10000  # Limit system message to 10k
    )


def create_memory_checkpointer() -> MemorySaver:
    """
    Create a LangGraph memory checkpointer for state persistence.
    
    Returns:
        MemorySaver instance for checkpointing
    """
    return MemorySaver()

