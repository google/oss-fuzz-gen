"""
Prompt loader for LangGraph agents.

This module loads prompt templates from external files, similar to the
legacy agent system but simplified for LangGraph.
"""
import os
from typing import Dict, Optional


# Base directory for agent_graph prompts
# LangGraph agents use this hardcoded path - not configurable via CLI
PROMPT_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)),
                 'prompts', 'agent_graph'))


def load_prompt_file(filename: str) -> str:
    """
    Load a prompt file from the prompts/agent_graph directory.
    
    Args:
        filename: Name of the prompt file
    
    Returns:
        Contents of the prompt file
    
    Raises:
        FileNotFoundError: If the prompt file doesn't exist
    """
    filepath = os.path.join(PROMPT_DIR, filename)
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Prompt file not found: {filepath}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


def load_system_prompt(agent_name: str) -> str:
    """
    Load system prompt for a specific agent.
    
    Args:
        agent_name: Name of the agent (e.g., "function_analyzer")
    
    Returns:
        System prompt text
    """
    filename = f"{agent_name}_system.txt"
    return load_prompt_file(filename)


def load_user_prompt_template(agent_name: str) -> str:
    """
    Load user prompt template for a specific agent.
    
    Args:
        agent_name: Name of the agent (e.g., "function_analyzer")
    
    Returns:
        User prompt template text
    """
    filename = f"{agent_name}_prompt.txt"
    return load_prompt_file(filename)


def format_prompt(template: str, **kwargs) -> str:
    """
    Format a prompt template with provided arguments.
    
    Args:
        template: Prompt template string with {VARIABLE} placeholders
        **kwargs: Variables to substitute in the template
    
    Returns:
        Formatted prompt
    
    Example:
        >>> template = "Hello {NAME}, you are {AGE} years old"
        >>> format_prompt(template, NAME="Alice", AGE=30)
        "Hello Alice, you are 30 years old"
    """
    # Convert kwargs to uppercase keys for consistency
    uppercase_kwargs = {k.upper(): v for k, v in kwargs.items()}
    
    # Use safe_substitute to avoid KeyError for missing variables
    # First, replace with uppercase keys
    result = template
    for key, value in uppercase_kwargs.items():
        placeholder = "{" + key + "}"
        result = result.replace(placeholder, str(value))
    
    return result


class PromptManager:
    """
    Manager for loading and caching prompts for LangGraph agents.
    """
    
    def __init__(self):
        """Initialize the prompt manager with empty cache."""
        self._system_prompts: Dict[str, str] = {}
        self._user_templates: Dict[str, str] = {}
    
    def get_system_prompt(self, agent_name: str) -> str:
        """
        Get system prompt for an agent (with caching).
        
        Args:
            agent_name: Name of the agent
        
        Returns:
            System prompt text
        """
        if agent_name not in self._system_prompts:
            self._system_prompts[agent_name] = load_system_prompt(agent_name)
        return self._system_prompts[agent_name]
    
    def get_user_prompt_template(self, agent_name: str) -> str:
        """
        Get user prompt template for an agent (with caching).
        
        Args:
            agent_name: Name of the agent
        
        Returns:
            User prompt template text
        """
        if agent_name not in self._user_templates:
            self._user_templates[agent_name] = load_user_prompt_template(agent_name)
        return self._user_templates[agent_name]
    
    def build_user_prompt(self, agent_name: str, **kwargs) -> str:
        """
        Build a user prompt by loading template and formatting it.
        
        Args:
            agent_name: Name of the agent
            **kwargs: Variables to substitute in the template
        
        Returns:
            Formatted user prompt
        """
        template = self.get_user_prompt_template(agent_name)
        return format_prompt(template, **kwargs)
    
    def clear_cache(self):
        """Clear the prompt cache."""
        self._system_prompts.clear()
        self._user_templates.clear()


# Global prompt manager instance
_prompt_manager = PromptManager()


def get_prompt_manager() -> PromptManager:
    """
    Get the global prompt manager instance.
    
    Returns:
        Global PromptManager instance
    """
    return _prompt_manager

