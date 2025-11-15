"""
Prompt loader for LangGraph agents.

Unified interface for loading all agent prompts.
"""
import os
from typing import Dict


# Base directory for agent prompts
PROMPT_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)),
                 'prompts'))


def load_prompt_file(filename: str) -> str:
    """
    Load a prompt file from the prompts directory.
    
    Use this ONLY for non-standard files (e.g., session_memory_header.txt).
    For standard agent prompts, use PromptManager.
    
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


class PromptManager:
    """
    Manager for loading and caching prompts for LangGraph agents.
    
    Standard naming convention:
    - System prompt: {agent_name}_system.txt
    - User prompt: {agent_name}_prompt.txt
    """
    
    def __init__(self):
        """Initialize the prompt manager with empty cache."""
        self._cache: Dict[str, str] = {}
    
    def get_system_prompt(self, agent_name: str) -> str:
        """
        Get system prompt for an agent (with caching).
        
        Args:
            agent_name: Name of the agent (e.g., "function_analyzer")
        
        Returns:
            System prompt text from {agent_name}_system.txt
        """
        filename = f"{agent_name}_system.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]
    
    def get_user_prompt_template(self, agent_name: str) -> str:
        """
        Get user prompt template for an agent (with caching).
        
        Args:
            agent_name: Name of the agent (e.g., "function_analyzer")
        
        Returns:
            User prompt template text from {agent_name}_prompt.txt
        """
        filename = f"{agent_name}_prompt.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]
    
    def build_user_prompt(self, agent_name: str, **kwargs) -> str:
        """
        Build a user prompt by loading template and formatting it.
        
        Args:
            agent_name: Name of the agent (WITHOUT _prompt suffix!)
            **kwargs: Variables to substitute in the template
        
        Returns:
            Formatted user prompt
        
        Example:
            >>> pm = PromptManager()
            >>> prompt = pm.build_user_prompt("crash_analyzer", 
            ...                               CRASH_INFO="...", 
            ...                               SOURCE_CODE="...")
        """
        template = self.get_user_prompt_template(agent_name)
        # Convert kwargs to uppercase and substitute
        result = template
        for key, value in kwargs.items():
            placeholder = "{" + key.upper() + "}"
            result = result.replace(placeholder, str(value))
        return result
    
    # Special methods for non-standard prompts
    
    def get_session_memory_header(self) -> str:
        """Get session memory header template."""
        filename = "session_memory_header.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]
    
    def get_session_memory_footer(self) -> str:
        """Get session memory footer template."""
        filename = "session_memory_footer.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]
    
    def get_function_analyzer_initial_prompt(self) -> str:
        """Get function analyzer initial analysis prompt."""
        filename = "function_analyzer_initial_prompt.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]
    
    def get_function_analyzer_incremental_refine_prompt(self) -> str:
        """Get function analyzer incremental refinement prompt."""
        filename = "function_analyzer_incremental_refine_prompt.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]
    
    def get_function_analyzer_final_summary_prompt(self) -> str:
        """Get function analyzer final summary prompt."""
        filename = "function_analyzer_final_summary_prompt.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]
    
    def clear_cache(self):
        """Clear the prompt cache."""
        self._cache.clear()


# Global prompt manager instance
_prompt_manager = PromptManager()


def get_prompt_manager() -> PromptManager:
    """
    Get the global prompt manager instance.
    
    Returns:
        Global PromptManager instance
    """
    return _prompt_manager

