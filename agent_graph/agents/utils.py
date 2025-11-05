"""
Shared utility functions for agents.

This module provides common utilities used by both BaseAgent
and LangGraphAgent hierarchies.

Note: The XML tag parsing functions (parse_tag and parse_tags) have been removed
in favor of OpenAI Function Calling. All agents now use chat_with_tools() for
structured tool interactions.
"""

