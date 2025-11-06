"""
Shared utility functions for agents.

This module provides common utilities used by both BaseAgent
and LangGraphAgent hierarchies.
"""

import re


def parse_tag(response: str, tag: str) -> str:
    """
    Parse XML-style or code block-style tags from LLM response.
    
    Args:
        response: LLM response text
        tag: Tag name to extract (e.g., 'fuzz_target', 'solution')
        
    Returns:
        Content within the tag, or empty string if not found
    """
    patterns = [
        rf'<{tag}>(.*?)</{tag}>',  # XML style: <tag>...</tag>
        rf'```{tag}(.*?)```'       # Code block style: ```tag...```
    ]
    
    for pattern in patterns:
        match = re.search(pattern, response, re.DOTALL)
        if match:
            return match.group(1).strip()
    
    return ''

