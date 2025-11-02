"""
Shared utility functions for agents.

This module provides common utilities used by both BaseAgent
and LangGraphAgent hierarchies.
"""
import re
from typing import List


def parse_tag(response: str, tag: str) -> str:
    """
    Parse XML-style tags from LLM response.
    
    Args:
        response: The LLM response text
        tag: The tag name to extract (without < >)
    
    Returns:
        Content between the tags, or empty string if not found
        
    Examples:
        >>> parse_tag("<code>hello</code>", "code")
        'hello'
        >>> parse_tag("<fuzz_target>int main() {}</fuzz_target>", "fuzz_target")
        'int main() {}'
    """
    match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    if not match:
        return ''
    
    content = match.group(1).strip()
    
    # Remove markdown code block markers if present
    # LLMs sometimes wrap code in ```language ... ``` inside XML tags
    # Match: ```<optional_language>\n<code>\n```
    if content.startswith('```'):
        # Remove opening marker: ```c, ```cpp, ```python, etc.
        content = re.sub(r'^```\w*\n?', '', content)
        # Remove closing marker: ```
        content = re.sub(r'\n?```$', '', content)
        content = content.strip()
    
    return content


def parse_tags(response: str, tag: str) -> List[str]:
    """
    Parse multiple XML-style tags from LLM response.
    
    Args:
        response: The LLM response text
        tag: The tag name to extract (without < >)
    
    Returns:
        List of content between all matching tags
        
    Examples:
        >>> parse_tags("<bash>ls</bash><bash>pwd</bash>", "bash")
        ['ls', 'pwd']
    """
    matches = re.findall(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return [content.strip() for content in matches]

