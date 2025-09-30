"""
Local copy of agent modules for agent_graph independence.

This module contains local copies of the original agent classes to ensure
that agent_graph can operate independently without dependencies on the
main agent/ directory.
"""

from .base_agent import BaseAgent, ADKBaseAgent
from .function_analyzer import FunctionAnalyzer
from .prototyper import Prototyper
from .enhancer import Enhancer
from .crash_analyzer import CrashAnalyzer

__all__ = [
    'BaseAgent',
    'ADKBaseAgent',
    'FunctionAnalyzer',
    'Prototyper',
    'Enhancer',
    'CrashAnalyzer',
]
