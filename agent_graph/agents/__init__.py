# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
