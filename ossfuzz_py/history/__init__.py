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
History management package for the OSS-Fuzz Python SDK.

This package provides managers for different types of historical data:
- BuildHistoryManager: Build history and statistics
- CrashHistoryManager: Crash data and analysis
- CorpusHistoryManager: Corpus growth and statistics
- CoverageHistoryManager: Coverage trends and analysis
"""

from .build_history_manager import BuildHistoryManager
from .corpus_history_manager import CorpusHistoryManager
from .coverage_history_manager import CoverageHistoryManager
from .crash_history_manager import CrashHistoryManager
from .history_manager import HistoryManager

__all__ = [
    'HistoryManager',
    'BuildHistoryManager',
    'CrashHistoryManager',
    'CorpusHistoryManager',
    'CoverageHistoryManager',
]
