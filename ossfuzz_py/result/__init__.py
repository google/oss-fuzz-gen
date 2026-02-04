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
Result management module for OSS-Fuzz SDK.

This module provides result management capabilities including the ResultManager
class and related result data structures.
"""

from .result_manager import ResultManager
from .results import (AnalysisInfo, BenchmarkResult, BuildInfo,
                      CoverageAnalysis, CrashAnalysis, Result, RunInfo,
                      TrialResult)

__all__ = [
    'ResultManager',
    'Result',
    'BuildInfo',
    'RunInfo',
    'AnalysisInfo',
    'TrialResult',
    'BenchmarkResult',
    'CoverageAnalysis',
    'CrashAnalysis',
]
