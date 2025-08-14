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
Data models for the OSS-Fuzz Python SDK.

This module defines Pydantic models for representing historical fuzzing
results, metadata, and time series data. These models provide validation,
serialization, and a clear structure for data exchange within the SDK.
"""
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FileType(Enum):
  """File types of target files."""
  C = 'C'
  CPP = 'C++'
  JAVA = 'Java'
  NONE = ''


class Severity(Enum):
  """Enum for crash severity levels."""
  CRITICAL = "CRITICAL"
  HIGH = "HIGH"
  MEDIUM = "MEDIUM"
  LOW = "LOW"
  INFO = "INFO"
  UNKNOWN = "UNKNOWN"


class Sanitizer(Enum):
  """Enum for supported sanitizers."""
  ADDRESS = "address"
  MEMORY = "memory"
  UNDEFINED = "undefined"
  DATAFLOW = "dataflow"


class FuzzingEngine(Enum):
  """Enum for supported fuzzing engines."""
  LIBFUZZER = "libfuzzer"
  AFL = "afl"
  HONGGFUZZ = "honggfuzz"
  CENTIPEDE = "centipede"


class BaseDataModel(BaseModel):
  """Base model with common configurations."""

  class Config:
    orm_mode = True  # Allows models to be created from ORM objects
    use_enum_values = True  # Ensures enum values are used in serialization
    extra = 'forbid'  # Disallow extra fields not defined in the model


class CrashData(BaseDataModel):
  """
    Represents information about a single crash occurrence.
    """
  crash_id: str = Field(..., description="Unique identifier for the crash.")
  timestamp: datetime = Field(
      ..., description="Timestamp when the crash occurred or was reported.")
  fuzzer_name: str = Field(
      ..., description="Name of the fuzzer that triggered the crash.")
  crash_signature: str = Field(
      ...,
      description="A condensed representation or signature of the crash (e.g., "
      "stack trace summary).")
  severity: Severity = Field(Severity.UNKNOWN,
                             description="Severity of the crash.")
  reproducible: Optional[bool] = Field(
      None, description="Whether the crash is confirmed to be reproducible.")
  stack_trace: Optional[str] = Field(
      None, description="Full stack trace, if available.")
  affected_files: Optional[List[str]] = Field(
      None,
      description="List of source files potentially involved in the crash.")
  regression_range: Optional[str] = Field(
      None,
      description="Commit range where this crash might have been introduced.")
  bug_report_url: Optional[str] = Field(
      None,
      description=
      "URL to an associated bug report (e.g., Monorail, GitHub Issue).")


class ProjectConfig(BaseDataModel):
  """Configuration for an OSS-Fuzz project."""
  project_name: str = Field(..., description="Name of the project")
  language: str = Field(..., description="Programming language of the project")
  sanitizer: Sanitizer = Field(Sanitizer.ADDRESS,
                               description="Sanitizer to use")
  architecture: str = Field("x86_64", description="Target architecture")
  fuzzing_engine: FuzzingEngine = Field(FuzzingEngine.LIBFUZZER,
                                        description="Fuzzing engine to use")
  environment_vars: Dict[str, str] = Field(default_factory=dict,
                                           description="Environment variables")
  build_args: List[str] = Field(default_factory=list,
                                description="Build arguments")
  commit: Optional[Dict[str, str]] = Field(None,
                                           description="Commit information")

  @classmethod
  def from_project_yaml(cls, path: Path) -> 'ProjectConfig':
    """Load configuration from project.yaml file."""
    import yaml
    with open(path, 'r') as f:
      data = yaml.safe_load(f)
    return cls(**data)

  def to_yaml(self, path: Path) -> bool:
    """Save configuration to YAML file."""
    import yaml
    try:
      with open(path, 'w') as f:
        yaml.dump(self.dict(), f, default_flow_style=False)
      return True
    except Exception:
      return False


class BuildHistoryData(BaseDataModel):
  """Represents a single build history entry."""
  build_id: str = Field(..., description="Unique identifier for the build")
  timestamp: datetime = Field(..., description="Build timestamp")
  project_name: str = Field(..., description="Name of the project")
  success: bool = Field(..., description="Whether the build was successful")
  duration_seconds: Optional[int] = Field(
      None, description="Build duration in seconds")
  commit_hash: Optional[str] = Field(None, description="Git commit hash")
  branch: Optional[str] = Field(None, description="Git branch")
  sanitizer: Optional[Sanitizer] = Field(None, description="Sanitizer used")
  architecture: Optional[str] = Field(None, description="Target architecture")
  error_message: Optional[str] = Field(
      None, description="Error message if build failed")
  artifacts: Optional[List[str]] = Field(None,
                                         description="List of build artifacts")


class CrashHistoryData(BaseDataModel):
  """Represents a single crash history entry."""
  crash_id: str = Field(..., description="Unique identifier for the crash")
  timestamp: datetime = Field(..., description="Crash timestamp")
  project_name: str = Field(..., description="Name of the project")
  fuzzer_name: str = Field(..., description="Name of the fuzzer")
  crash_type: str = Field(
      ..., description="Type of crash (e.g., heap-buffer-overflow)")
  crash_signature: str = Field(..., description="Crash signature/hash")
  severity: Severity = Field(Severity.UNKNOWN, description="Crash severity")
  reproducible: Optional[bool] = Field(
      None, description="Whether crash is reproducible")
  stack_trace: Optional[str] = Field(None, description="Stack trace")
  testcase_path: Optional[str] = Field(None, description="Path to testcase")
  regression_range: Optional[str] = Field(None, description="Regression range")


class CorpusHistoryData(BaseDataModel):
  """Represents a single corpus history entry."""
  timestamp: datetime = Field(..., description="Corpus snapshot timestamp")
  project_name: str = Field(..., description="Name of the project")
  fuzzer_name: str = Field(..., description="Name of the fuzzer")
  corpus_size: int = Field(..., description="Number of files in corpus")
  total_size_bytes: int = Field(...,
                                description="Total size of corpus in bytes")
  new_files_count: Optional[int] = Field(
      None, description="Number of new files added")
  coverage_increase: Optional[float] = Field(
      None, description="Coverage increase percentage")
  unique_features: Optional[int] = Field(
      None, description="Number of unique features")


class CoverageHistoryData(BaseDataModel):
  """Represents a single coverage history entry."""
  timestamp: datetime = Field(..., description="Coverage measurement timestamp")
  project_name: str = Field(..., description="Name of the project")
  fuzzer_name: Optional[str] = Field(None, description="Name of the fuzzer")
  line_coverage: float = Field(..., description="Line coverage percentage")
  function_coverage: Optional[float] = Field(
      None, description="Function coverage percentage")
  branch_coverage: Optional[float] = Field(
      None, description="Branch coverage percentage")
  lines_covered: Optional[int] = Field(None,
                                       description="Number of lines covered")
  lines_total: Optional[int] = Field(None, description="Total number of lines")
  functions_covered: Optional[int] = Field(
      None, description="Number of functions covered")
  functions_total: Optional[int] = Field(
      None, description="Total number of functions")
  branches_covered: Optional[int] = Field(
      None, description="Number of branches covered")
  branches_total: Optional[int] = Field(None,
                                        description="Total number of branches")


class TimeSeriesData(BaseDataModel):
  """Generic time series data container."""
  project_name: str = Field(..., description="Name of the project")
  data_type: str = Field(
      ..., description="Type of data (build, crash, corpus, coverage)")
  start_date: datetime = Field(..., description="Start date of the time series")
  end_date: datetime = Field(..., description="End date of the time series")
  data_points: List[Dict[str,
                         Any]] = Field(...,
                                       description="Time series data points")
  metadata: Optional[Dict[str, Any]] = Field(None,
                                             description="Additional metadata")


class HistoricalSummary(BaseDataModel):
  """Summary statistics for historical data."""
  project_name: str = Field(..., description="Name of the project")
  period_start: datetime = Field(..., description="Start of the summary period")
  period_end: datetime = Field(..., description="End of the summary period")

  # Build statistics
  total_builds: Optional[int] = Field(None,
                                      description="Total number of builds")
  successful_builds: Optional[int] = Field(
      None, description="Number of successful builds")
  build_success_rate: Optional[float] = Field(
      None, description="Build success rate percentage")

  # Crash statistics
  total_crashes: Optional[int] = Field(None,
                                       description="Total number of crashes")
  unique_crashes: Optional[int] = Field(None,
                                        description="Number of unique crashes")
  critical_crashes: Optional[int] = Field(
      None, description="Number of critical crashes")

  # Coverage statistics
  max_coverage: Optional[float] = Field(None,
                                        description="Maximum coverage achieved")
  avg_coverage: Optional[float] = Field(None, description="Average coverage")
  coverage_trend: Optional[str] = Field(
      None, description="Coverage trend (increasing/decreasing/stable)")

  # Corpus statistics
  max_corpus_size: Optional[int] = Field(None,
                                         description="Maximum corpus size")
  avg_corpus_size: Optional[float] = Field(None,
                                           description="Average corpus size")
  corpus_growth_rate: Optional[float] = Field(None,
                                              description="Corpus growth rate")
