"""
Data models for the OSS-Fuzz Python SDK.

This module defines Pydantic models for representing historical fuzzing
results, metadata, and time series data. These models provide validation,
serialization, and a clear structure for data exchange within the SDK.
"""
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

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
