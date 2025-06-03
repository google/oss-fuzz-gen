"""
Data models for the OSS-Fuzz Python SDK.

This module defines Pydantic models for representing historical fuzzing
results, metadata, and time series data. These models provide validation,
serialization, and a clear structure for data exchange within the SDK.
"""
from enum import Enum

from pydantic import BaseModel


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
        orm_mode = True # Allows models to be created from ORM objects
        use_enum_values = True # Ensures enum values are used in serialization
        extra = 'forbid' # Disallow extra fields not defined in the model
