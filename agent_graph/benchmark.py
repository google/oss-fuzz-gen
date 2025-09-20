"""
LangGraph-specific benchmark handling.
This provides a clean interface for LangGraph workflows without modifying the original benchmark code.
"""

from typing import Any, Dict


class LangGraphBenchmark:
    """A wrapper around the original Benchmark class for LangGraph workflows."""
    
    @classmethod
    def from_dict(cls, benchmark_dict: dict) -> 'LangGraphBenchmark':
        """Constructs a LangGraphBenchmark from a dictionary."""
        # Support both 'signature' and 'function_signature' keys for flexibility
        signature = (benchmark_dict.get('signature') or 
                    benchmark_dict.get('function_signature', ''))
        
        return cls(
            id=benchmark_dict.get('id', 'unknown'),
            project=benchmark_dict.get('project', 'unknown'),
            function_name=benchmark_dict.get('function_name', 'unknown'),
            signature=signature,
            filepath=benchmark_dict.get('filepath', ''),
            begin_line=benchmark_dict.get('begin_line', 0),
            end_line=benchmark_dict.get('end_line', 0),
            params=benchmark_dict.get('params', []),
            return_type=benchmark_dict.get('return_type', 'void'),
            target_path=benchmark_dict.get('target_path', ''),
            build_script=benchmark_dict.get('build_script', ''),
            language=benchmark_dict.get('language', 'c'),
            additional_info=benchmark_dict
        )
    
    def __init__(self, id: str, project: str, function_name: str, signature: str,
                 filepath: str, begin_line: int, end_line: int, params: list,
                 return_type: str, target_path: str, build_script: str,
                 language: str = 'c', additional_info: dict = None):
        self.id = id
        self.project = project
        self.function_name = function_name
        self.signature = signature
        # For backward compatibility - some code expects function_signature
        self.function_signature = signature
        self.filepath = filepath
        self.begin_line = begin_line
        self.end_line = end_line
        self.params = params
        self.return_type = return_type
        self.target_path = target_path
        self.build_script = build_script
        self.language = language
        self.additional_info = additional_info or {}
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'project': self.project,
            'function_name': self.function_name,
            'signature': self.signature,
            'filepath': self.filepath,
            'begin_line': self.begin_line,
            'end_line': self.end_line,
            'params': self.params,
            'return_type': self.return_type,
            'target_path': self.target_path,
            'build_script': self.build_script,
            'language': self.language,
            **self.additional_info
        }
    
    def __repr__(self) -> str:
        return f"LangGraphBenchmark({self.project}:{self.function_name})"
