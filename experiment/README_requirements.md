# Requirements Directory

## Purpose

The `requirements/` directory stores **LLM-generated API semantic modeling outputs** during the fuzzing workflow.

## Content

When the `FunctionAnalyzer` agent analyzes a target function, it generates semantic information about:
- API usage requirements
- Parameter constraints
- Function behavior descriptions
- Dependency requirements

This information is saved as `{trial:02d}.txt` files (e.g., `00.txt`, `01.txt`) and is used by subsequent agents to generate more accurate fuzz targets.

## Example

A requirements file might contain:
```
Function: calculate_checksum(data: bytes, algorithm: str) -> int

Requirements:
- data: Non-empty byte sequence
- algorithm: Must be one of ['crc32', 'adler32', 'md5']
- Returns: Integer checksum value
- Exceptions: ValueError if algorithm is invalid
```

## Related Code

- **Writer**: `agent_graph/agents/function_analyzer.py` - Generates and saves semantic analysis
- **Reader**: `agent_graph/agents/base_agent.py` - Loads requirements for fuzz target generation
- **Path Helper**: `experiment/workdir.py` - `requirements_file_path(trial)` method

## Note

This directory is **NOT** related to Python dependency requirements (like `requirements.txt` for pip). 
It stores LLM analysis outputs for the fuzzing workflow.

