"""A tool for LLM agents to interact within Fuzz Introspector to access
the project's information."""
import json
import logging
from typing import Any, Dict, List, Optional

from data_prep import introspector
from experiment import benchmark as benchmarklib
from tool import base_tool

logger = logging.getLogger(__name__)

class FuzzIntrospectorTool(base_tool.BaseTool):
  """
  Comprehensive Fuzz Introspector API tool for LLM agents.
  
  This tool provides access to various Fuzz Introspector APIs for:
  - Function analysis (source code, signatures, types)
  - Project structure (source files, headers, types)
  - Cross-references and call graphs
  - Optimal fuzzing targets
  - Test files and harness information
  """

  def __init__(self, benchmark: benchmarklib.Benchmark, name: str = ''):
    super().__init__(benchmark, name)
    self.project_name = benchmark.project
    self.project_functions = None

  # ==================== Function Information APIs ====================
  
  def get_target_function(self, function_name: str) -> Dict[str, Any]:
    """
    Gets detailed information about a specific target function.
    
    Args:
        function_name: Name of the function to query
        
    Returns:
        Dictionary with function details including signature, source location, 
        complexity metrics, etc.
        
    Example:
        result = tool.get_target_function("XMLNode::InsertEndChild")
    """
    logger.info('Getting target function details: %s', function_name)
    return introspector.query_introspector_target_function(
        self.project_name, function_name)
  
  def get_function_signature(self, function_name: str) -> str:
    """
    Gets the full signature for a given function name.
    
    Args:
        function_name: Raw function name (demangled for C++)
        
    Returns:
        Full function signature string
        
    Example:
        sig = tool.get_function_signature("sam_hrecs_remove_ref_altnames")
        # Returns: "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)"
    """
    logger.info('Getting function signature for: %s', function_name)
    return introspector.query_introspector_function_signature(
        self.project_name, function_name)
  
  def get_function_source_code(self, function_signature: str) -> str:
    """
    Gets the source code of a function by its signature.
    
    Args:
        function_signature: Full function signature
        
    Returns:
        Source code string of the function
        
    Example:
        code = tool.get_function_source_code(
            "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)")
    """
    logger.info('Getting source code for function: %s', function_signature)
    return introspector.query_introspector_function_source(
        self.project_name, function_signature)

  def function_source_with_signature(self, project_name: str,
                                     function_signature: str) -> str:
    """
    Retrieves a function's source from the fuzz introspector API,
      using the project's name and function's signature.

    Args:
        project_name (str): The name of the project.
        function_signature (str): The signature of the function.

    Returns:
        str: Source code of the function if found, otherwise an empty string.
    """
    logger.info('Retrieving function source for %s in project %s.',
                function_signature, project_name)

    function_code = introspector.query_introspector_function_source(
        project_name, function_signature)

    if function_code.strip():
      logger.info('Function with signature %s found and extracted.',
                  function_signature)
    else:
      logger.error('Error: Function with signature %s not found in project %s.',
                   function_signature, project_name)

    return function_code

  def get_function_implementation(self, project_name: str,
                                  function_name: str) -> str:
    """
    Retrieves a function's source from the fuzz introspector API,
      using the project's name and function's name

    Args:
        project_name (str): The name of the project.
        function_name (str): The name of the function.

    Returns:
        str: Source code of the function if found, otherwise an empty string.
    """
    logger.info('Retrieving function source for %s in project %s.',
                function_name, project_name)

    if self.project_functions is None:
      logger.info(
          'Project functions not initialized. Initializing for project %s.',
          project_name)
      functions_list = introspector.query_introspector_all_functions(
          project_name)

      if functions_list:
        # func["debug_summary"] and func["debug_summary"]["name"] could be
        # None or empty but still exists
        self.project_functions = {
            func["debug_summary"]["name"]: func
            for func in functions_list
            if isinstance(func.get("debug_summary"), dict) and
            isinstance(func["debug_summary"].get("name"), str) and
            func["debug_summary"]["name"].strip()
        }
      else:
        self.project_functions = None

    if (self.project_functions is None or
        function_name not in self.project_functions):
      logger.error('Error: Required function not found for project %s.',
                   project_name)
      return ''

    function_signature = self.project_functions[function_name][
        'function_signature']

    return self.function_source_with_signature(project_name, function_signature)
  
  def get_function_debug_types(self, function_signature: str) -> List[str]:
    """
    Gets debug type information for function parameters.
    
    Args:
        function_signature: Full function signature
        
    Returns:
        List of type strings for function arguments
        
    Example:
        types = tool.get_function_debug_types(
            "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)")
    """
    logger.info('Getting debug types for function: %s', function_signature)
    return introspector.query_introspector_function_debug_arg_types(
        self.project_name, function_signature)
  
  # ==================== Cross-Reference APIs ====================
  
  def get_sample_cross_references(self, function_signature: str) -> List[str]:
    """
    Gets sample cross-references with pre-processed usage examples.
    
    Returns high-quality code snippets showing how the function is used.
    
    Args:
        function_signature: Full function signature
        
    Returns:
        List of source code snippets showing function usage
        
    Example:
        samples = tool.get_sample_cross_references(
            "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)")
    """
    logger.info('Getting sample cross-references for: %s', function_signature)
    return introspector.query_introspector_sample_xrefs(
        self.project_name, function_signature)
  
  def get_call_sites_metadata(self, function_signature: str) -> List[Dict[str, Any]]:
    """
    Gets metadata about where a function is called without full source code.
    
    ⚠️ NOT RECOMMENDED for typical driver generation workflows.
    
    This method is kept for special use cases (e.g., iterative learning in function_analyzer),
    but for most driver generation tasks, prefer:
      1. get_sample_cross_references() - pre-processed, high-quality code snippets
      2. Direct test file analysis via query_introspector_for_tests_xref()
    
    Why not recommended:
      - Requires secondary queries to fetch actual source code
      - Returns metadata from all callers (including internal implementations)
      - Needs additional filtering and snippet extraction
      - Lower signal-to-noise ratio than sample_xrefs
    
    Args:
        function_signature: Full function signature
        
    Returns:
        List of dicts with keys: src_func, src_file, src_line
        
    Example:
        sites = tool.get_call_sites_metadata(
            "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)")
        # [{'src_func': 'caller_func', 'src_file': '/path/to/file.c', 'src_line': 42}, ...]
    """
    logger.info('Getting call site metadata for: %s', function_signature)
    return introspector.query_introspector_call_sites_metadata(
        self.project_name, function_signature)
  
  # ==================== Project Structure APIs ====================
  
  def get_all_functions(self) -> List[Dict[str, Any]]:
    """
    Gets JSON representation of all functions in the project.
    
    Returns:
        List of function dictionaries with metadata
        
    Example:
        all_funcs = tool.get_all_functions()
        # [{'function_signature': '...', 'function_name': '...', ...}, ...]
    """
    logger.info('Getting all functions for project: %s', self.project_name)
    return introspector.query_introspector_all_functions(self.project_name)
  
  def get_project_source_code(self, filepath: str, 
                             begin_line: int = 0, 
                             end_line: int = 10000) -> str:
    """
    Gets source code from a specific file in the project.
    
    Args:
        filepath: Path to the source file
        begin_line: Starting line number (default: 0)
        end_line: Ending line number (default: 10000)
        
    Returns:
        Source code string for the specified range
        
    Example:
        code = tool.get_project_source_code('/src/htslib/htsfile.c', 10, 90)
    """
    logger.info('Getting source code from %s [%d:%d]', 
                filepath, begin_line, end_line)
    return introspector.query_introspector_source_code(
        self.project_name, filepath, begin_line, end_line)
  
  def get_all_header_files(self) -> List[str]:
    """
    Gets all header files in the project.
    
    Returns:
        List of header file paths
        
    Example:
        headers = tool.get_all_header_files()
        # ['/include/header1.h', '/include/header2.h', ...]
    """
    logger.info('Getting all header files for project: %s', self.project_name)
    return introspector.query_introspector_header_files(self.project_name)
  
  def get_headers_for_function(self, function_signature: str) -> List[str]:
    """
    Gets the header files needed to use a specific function.
    
    Args:
        function_signature: Full function signature
        
    Returns:
        List of header file paths needed
        
    Example:
        headers = tool.get_headers_for_function(
            "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)")
    """
    logger.info('Getting headers for function: %s', function_signature)
    return introspector.query_introspector_header_files_to_include(
        self.project_name, function_signature)
  
  def get_all_source_files(self) -> List[str]:
    """
    Gets all source file paths in the project.
    
    Returns:
        List of source file paths
        
    Example:
        sources = tool.get_all_source_files()
    """
    logger.info('Getting all source files for project: %s', self.project_name)
    return introspector.query_introspector_jvm_source_path(self.project_name)
  
  # ==================== Type Information APIs ====================
  
  def get_type_definitions(self) -> List[Dict[str, Any]]:
    """
    Gets full type definitions for the project (structs, unions, typedefs, enums).
    
    Returns:
        List of type definition dictionaries
        
    Example:
        types = tool.get_type_definitions()
    """
    logger.info('Getting type definitions for project: %s', self.project_name)
    return introspector.query_introspector_type_definition(self.project_name)
  
  def get_functions_by_return_type(self, return_type: str) -> List[Dict[str, Any]]:
    """
    Finds all functions that return a specific type.
    
    Useful for finding factory/constructor functions for a type.
    
    Args:
        return_type: Type to match (e.g., "sam_hrecs_t *")
        
    Returns:
        List of function dictionaries matching the return type
        
    Example:
        funcs = tool.get_functions_by_return_type("sam_hrecs_t *")
    """
    logger.info('Getting functions with return type: %s', return_type)
    return introspector.query_introspector_matching_function_constructor_type(
        self.project_name, return_type, is_function=True)
  
  # ==================== Target Selection APIs ====================
  
  def get_optimal_targets(self) -> List[Dict[str, Any]]:
    """
    Gets the list of optimal fuzzing targets recommended by Fuzz Introspector.
    
    These are functions identified as good candidates for fuzzing based on
    various heuristics (complexity, reachability, etc.).
    
    Returns:
        List of function dictionaries representing optimal targets
        
    Example:
        targets = tool.get_optimal_targets()
    """
    logger.info('Getting optimal targets for project: %s', self.project_name)
    return introspector.query_introspector_for_optimal_targets(self.project_name)
  
  def get_far_reach_low_coverage_targets(self) -> List[Dict[str, Any]]:
    """
    Gets functions with far reach but low code coverage.
    
    These are good fuzzing targets that reach a lot of code but aren't
    well covered by existing fuzzers.
    
    Returns:
        List of function dictionaries
        
    Example:
        targets = tool.get_far_reach_low_coverage_targets()
    """
    logger.info('Getting far-reach-low-coverage targets for: %s', self.project_name)
    return introspector.query_introspector_for_far_reach_low_cov(self.project_name)
  
  def get_easy_param_targets(self) -> List[Dict[str, Any]]:
    """
    Gets functions with easy-to-fuzz parameters (like data buffers).
    
    Returns:
        List of function dictionaries with fuzzer-friendly parameters
        
    Example:
        targets = tool.get_easy_param_targets()
    """
    logger.info('Getting easy-param targets for: %s', self.project_name)
    return introspector.query_introspector_for_easy_param_targets(self.project_name)
  
  def get_all_public_candidates(self) -> List[Dict[str, Any]]:
    """
    Gets all public accessible functions/constructors as fuzzing candidates.
    
    Returns:
        List of all public function dictionaries
        
    Example:
        candidates = tool.get_all_public_candidates()
    """
    logger.info('Getting all public candidates for: %s', self.project_name)
    return introspector.query_introspector_all_public_candidates(self.project_name)
  
  # ==================== Test & Harness APIs ====================
  
  def get_project_tests(self) -> List[str]:
    """
    Gets the list of test files in the project.
    
    Useful for test-to-harness conversion strategies.
    
    Returns:
        List of test file paths
        
    Example:
        tests = tool.get_project_tests()
    """
    logger.info('Getting project tests for: %s', self.project_name)
    return introspector.query_introspector_for_tests(self.project_name)
  
  def get_tests_for_functions(self, function_names: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Gets test files that reference specific functions (test-to-function cross-references).
    
    This is extremely valuable for understanding how functions are used in tests.
    
    Args:
        function_names: Optional list of function names to search for. 
                       If None, gets tests for all functions.
        
    Returns:
        Dictionary with keys:
        - 'source': List of source code snippets from tests
        - 'details': List of detailed call information (if available)
        
    Example:
        # Find tests that use a specific function
        tests = tool.get_tests_for_functions(["InsertEndChild"])
        for snippet in tests['source'][:3]:
            print(snippet)
    """
    logger.info('Getting test cross-references for functions: %s', function_names)
    return introspector.query_introspector_for_tests_xref(
        self.project_name, function_names)
  
  def get_test_source_code(self, filepath: str) -> str:
    """
    Gets the source code of a test file.
    
    Args:
        filepath: Path to the test file
        
    Returns:
        Test source code string
        
    Example:
        code = tool.get_test_source_code('/tests/test_parser.c')
    """
    logger.info('Getting test source code from: %s', filepath)
    return introspector.query_introspector_test_source(self.project_name, filepath)
  
  def get_harness_pairs(self) -> List[Dict[str, str]]:
    """
    Gets pairs of harness source files and their executable names.
    
    Returns:
        List of dicts with 'source' and 'executable' keys
        
    Example:
        harnesses = tool.get_harness_pairs()
        # [{'source': '/src/fuzzer.cpp', 'executable': 'fuzzer_bin'}, ...]
    """
    logger.info('Getting harness source/executable pairs for: %s', self.project_name)
    return introspector.query_introspector_for_harness_intrinsics(self.project_name)
  
  # ==================== Analysis & Metadata APIs ====================
  
  def get_annotated_cfg(self) -> Dict[str, Any]:
    """
    Gets the annotated Control Flow Graph for the project.
    
    Returns comprehensive CFG data with coverage and complexity information.
    
    Returns:
        Dictionary containing CFG data
        
    Example:
        cfg = tool.get_annotated_cfg()
    """
    logger.info('Getting annotated CFG for: %s', self.project_name)
    return introspector.query_introspector_cfg(self.project_name)
  
  def get_project_language(self) -> str:
    """
    Gets the programming language(s) used in the project.
    
    Returns:
        Language string (e.g., 'c', 'c++', 'java', 'python')
        
    Example:
        lang = tool.get_project_language()
    """
    logger.info('Getting project language for: %s', self.project_name)
    from experiment import oss_fuzz_checkout
    return oss_fuzz_checkout.get_project_language(self.project_name)
  
  # ==================== Utility Methods ====================
  
  def get_function_location(self, function_signature: str) -> tuple:
    """
    Gets the file path and line range for a function.
    
    Args:
        function_signature: Full function signature
        
    Returns:
        Tuple of (filepath, start_line, end_line)
        
    Example:
        path, start, end = tool.get_function_location(
            "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)")
    """
    logger.info('Getting location for function: %s', function_signature)
    filepath = introspector.query_introspector_source_file_path(
        self.project_name, function_signature)
    line_info = introspector.query_introspector_function_line(
        self.project_name, function_signature)
    return (filepath, line_info[0], line_info[1])
  
  def summarize_function(self, function_name: str) -> str:
    """
    Gets a comprehensive summary of a function including source, callers, and types.
    
    Args:
        function_name: Name of the function
        
    Returns:
        Formatted string summary
        
    Example:
        summary = tool.summarize_function("sam_hrecs_remove_ref_altnames")
    """
    logger.info('Summarizing function: %s', function_name)
    
    # Get signature
    sig = self.get_function_signature(function_name)
    if not sig:
      return f"Function '{function_name}' not found."
    
    # Get source code
    source = self.get_function_source_code(sig)
    
    # Get location
    filepath, start, end = self.get_function_location(sig)
    
    # Get sample callers
    samples = self.get_sample_cross_references(sig)
    
    summary = f"""
Function Summary: {function_name}
{'=' * 80}
Signature: {sig}
Location: {filepath}:{start}-{end}

Source Code:
{'-' * 80}
{source}
{'-' * 80}

Sample Callers: {len(samples)} found
{'-' * 80}
"""
    
    for i, sample in enumerate(samples[:3], 1):  # Show up to 3 samples
      summary += f"\nCaller {i}:\n{sample}\n"
    
    return summary

  def execute(self, command: str) -> Any:
    """
    Executes a command-based API call.
    
    Command format: "method_name arg1 arg2 ..."
    
    Example:
        result = tool.execute("get_function_signature sam_hrecs_remove_ref_altnames")
    """
    parts = command.strip().split(maxsplit=1)
    if not parts:
      return "Error: Empty command"
    
    method_name = parts[0]
    args_str = parts[1] if len(parts) > 1 else ""
    
    # Map command names to methods
    method_map = {
        'get_target_function': self.get_target_function,
        'get_function_signature': self.get_function_signature,
        'get_function_source': self.get_function_source_code,
        'get_sample_xrefs': self.get_sample_cross_references,
        'get_all_functions': self.get_all_functions,
        'get_optimal_targets': self.get_optimal_targets,
        'get_headers': self.get_all_header_files,
        'summarize': self.summarize_function,
    }
    
    method = method_map.get(method_name)
    if not method:
      return f"Error: Unknown command '{method_name}'"
    
    try:
      if args_str:
        return method(args_str)
      else:
        return method()
    except Exception as e:
      logger.error('Error executing command %s: %s', command, e)
      return f"Error: {str(e)}"
