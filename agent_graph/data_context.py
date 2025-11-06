"""
Data context for fuzzing workflow - Single source of truth for all fuzzing data.

This module establishes clear data ownership:
- All data prepared ONCE in run_single_fuzz.py
- Nodes NEVER extract data, they only process what's given
- Failure is explicit, not hidden with fallbacks
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FuzzingContext:
    """
    Immutable data context containing ALL information needed for fuzzing.
    
    Philosophy:
    - Prepared once, used everywhere
    - No fallbacks - if data is missing, preparation failed
    - Immutable - once created, never modified
    - Explicit failures - missing data raises ValueError, not returns None
    
    Fields:
    - project_name: Target project (e.g., "libxml2")
    - function_signature: Full function signature (e.g., "xmlParseDocument")
    - function_info: FuzzIntrospector data about the function
    - api_dependencies: Dependency graph and call sequences
    - header_info: Header files needed for compilation
    - existing_fuzzer_headers: Headers used in existing fuzzers (for reference)
    - source_code: Optional source code of the function
    """
    
    # === Core identifiers ===
    project_name: str
    function_signature: str
    
    # === Required data (must be present) ===
    function_info: Dict[str, Any]
    api_dependencies: Dict[str, Any]
    header_info: Dict[str, List[str]]
    existing_fuzzer_headers: Dict[str, List[str]]
    
    # === Optional data ===
    source_code: Optional[str] = None
    
    # === Metadata ===
    preparation_time: float = 0.0
    
    def __post_init__(self):
        """Validate required data is not empty."""
        if not self.function_info:
            raise ValueError("function_info cannot be empty")
        if not self.api_dependencies:
            raise ValueError("api_dependencies cannot be empty")
        if not self.header_info:
            raise ValueError("header_info cannot be empty")
    
    @classmethod
    def prepare(cls, project_name: str, function_signature: str, 
                logger_instance: logging.Logger = None) -> 'FuzzingContext':
        """
        Prepare all fuzzing data in one shot.
        
        Philosophy:
        - Either succeeds completely or raises ValueError
        - No fallbacks - missing data is a DATA problem, not a code problem
        - Fail fast - let caller decide how to handle failures
        
        Args:
            project_name: Target project name
            function_signature: Full function signature
            logger_instance: Optional logger for progress reporting
        
        Returns:
            Fully initialized FuzzingContext
        
        Raises:
            ValueError: If any required data cannot be obtained
            RuntimeError: If underlying APIs fail
        """
        import time
        from data_prep import introspector
        from agent_graph.api_context_extractor import APIContextExtractor
        from agent_graph.api_dependency_analyzer import APIDependencyAnalyzer
        from agent_graph.header_extractor import get_function_definition_headers
        
        log = logger_instance or logger
        start_time = time.time()
        
        log.info(f'📦 Preparing fuzzing context for {function_signature}')
        
        # === Step 1: Query function information ===
        log.debug('  1/5 Querying function information...')
        try:
            function_info = introspector.query_introspector_target_function(
                project_name, function_signature
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to query function information: {e}\n"
                f"This is likely a FuzzIntrospector API issue."
            ) from e
        
        if not function_info:
            raise ValueError(
                f"Function '{function_signature}' not found in project '{project_name}'.\n"
                f"Fix your input or check FuzzIntrospector data."
            )
        
        # === Step 2: Query source code (optional) ===
        log.debug('  2/5 Querying source code...')
        try:
            source_code = introspector.query_introspector_function_source(
                project_name, function_signature
            )
        except Exception as e:
            log.warning(f"Failed to get source code: {e}")
            source_code = None
        
        # === Step 3: Extract API context ===
        log.debug('  3/5 Extracting API context...')
        try:
            extractor = APIContextExtractor(project_name)
            api_context = extractor.extract(function_signature)
        except Exception as e:
            raise RuntimeError(
                f"Failed to extract API context: {e}\n"
                f"This is an internal error in APIContextExtractor."
            ) from e
        
        if not api_context or not api_context.get('parameters'):
            raise ValueError(
                f"API context extraction returned empty result for '{function_signature}'.\n"
                f"This function might have unusual signature that APIContextExtractor cannot parse."
            )
        
        # === Step 4: Build dependency graph ===
        log.debug('  4/5 Building dependency graph...')
        try:
            analyzer = APIDependencyAnalyzer(
                project_name,
                llm=None,
                use_llm=False  # Use heuristic mode for data preparation
            )
            api_dependencies = analyzer.build_dependency_graph(function_signature)
        except Exception as e:
            raise RuntimeError(
                f"Failed to build dependency graph: {e}\n"
                f"This is an internal error in APIDependencyAnalyzer."
            ) from e
        
        if not api_dependencies:
            # For dependency graph, empty result might be valid (function with no deps)
            # but we should log it as suspicious
            log.warning(
                f"Dependency graph is empty for '{function_signature}'. "
                f"This is unusual - most functions have dependencies."
            )
            api_dependencies = {
                'call_sequence': [],
                'dependencies': [],
                'note': 'No dependencies found - this is suspicious'
            }
        
        # === Step 5: Extract header information ===
        log.debug('  5/5 Extracting headers...')
        try:
            header_info = get_function_definition_headers(project_name, function_signature)
        except Exception as e:
            raise RuntimeError(
                f"Failed to extract headers: {e}\n"
                f"This is an internal error in header_extractor."
            ) from e
        
        if not header_info:
            # Headers might be legitimately empty, but create explicit empty result
            log.warning("Header extraction returned empty - will use minimal headers")
            header_info = {
                'standard_headers': [],
                'project_headers': [],
                'note': 'No headers extracted - compilation might fail'
            }
        
        # === Step 6: Extract existing fuzzer headers (for reference) ===
        log.debug('  6/6 Extracting existing fuzzer headers...')
        try:
            existing_fuzzer_headers = _extract_existing_fuzzer_headers(
                project_name, log
            )
        except Exception as e:
            log.warning(f"Failed to extract existing fuzzer headers: {e}")
            existing_fuzzer_headers = {
                'standard_headers': [],
                'project_headers': []
            }
        
        # === Create context ===
        elapsed = time.time() - start_time
        log.info(f'✅ Fuzzing context prepared in {elapsed:.2f}s')
        log.debug(
            f'   └─ Source: {len(source_code) if source_code else 0} chars, '
            f'Params: {len(api_context.get("parameters", []))}, '
            f'Deps: {len(api_dependencies.get("call_sequence", []))}, '
            f'Headers: {len(header_info.get("standard_headers", [])) + len(header_info.get("project_headers", []))}'
        )
        
        # Store api_context inside api_dependencies for backward compatibility
        api_dependencies['api_context'] = api_context
        
        return cls(
            project_name=project_name,
            function_signature=function_signature,
            function_info=function_info,
            api_dependencies=api_dependencies,
            header_info=header_info,
            existing_fuzzer_headers=existing_fuzzer_headers,
            source_code=source_code,
            preparation_time=elapsed
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for state storage."""
        return {
            'project_name': self.project_name,
            'function_signature': self.function_signature,
            'function_info': self.function_info,
            'api_dependencies': self.api_dependencies,
            'header_info': self.header_info,
            'existing_fuzzer_headers': self.existing_fuzzer_headers,
            'source_code': self.source_code,
            'preparation_time': self.preparation_time,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FuzzingContext':
        """Reconstruct from dictionary."""
        return cls(**data)


def _extract_existing_fuzzer_headers(project_name: str, 
                                     log: logging.Logger) -> Dict[str, List[str]]:
    """
    Extract headers from existing fuzzers for reference.
    
    This is not critical data - if it fails, we just return empty.
    """
    from data_prep import introspector
    import re
    
    result = {
        'standard_headers': [],
        'project_headers': []
    }
    
    try:
        # Get all fuzzer files
        fuzzers = introspector.query_introspector_harness_files(project_name)
        if not fuzzers:
            return result
        
        standard_headers = set()
        project_headers = set()
        
        # Extract headers from first few fuzzers
        for fuzzer_path in fuzzers[:5]:
            try:
                fuzzer_source = introspector.query_introspector_file_source(
                    project_name, fuzzer_path
                )
                if not fuzzer_source:
                    continue
                
                # Extract #include statements from top of file
                for line in fuzzer_source.split('\n')[:50]:
                    include_match = re.match(r'^\s*#include\s+[<"]([^>"]+)[>"]', line)
                    if include_match:
                        header = include_match.group(1)
                        if header.startswith(project_name) or '/' in header:
                            project_headers.add(header)
                        else:
                            standard_headers.add(header)
            except Exception:
                continue  # Skip this fuzzer if extraction fails
        
        result['standard_headers'] = sorted(standard_headers)
        result['project_headers'] = sorted(project_headers)
        
    except Exception as e:
        log.warning(f"Failed to extract existing fuzzer headers: {e}")
    
    return result

