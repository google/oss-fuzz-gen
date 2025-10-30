#!/usr/bin/env python3
"""
Header extractor using tree-sitter to find function definitions and extract headers.

This module provides functionality to:
1. Find the source file containing a function definition
2. Extract #include statements from that source file
3. Categorize headers into standard and project-specific headers
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from tree_sitter import Language, Parser, Node
import tree_sitter_cpp

logger = logging.getLogger(__name__)


class HeaderExtractor:
    """Extract headers from source files using tree-sitter."""
    
    def __init__(self, language: str = 'cpp'):
        """Initialize the header extractor.
        
        Args:
            language: Programming language (default: 'cpp')
        """
        self.language = language
        self.tree_sitter_lang = Language(tree_sitter_cpp.language())
        self.parser = Parser(self.tree_sitter_lang)
    
    def extract_headers_from_file(
        self,
        file_path: str
    ) -> Dict[str, List[str]]:
        """Extract #include statements from a LOCAL source file.
        
        NOTE: This method is for LOCAL files only (e.g., test files).
        For files in OSS-Fuzz containers, use get_function_definition_headers()
        which retrieves content via FuzzIntrospector API.
        
        Args:
            file_path: Path to the LOCAL source file
        
        Returns:
            Dictionary with:
            - 'standard_headers': List of system headers (e.g., <cstddef>)
            - 'project_headers': List of project headers (e.g., "utils.h")
            - 'raw_includes': All includes as they appear in the file
        """
        if not os.path.exists(file_path):
            logger.warning(f'Source file does not exist: {file_path}')
            return {
                'standard_headers': [],
                'project_headers': [],
                'raw_includes': []
            }
        
        try:
            with open(file_path, 'rb') as f:
                source_content = f.read()
        except Exception as e:
            logger.error(f'Failed to read source file {file_path}: {e}')
            return {
                'standard_headers': [],
                'project_headers': [],
                'raw_includes': []
            }
        
        return self._extract_headers_from_content(source_content, file_path)
    
    def _extract_headers_from_content(
        self,
        source_content: bytes,
        file_path: str = ''
    ) -> Dict[str, List[str]]:
        """Extract headers from source content using tree-sitter.
        
        Args:
            source_content: Source code content as bytes
            file_path: Optional file path for logging
        
        Returns:
            Dictionary with standard_headers, project_headers, and raw_includes
        """
        try:
            tree = self.parser.parse(source_content)
            root = tree.root_node
        except Exception as e:
            logger.error(f'Failed to parse source file {file_path}: {e}')
            return {
                'standard_headers': [],
                'project_headers': [],
                'raw_includes': []
            }
        
        standard_headers: List[str] = []
        project_headers: List[str] = []
        raw_includes: List[str] = []
        
        # Find all preproc_include nodes
        includes = self._find_includes(root, source_content)
        
        for include_text in includes:
            raw_includes.append(include_text)
            
            # Parse the include statement
            if '<' in include_text and '>' in include_text:
                # System header: #include <header>
                header = self._extract_header_name(include_text, '<', '>')
                if header:
                    standard_headers.append(f'<{header}>')
            elif '"' in include_text:
                # Project header: #include "header"
                header = self._extract_header_name(include_text, '"', '"')
                if header:
                    project_headers.append(f'"{header}"')
        
        logger.info(
            f'Extracted {len(standard_headers)} standard headers and '
            f'{len(project_headers)} project headers from {file_path or "source"}'
        )
        
        return {
            'standard_headers': standard_headers,
            'project_headers': project_headers,
            'raw_includes': raw_includes
        }
    
    def _find_includes(self, node: Node, source_content: bytes) -> List[str]:
        """Recursively find all #include statements in the AST.
        
        Args:
            node: Current tree-sitter node
            source_content: Source code content
        
        Returns:
            List of include statements as strings
        """
        includes = []
        
        if node.type == 'preproc_include':
            # Get the text of the include statement
            include_text = source_content[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')
            includes.append(include_text)
        
        # Recursively process children
        for child in node.children:
            includes.extend(self._find_includes(child, source_content))
        
        return includes
    
    def _extract_header_name(
        self,
        include_text: str,
        start_char: str,
        end_char: str
    ) -> Optional[str]:
        """Extract header name from include statement.
        
        Args:
            include_text: The full include statement (e.g., #include <stdio.h>)
            start_char: Starting delimiter ('<' or '"')
            end_char: Ending delimiter ('>' or '"')
        
        Returns:
            Header name without delimiters, or None if not found
        """
        try:
            start_idx = include_text.find(start_char)
            end_idx = include_text.find(end_char, start_idx + 1)
            
            if start_idx >= 0 and end_idx > start_idx:
                return include_text[start_idx + 1:end_idx]
        except Exception as e:
            logger.warning(f'Failed to extract header name from: {include_text}: {e}')
        
        return None
    
    def categorize_headers(
        self,
        headers: Dict[str, List[str]]
    ) -> Dict[str, List[str]]:
        """Further categorize headers by type (STL, C standard library, etc.).
        
        Args:
            headers: Dictionary from extract_headers_from_file()
        
        Returns:
            Enhanced dictionary with additional categorization
        """
        result = headers.copy()
        
        stl_headers = []
        c_std_headers = []
        posix_headers = []
        other_system_headers = []
        
        # Common STL headers
        stl_patterns = {
            'algorithm', 'array', 'atomic', 'bitset', 'chrono', 'complex',
            'condition_variable', 'deque', 'exception', 'filesystem', 'forward_list',
            'fstream', 'functional', 'future', 'initializer_list', 'iomanip',
            'ios', 'iosfwd', 'iostream', 'istream', 'iterator', 'limits',
            'list', 'locale', 'map', 'memory', 'mutex', 'new', 'numeric',
            'optional', 'ostream', 'queue', 'random', 'ratio', 'regex',
            'set', 'sstream', 'stack', 'stdexcept', 'streambuf', 'string',
            'string_view', 'system_error', 'thread', 'tuple', 'type_traits',
            'typeindex', 'typeinfo', 'unordered_map', 'unordered_set', 'utility',
            'valarray', 'variant', 'vector'
        }
        
        # C standard library headers
        c_std_patterns = {
            'assert.h', 'ctype.h', 'errno.h', 'float.h', 'limits.h', 'locale.h',
            'math.h', 'setjmp.h', 'signal.h', 'stdarg.h', 'stddef.h', 'stdio.h',
            'stdlib.h', 'string.h', 'time.h', 'wchar.h', 'wctype.h',
            # C++ versions
            'cassert', 'cctype', 'cerrno', 'cfloat', 'climits', 'clocale',
            'cmath', 'csetjmp', 'csignal', 'cstdarg', 'cstddef', 'cstdio',
            'cstdlib', 'cstring', 'ctime', 'cwchar', 'cwctype'
        }
        
        # POSIX headers
        posix_patterns = {
            'unistd.h', 'fcntl.h', 'sys/types.h', 'sys/stat.h', 'sys/wait.h',
            'pthread.h', 'dirent.h', 'pwd.h', 'grp.h', 'sys/socket.h',
            'netinet/in.h', 'arpa/inet.h', 'sys/mman.h'
        }
        
        for header in headers.get('standard_headers', []):
            # Remove < > for comparison
            clean_header = header.strip('<>')
            
            if clean_header in stl_patterns:
                stl_headers.append(header)
            elif clean_header in c_std_patterns:
                c_std_headers.append(header)
            elif clean_header in posix_patterns:
                posix_headers.append(header)
            else:
                other_system_headers.append(header)
        
        result['stl_headers'] = stl_headers
        result['c_std_headers'] = c_std_headers
        result['posix_headers'] = posix_headers
        result['other_system_headers'] = other_system_headers
        
        return result


def get_function_definition_headers(
    project_name: str,
    function_signature: str,
    project_src_dir: Optional[str] = None
) -> Optional[Dict[str, List[str]]]:
    """Get headers from the source file containing a function definition.
    
    This is the main entry point for the header extraction functionality.
    It combines FuzzIntrospector's file path query with tree-sitter header extraction.
    
    Args:
        project_name: Name of the project
        function_signature: Signature of the target function
        project_src_dir: Optional root directory of project source code (DEPRECATED)
    
    Returns:
        Dictionary with extracted headers, or None if function not found
    """
    from data_prep import introspector
    
    # Query FuzzIntrospector for the file path
    logger.info(f'Querying FI for definition file of {function_signature}')
    file_path = introspector.query_introspector_source_file_path(
        project_name,
        function_signature
    )
    
    if not file_path:
        logger.warning(
            f'Could not find definition file for {function_signature} in {project_name}'
        )
        return None
    
    logger.info(f'Function defined in: {file_path}')
    
    # Get the source code content from the container via FuzzIntrospector API
    # Note: We query the entire file (0 to 100000 lines) to get all headers
    source_code = introspector.query_introspector_source_code(
        project_name,
        file_path,
        begin_line=0,
        end_line=100000  # Large enough to capture entire file
    )
    
    if not source_code:
        logger.warning(f'Source file does not exist: {file_path}')
        return {
            'standard_headers': [],
            'project_headers': [],
            'raw_includes': [],
            'definition_file': file_path,
            'full_path': file_path
        }
    
    # Extract headers using tree-sitter from the source content
    extractor = HeaderExtractor()
    headers = extractor._extract_headers_from_content(
        source_code.encode('utf-8'),
        file_path
    )
    
    # Add metadata
    headers['definition_file'] = file_path
    headers['full_path'] = file_path
    
    # Categorize headers for better organization
    headers = extractor.categorize_headers(headers)
    
    return headers


def format_definition_headers_section(
    headers: Optional[Dict[str, List[str]]]
) -> str:
    """Format definition file headers as a comment section for skeleton code.
    
    Args:
        headers: Dictionary returned by get_function_definition_headers()
    
    Returns:
        Formatted string to include in skeleton code
    """
    if not headers:
        return ""
    
    lines = []
    lines.append("//")
    lines.append("// HIGHEST PRIORITY: Headers from function definition file")
    lines.append(f"// Source: {headers.get('definition_file', 'unknown')}")
    lines.append("//")
    
    # Standard headers first
    standard = headers.get('standard_headers', [])
    if standard:
        for header in sorted(set(standard)):
            lines.append(f"#include {header}")
    
    # Then project headers
    project = headers.get('project_headers', [])
    if project:
        if standard:
            lines.append("")  # Blank line between standard and project
        for header in sorted(set(project)):
            lines.append(f"#include {header}")
    
    lines.append("//")
    
    return "\n".join(lines)


class ConstructorExtractor:
    """Extract constructor information from C++ headers using tree-sitter."""
    
    def __init__(self):
        """Initialize the constructor extractor."""
        self.tree_sitter_lang = Language(tree_sitter_cpp.language())
        self.parser = Parser(self.tree_sitter_lang)
    
    def extract_class_constructors(
        self,
        class_name: str,
        header_file: str
    ) -> Dict[str, Any]:
        """
        Extract constructor information from a class in a header file.
        
        Args:
            class_name: Class name (may include namespace, e.g., "Terminal::Framebuffer")
            header_file: Path to header file
        
        Returns:
            {
                'has_default_constructor': bool,
                'constructors': [
                    {
                        'signature': str,
                        'parameters': [{'type': str, 'name': str, 'has_default': bool}],
                        'is_explicit': bool,
                        'is_deleted': bool,
                        'minimal_example': str
                    }
                ],
                'class_qualified_name': str
            }
        """
        if not os.path.exists(header_file):
            logger.warning(f'Header file does not exist: {header_file}')
            return self._empty_constructor_info(class_name)
        
        try:
            with open(header_file, 'rb') as f:
                source_content = f.read()
        except Exception as e:
            logger.error(f'Failed to read header file {header_file}: {e}')
            return self._empty_constructor_info(class_name)
        
        try:
            tree = self.parser.parse(source_content)
            root = tree.root_node
        except Exception as e:
            logger.error(f'Failed to parse header file {header_file}: {e}')
            return self._empty_constructor_info(class_name)
        
        # Find the class declaration
        class_node = self._find_class_declaration(root, class_name, source_content)
        
        if not class_node:
            logger.warning(f'Could not find class {class_name} in {header_file}')
            return self._empty_constructor_info(class_name)
        
        # Extract constructors
        constructor_nodes = self._extract_constructor_nodes(
            class_node, class_name, source_content
        )
        
        constructors = []
        has_default_constructor = False
        
        for ctor_node in constructor_nodes:
            ctor_info = self._parse_constructor(
                ctor_node, class_name, source_content
            )
            
            if ctor_info:
                constructors.append(ctor_info)
                
                # Check if this is a default constructor
                if not ctor_info['is_deleted']:
                    params_without_defaults = [
                        p for p in ctor_info['parameters'] 
                        if not p['has_default']
                    ]
                    if not params_without_defaults:
                        has_default_constructor = True
        
        logger.info(
            f'Found {len(constructors)} constructors for {class_name}, '
            f'has_default: {has_default_constructor}'
        )
        
        return {
            'has_default_constructor': has_default_constructor,
            'constructors': constructors,
            'class_qualified_name': class_name
        }
    
    def _empty_constructor_info(self, class_name: str) -> Dict[str, Any]:
        """Return empty constructor info structure."""
        return {
            'has_default_constructor': False,
            'constructors': [],
            'class_qualified_name': class_name
        }
    
    def _find_class_declaration(
        self,
        root_node: Node,
        class_name: str,
        source_content: bytes
    ) -> Optional[Node]:
        """Find class declaration node in AST."""
        # Handle namespace-qualified class names
        # e.g., "Terminal::Framebuffer" -> ["Terminal", "Framebuffer"]
        name_parts = class_name.split('::')
        target_class = name_parts[-1]
        
        def visit(node: Node) -> Optional[Node]:
            # Look for class_specifier or struct_specifier
            if node.type in ['class_specifier', 'struct_specifier']:
                # Get class name
                for child in node.children:
                    if child.type == 'type_identifier':
                        class_text = source_content[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
                        if class_text == target_class:
                            # Found the class
                            # TODO: verify namespace if needed
                            return node
            
            # Recursively visit children
            for child in node.children:
                result = visit(child)
                if result:
                    return result
            
            return None
        
        return visit(root_node)
    
    def _extract_constructor_nodes(
        self,
        class_node: Node,
        class_name: str,
        source_content: bytes
    ) -> List[Node]:
        """Extract all constructor nodes from a class."""
        constructors = []
        simple_class_name = class_name.split('::')[-1]
        
        # Find field_declaration_list (class body)
        for child in class_node.children:
            if child.type == 'field_declaration_list':
                # Iterate through class members
                for member in child.children:
                    if self._is_constructor(member, simple_class_name, source_content):
                        constructors.append(member)
        
        return constructors
    
    def _is_constructor(
        self,
        node: Node,
        class_name: str,
        source_content: bytes
    ) -> bool:
        """Check if a node is a constructor declaration."""
        if node.type not in ['function_definition', 'declaration', 'field_declaration']:
            return False
        
        # Look for function_declarator
        for child in node.children:
            if child.type == 'function_declarator':
                # Get the function name
                for subchild in child.children:
                    if subchild.type in ['identifier', 'field_identifier']:
                        func_name = source_content[subchild.start_byte:subchild.end_byte].decode('utf-8', errors='ignore')
                        if func_name == class_name:
                            return True
            # Handle direct declarator
            elif child.type in ['identifier', 'field_identifier']:
                func_name = source_content[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
                if func_name == class_name:
                    return True
        
        return False
    
    def _parse_constructor(
        self,
        constructor_node: Node,
        class_name: str,
        source_content: bytes
    ) -> Optional[Dict[str, Any]]:
        """Parse a constructor node to extract its information."""
        is_explicit = False
        is_deleted = False
        parameters = []
        
        # Check for explicit keyword (it's explicit_function_specifier in tree-sitter)
        for child in constructor_node.children:
            if child.type == 'explicit_function_specifier':
                is_explicit = True
        
        # Find function_declarator
        func_declarator = None
        for child in constructor_node.children:
            if child.type == 'function_declarator':
                func_declarator = child
                break
        
        if not func_declarator:
            return None
        
        # Extract parameters
        for child in func_declarator.children:
            if child.type == 'parameter_list':
                parameters = self._parse_parameter_list(child, source_content)
                break
        
        # Check if deleted (= delete) - it's in delete_method_clause
        for child in constructor_node.children:
            if child.type == 'delete_method_clause':
                is_deleted = True
                break
        
        # Generate signature
        param_strs = []
        for param in parameters:
            param_str = param['type']
            if param['name']:
                param_str += f" {param['name']}"
            param_strs.append(param_str)
        
        simple_class_name = class_name.split('::')[-1]
        signature = f"{simple_class_name}({', '.join(param_strs)})"
        
        # Generate minimal example
        minimal_example = self._generate_minimal_constructor_call(
            class_name, parameters
        )
        
        return {
            'signature': signature,
            'parameters': parameters,
            'is_explicit': is_explicit,
            'is_deleted': is_deleted,
            'minimal_example': minimal_example
        }
    
    def _parse_parameter_list(
        self,
        param_list_node: Node,
        source_content: bytes
    ) -> List[Dict[str, Any]]:
        """Parse parameter list node."""
        parameters = []
        
        for child in param_list_node.children:
            # Handle both parameter_declaration and optional_parameter_declaration
            if child.type in ['parameter_declaration', 'optional_parameter_declaration']:
                param_info = self._parse_parameter_declaration(child, source_content)
                if param_info:
                    parameters.append(param_info)
        
        return parameters
    
    def _parse_parameter_declaration(
        self,
        param_node: Node,
        source_content: bytes
    ) -> Optional[Dict[str, Any]]:
        """Parse a single parameter declaration."""
        param_type = ""
        param_name = ""
        has_default = False
        
        # Check if this is an optional_parameter_declaration (has default)
        if param_node.type == 'optional_parameter_declaration':
            has_default = True
        
        # Extract type
        type_parts = []
        identifier_node = None
        
        for child in param_node.children:
            if child.type in ['type_identifier', 'primitive_type', 'qualified_identifier']:
                type_parts.append(source_content[child.start_byte:child.end_byte].decode('utf-8', errors='ignore'))
            elif child.type in ['const', 'volatile', 'unsigned', 'signed', 'type_qualifier']:
                # type_qualifier contains const/volatile
                if child.type == 'type_qualifier':
                    for subchild in child.children:
                        if subchild.type in ['const', 'volatile']:
                            type_parts.append(source_content[subchild.start_byte:subchild.end_byte].decode('utf-8', errors='ignore'))
                else:
                    type_parts.append(source_content[child.start_byte:child.end_byte].decode('utf-8', errors='ignore'))
            elif child.type in ['pointer_declarator', 'reference_declarator', 'abstract_pointer_declarator', 'abstract_reference_declarator']:
                # Handle pointer/reference in type
                self._extract_type_from_declarator(child, type_parts, source_content)
            elif child.type in ['identifier', 'field_identifier']:
                identifier_node = child
                param_name = source_content[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
            elif child.type == 'default_value' or child.type == '=':
                has_default = True
        
        param_type = ' '.join(type_parts).strip()
        
        if not param_type:
            return None
        
        return {
            'type': param_type,
            'name': param_name or '',
            'has_default': has_default
        }
    
    def _extract_type_from_declarator(
        self,
        declarator_node: Node,
        type_parts: List[str],
        source_content: bytes
    ) -> None:
        """Extract type information from a declarator node."""
        for child in declarator_node.children:
            if child.type in ['type_identifier', 'primitive_type', 'qualified_identifier']:
                type_parts.append(source_content[child.start_byte:child.end_byte].decode('utf-8', errors='ignore'))
            elif child.type in ['*', '&', '&&']:
                type_parts.append(source_content[child.start_byte:child.end_byte].decode('utf-8', errors='ignore'))
            elif child.type in ['pointer_declarator', 'reference_declarator']:
                self._extract_type_from_declarator(child, type_parts, source_content)
    
    def _generate_minimal_constructor_call(
        self,
        class_name: str,
        parameters: List[Dict[str, Any]]
    ) -> str:
        """Generate minimal constructor call example."""
        if not parameters:
            return f"{class_name}()"
        
        # Generate minimal values for each parameter
        args = []
        for param in parameters:
            if param['has_default']:
                # If it has a default value, we can omit it
                continue
            
            param_type = param['type'].lower()
            
            # Generate minimal value based on type
            if any(t in param_type for t in ['int', 'size', 'long', 'short']):
                args.append('1')
            elif any(t in param_type for t in ['float', 'double']):
                args.append('1.0')
            elif 'bool' in param_type:
                args.append('false')
            elif 'string' in param_type:
                args.append('""')
            elif 'char' in param_type and '*' not in param['type']:
                args.append("'\\0'")
            elif '*' in param['type'] or '&' in param['type']:
                # For pointers/references, we might need actual objects
                if '*' in param['type']:
                    args.append('nullptr')
                else:
                    # Reference needs actual object - this is tricky
                    base_type = param['type'].replace('&', '').replace('const', '').strip()
                    args.append(f'{base_type}()')
            else:
                # For other types, try default construction
                base_type = param['type'].replace('const', '').replace('&', '').replace('*', '').strip()
                args.append(f'{base_type}()')
        
        return f"{class_name}({', '.join(args)})"


def get_class_constructor_info(
    project_name: str,
    class_name: str,
    header_file: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Get constructor information for a class.
    
    Args:
        project_name: Name of the project
        class_name: Fully qualified class name (e.g., "Terminal::Framebuffer")
        header_file: Optional header file path. If not provided, will try to find it.
    
    Returns:
        Dictionary with constructor information, or None if not found
    """
    if not header_file:
        # Try to find the header file
        # This would need FuzzIntrospector integration or heuristics
        logger.warning(f'Header file not provided for {class_name}')
        return None
    
    extractor = ConstructorExtractor()
    return extractor.extract_class_constructors(class_name, header_file)

