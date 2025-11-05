#!/usr/bin/env python3
"""
Shared heuristics and constants for API analysis.

This module provides common heuristics used across multiple API analysis components
to avoid code duplication and ensure consistency.
"""

# ==============================================================================
# Function Naming Patterns
# ==============================================================================

# Initialization function suffixes (used to identify constructor/init functions)
INIT_SUFFIXES = [
    '_init',
    '_create', 
    '_new',
    '_alloc',
    '_setup',
    '_open'
]

# Cleanup function suffixes (used to identify destructor/cleanup functions)
CLEANUP_SUFFIXES = [
    '_destroy',
    '_free',
    '_delete',
    '_cleanup',
    '_close',
    '_release',
    '_deinit',
    '_fini'
]

# ==============================================================================
# Type Analysis Patterns
# ==============================================================================

# Type name keywords that typically require initialization
# (e.g., "igraph_storage_t", "http_context", "buffer_state")
INIT_REQUIRED_KEYWORDS = [
    'storage',
    'context',
    'state',
    'buffer',
    'data',
    'cache',
    'pool',
    'arena'
]

# Primitive types (no initialization needed)
PRIMITIVE_TYPES = {
    'int', 'char', 'short', 'long', 'float', 'double',
    'void', 'bool', 'size_t', 'ssize_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uintptr_t', 'intptr_t', 'ptrdiff_t'
}

# ==============================================================================
# Utility Functions
# ==============================================================================

def is_primitive_type(type_name: str) -> bool:
    """
    Check if a type is a primitive type (no initialization needed).
    
    Args:
        type_name: Type name (cleaned, without modifiers)
    
    Returns:
        True if type is primitive, False otherwise
    
    Examples:
        >>> is_primitive_type('int')
        True
        >>> is_primitive_type('igraph_t')
        False
    """
    return type_name in PRIMITIVE_TYPES


def clean_type_name(type_str: str) -> str:
    """
    Clean type string by removing modifiers (const, *, &, etc.).
    
    Args:
        type_str: Raw type string (e.g., "const igraph_t *")
    
    Returns:
        Cleaned type name (e.g., "igraph_t")
    
    Examples:
        >>> clean_type_name("const igraph_t *")
        'igraph_t'
        >>> clean_type_name("struct my_struct &")
        'my_struct'
    """
    import re
    
    # Remove const, volatile, *, &
    cleaned = type_str.replace('const', '').replace('volatile', '')
    cleaned = cleaned.replace('*', '').replace('&', '').strip()
    
    # Remove struct/enum/union prefix
    cleaned = re.sub(r'^(struct|enum|union)\s+', '', cleaned)
    
    return cleaned


def requires_initialization(param_type: str, param: dict) -> bool:
    """
    Check if a parameter requires explicit initialization.
    
    Args:
        param_type: Cleaned parameter type
        param: Parameter info dict with 'type' and 'name' keys
    
    Returns:
        True if parameter needs initialization, False otherwise
    
    Examples:
        >>> requires_initialization('igraph_storage_t', {'type': 'igraph_storage_t *', 'name': 'store'})
        True
        >>> requires_initialization('int', {'type': 'int', 'name': 'count'})
        False
    """
    # Rule 1: Type name contains initialization keywords
    type_lower = param_type.lower()
    if any(kw in type_lower for kw in INIT_REQUIRED_KEYWORDS):
        return True
    
    # Rule 2: Output parameter (pointer type, not const) + non-primitive type
    if '*' in param['type'] and 'const' not in param['type']:
        if not is_primitive_type(param_type):
            return True
    
    return False


def get_base_name_from_type(param_type: str) -> str:
    """
    Extract base name from a type (for finding related functions).
    
    Args:
        param_type: Type name (e.g., "igraph_storage_t")
    
    Returns:
        Base name without suffix (e.g., "igraph_storage")
    
    Examples:
        >>> get_base_name_from_type('igraph_storage_t')
        'igraph_storage'
        >>> get_base_name_from_type('struct my_buffer')
        'my_buffer'
    """
    # Remove _t suffix (common in C)
    base_name = param_type.replace('_t', '')
    
    # Remove struct/enum/union prefix
    base_name = base_name.replace('struct ', '').replace('enum ', '').replace('union ', '')
    
    return base_name.strip()

