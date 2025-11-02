#!/usr/bin/env python3
"""
API Validator - Detects internal/private API usage in generated fuzz targets.

This module helps prevent LLM from using internal APIs that are not available
in the OSS-Fuzz build environment by scanning generated code for known patterns.
"""

import re
import logging
from typing import List, Dict, Tuple, Set

logger = logging.getLogger(__name__)


class APIValidator:
    """Validates that generated code uses only public APIs."""
    
    # Pattern categories
    INTERNAL_FUNCTION_PATTERNS = [
        # Functions with internal/impl/detail suffixes
        r'\b\w+_internal\s*\(',
        r'\b\w+_impl\s*\(',
        r'\b\w+_detail\s*\(',
        r'\b\w+_private\s*\(',
        
        # Functions starting with underscore (C convention)
        r'\b_[a-z]\w+\s*\(',
        
        # Common internal helper patterns
        r'\b\w+_get_default\s*\(',
        r'\b\w+_default\s*\(',
        r'\bdefault_\w+\s*\(',
        
        # Internal state/context getters
        r'\bget_internal_\w+\s*\(',
        r'\bset_internal_\w+\s*\(',
    ]
    
    INTERNAL_HEADER_PATTERNS = [
        # Internal directories
        r'#include\s*[<"].*internal/',
        r'#include\s*[<"].*private/',
        r'#include\s*[<"].*detail/',
        r'#include\s*[<"].*impl/',
        r'#include\s*[<"].*implementation/',
        
        # Internal suffixes
        r'#include\s*[<"].*_impl\.h[">]',
        r'#include\s*[<"].*_detail\.h[">]',
        r'#include\s*[<"].*_internal\.h[">]',
        r'#include\s*[<"].*_private\.h[">]',
        
        # Deep relative paths (likely internal)
        r'#include\s*"\.\.\/\.\.\/\.\.+/',
    ]
    
    THIRD_PARTY_HEADER_PATTERNS = [
        # Known third-party libraries
        r'#include\s*<cs/cs\.h>',
        r'#include\s*<cs\.h>',
        r'#include\s*<suitesparse/',
        r'#include\s*<boost/',
        r'#include\s*<eigen/',
        
        # Testing frameworks
        r'#include\s*<gtest/',
        r'#include\s*<gmock/',
        r'#include\s*<catch2/',
        r'#include\s*<doctest/',
        
        # Benchmarking
        r'#include\s*<benchmark/',
        
        # Configuration headers
        r'#include\s*[<"]config\.h[">]',
        r'#include\s*[<"]version\.h[">]',
    ]
    
    DIRECT_STRUCT_ACCESS_PATTERNS = [
        # Direct member access (may be private)
        r'\w+\s*->\s*\w+\s*=',  # obj->member = value
        r'\w+\.\w+\s*=',         # obj.member = value
    ]
    
    def __init__(self):
        """Initialize the validator."""
        # Compile regex patterns for efficiency
        self.internal_func_re = [re.compile(p) for p in self.INTERNAL_FUNCTION_PATTERNS]
        self.internal_header_re = [re.compile(p) for p in self.INTERNAL_HEADER_PATTERNS]
        self.third_party_header_re = [re.compile(p) for p in self.THIRD_PARTY_HEADER_PATTERNS]
        self.struct_access_re = [re.compile(p) for p in self.DIRECT_STRUCT_ACCESS_PATTERNS]
        
        # Whitelist: common patterns that are actually OK
        self.function_whitelist = {
            '__attribute__',
            '_Generic',  # C11 generic macro
        }
        
        self.struct_access_whitelist = {
            'data', 'size',  # Common fuzzer input variables
            'length', 'len',
            'ptr', 'buf',
        }
    
    def validate_code(self, code: str, project_name: str = None) -> Dict[str, List[Dict]]:
        """Validate generated fuzz target code.
        
        Args:
            code: Generated C/C++ code
            project_name: Optional project name for project-specific rules
        
        Returns:
            Dictionary with validation results:
            {
                'issues': [
                    {
                        'category': 'internal_function',
                        'severity': 'high',
                        'pattern': 'igraph_arpack_options_get_default',
                        'line_number': 42,
                        'line': 'options = igraph_arpack_options_get_default();',
                        'suggestion': 'Use igraph_arpack_options_init() instead'
                    },
                    ...
                ],
                'clean': bool  # True if no issues
            }
        """
        issues = []
        lines = code.split('\n')
        
        # Check for internal function calls
        issues.extend(self._check_internal_functions(lines))
        
        # Check for internal headers
        issues.extend(self._check_internal_headers(lines))
        
        # Check for third-party headers
        issues.extend(self._check_third_party_headers(lines))
        
        # Check for direct struct access (less strict, just warnings)
        issues.extend(self._check_struct_access(lines))
        
        return {
            'issues': issues,
            'clean': len([i for i in issues if i['severity'] == 'high']) == 0
        }
    
    def _check_internal_functions(self, lines: List[str]) -> List[Dict]:
        """Check for internal function calls."""
        issues = []
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('/*'):
                continue
            
            for pattern_re in self.internal_func_re:
                matches = pattern_re.finditer(line)
                for match in matches:
                    func_name = match.group(0).strip('( ')
                    
                    # Check whitelist
                    if func_name in self.function_whitelist:
                        continue
                    
                    issues.append({
                        'category': 'internal_function',
                        'severity': 'high',
                        'pattern': func_name,
                        'line_number': line_num,
                        'line': line.strip(),
                        'suggestion': self._suggest_function_fix(func_name)
                    })
        
        return issues
    
    def _check_internal_headers(self, lines: List[str]) -> List[Dict]:
        """Check for internal header includes."""
        issues = []
        
        for line_num, line in enumerate(lines, 1):
            for pattern_re in self.internal_header_re:
                if pattern_re.search(line):
                    issues.append({
                        'category': 'internal_header',
                        'severity': 'high',
                        'pattern': line.strip(),
                        'line_number': line_num,
                        'line': line.strip(),
                        'suggestion': 'Remove this header and use public API headers instead'
                    })
        
        return issues
    
    def _check_third_party_headers(self, lines: List[str]) -> List[Dict]:
        """Check for third-party dependency headers."""
        issues = []
        
        for line_num, line in enumerate(lines, 1):
            for pattern_re in self.third_party_header_re:
                if pattern_re.search(line):
                    issues.append({
                        'category': 'third_party_header',
                        'severity': 'high',
                        'pattern': line.strip(),
                        'line_number': line_num,
                        'line': line.strip(),
                        'suggestion': 'Remove third-party dependency header - not available in OSS-Fuzz'
                    })
        
        return issues
    
    def _check_struct_access(self, lines: List[str]) -> List[Dict]:
        """Check for direct struct member access (may access private members)."""
        issues = []
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and type declarations
            if line.strip().startswith('//') or \
               line.strip().startswith('/*') or \
               'typedef' in line or \
               'struct' in line:
                continue
            
            for pattern_re in self.struct_access_re:
                matches = pattern_re.finditer(line)
                for match in matches:
                    # Extract member name
                    member_match = re.search(r'(\w+)\s*=', match.group(0))
                    if member_match:
                        member_name = member_match.group(1)
                        
                        # Check whitelist
                        if member_name in self.struct_access_whitelist:
                            continue
                        
                        issues.append({
                            'category': 'direct_struct_access',
                            'severity': 'medium',  # Less severe, may be OK
                            'pattern': match.group(0).strip(),
                            'line_number': line_num,
                            'line': line.strip(),
                            'suggestion': f'Consider using public setter/getter for member "{member_name}"'
                        })
        
        return issues
    
    def _suggest_function_fix(self, func_name: str) -> str:
        """Suggest a fix for internal function usage."""
        if '_get_default' in func_name:
            base = func_name.replace('_get_default', '')
            return f'Use {base}_init() instead for initialization'
        elif '_default' in func_name:
            return 'Look for public initialization functions (e.g., *_init, *_create)'
        elif func_name.startswith('_'):
            return f'Internal function - find public equivalent in existing fuzzers'
        elif '_internal' in func_name or '_impl' in func_name:
            return 'This is an internal implementation - use public API from existing fuzzers'
        else:
            return 'Replace with public API function from existing fuzzers or headers'
    
    def format_validation_report(self, validation_result: Dict) -> str:
        """Format validation results as a human-readable report.
        
        Args:
            validation_result: Result from validate_code()
        
        Returns:
            Formatted string report
        """
        issues = validation_result['issues']
        
        if not issues:
            return "✅ Code validation passed - no internal API usage detected"
        
        # Group issues by severity
        high_severity = [i for i in issues if i['severity'] == 'high']
        medium_severity = [i for i in issues if i['severity'] == 'medium']
        
        lines = [
            "⚠️  Code Validation Issues Detected",
            ""
        ]
        
        if high_severity:
            lines.extend([
                f"## 🔴 HIGH SEVERITY ({len(high_severity)} issues)",
                "",
                "These MUST be fixed - they will cause compilation errors:",
                ""
            ])
            
            for issue in high_severity[:10]:  # Limit to 10
                lines.append(f"**Line {issue['line_number']}**: {issue['category']}")
                lines.append(f"  ❌ `{issue['pattern']}`")
                lines.append(f"  💡 {issue['suggestion']}")
                lines.append("")
        
        if medium_severity:
            lines.extend([
                f"## 🟡 MEDIUM SEVERITY ({len(medium_severity)} issues)",
                "",
                "These may cause issues - review carefully:",
                ""
            ])
            
            for issue in medium_severity[:5]:  # Limit to 5
                lines.append(f"**Line {issue['line_number']}**: {issue['category']}")
                lines.append(f"  ⚠️  `{issue['pattern']}`")
                lines.append(f"  💡 {issue['suggestion']}")
                lines.append("")
        
        return '\n'.join(lines)


def validate_fuzz_target(code: str, project_name: str = None) -> Tuple[bool, str]:
    """Convenience function to validate fuzz target code.
    
    Args:
        code: Generated C/C++ fuzz target code
        project_name: Optional project name
    
    Returns:
        Tuple of (is_valid: bool, report: str)
    """
    validator = APIValidator()
    result = validator.validate_code(code, project_name)
    report = validator.format_validation_report(result)
    
    return result['clean'], report


# Example usage
if __name__ == '__main__':
    test_code = '''
#include <igraph/igraph.h>
#include "../../internal/libraw_cxx_defs.h"  // Internal!
#include <cs/cs.h>  // Third-party!

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    igraph_arpack_options_t *options = igraph_arpack_options_get_default();  // Internal!
    options->maxiter = 100;  // Direct access!
    
    _internal_helper(data, size);  // Internal!
    
    return 0;
}
'''
    
    is_valid, report = validate_fuzz_target(test_code, 'igraph')
    print(report)
    print(f"\nValidation result: {'PASS' if is_valid else 'FAIL'}")

