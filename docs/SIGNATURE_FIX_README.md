# Function Signature Resolution Fix

## Problems

FuzzIntrospector API queries were failing due to two types of function signature mismatches:

### Problem 1: Missing Parameter Names

When querying FuzzIntrospector API for function information, Logic-Fuzz was using incomplete function signatures (without parameter names) from YAML benchmark files. However, FuzzIntrospector stores function signatures with full parameter names, causing query failures. 

**Example:**

**YAML file signature (incomplete):**

```
void LibRaw::crxLoadDecodeLoop(void *, int)
```

**FuzzIntrospector database signature (complete):**

```
void LibRaw::crxLoadDecodeLoop(void *img, int nPlanes)
```

### Problem 2: C++ Type Name Format Variations

FuzzIntrospector's different API endpoints return C++ type names in inconsistent formats:

- **Cross-references API** returns compact type names: `unsignedlong`, `unsignedint` (no spaces)
- **Function signature API** expects standard C++ syntax: `unsigned long`, `unsigned int` (with spaces)

This caused signature lookup failures when querying caller function signatures.

**Example:**

**Cross-references API returns:**
```
Terminal::Emulator::resize(unsignedlong,unsignedlong)
```

**Function signature API expects:**
```
Terminal::Emulator::resize(unsigned long,unsigned long)
```

Both mismatches caused errors like:
```
Could not find function
```

## Solutions

### Solution 1: Parameter Name Resolution (Original Fix)

Modified five functions in `data_prep/introspector.py`:

1. **`query_introspector_source_file_path()`** - Gets source file path for a function
2. **`query_introspector_function_source()`** - Gets function source code
3. **`query_introspector_function_line()`** - Gets function line numbers
4. **`query_introspector_sample_xrefs()`** - Gets sample cross-references

Additionally, added a helper function:
5. **`_extract_function_name_from_signature()`** - Extracts function name from signature

These query functions implement a **parameter name fallback mechanism**:

1. First, try to query with the provided signature
2. If query fails (returns empty result):
   - Extract function name from signature
   - Query FuzzIntrospector's `/api/function-signature` to get full signature
   - Retry query with the complete signature

### Solution 2: C++ Type Name Normalization (New Fix)

Modified `query_introspector_function_signature()` and added a new helper function:

1. **`_normalize_cpp_types()`** - Normalizes C++ type names in function signatures
2. **`query_introspector_function_signature()`** - Enhanced with type normalization fallback

The normalization function handles these type variations:
- `unsignedlong` → `unsigned long`
- `unsignedint` → `unsigned int`
- `unsignedshort` → `unsigned short`
- `unsignedchar` → `unsigned char`
- `longlong` → `long long`
- `longdouble` → `long double`
- `signedchar` → `signed char`
- `signedint` → `signed int`
- `signedshort` → `signed short`
- `signedlong` → `signed long`

The enhanced `query_introspector_function_signature()` implements a **type normalization fallback**:

1. First, try to query with the provided function name
2. If query fails (returns empty result):
   - Normalize C++ type names (add spaces to compound types)
   - Retry query with the normalized function name

### Code Changes

The fix adds automatic signature resolution without modifying:
- ✅ FuzzIntrospector code (remains as-is, "out of the box")
- ✅ YAML benchmark files (no changes needed)
- ✅ Logic-Fuzz workflow (transparent to users)

## Testing

### Prerequisites

1. Ensure FuzzIntrospector service is running:
   ```bash
   # Check if service is running
   curl -s http://0.0.0.0:8080/api/project-summary?project=libraw | head -20
   ```

2. If not running, start it (refer to Logic-Fuzz documentation)

### Run Test Scripts

**Test 1: Parameter name resolution fix**
```bash
python3 test_signature_fix.py
```

Expected output:
```
================================================================================
Test 1: Query with incomplete signature (no parameter names)
================================================================================
Project: libraw
Incomplete signature: void LibRaw::crxLoadDecodeLoop(void *, int)

Querying FuzzIntrospector for function source...
✓ SUCCESS! Got source code (XXX chars)

First 300 characters of source:
--------------------------------------------------------------------------------
[Function source code here]
--------------------------------------------------------------------------------

================================================================================
Test 2: Query for function line numbers
================================================================================
Querying FuzzIntrospector for function line numbers...
✓ SUCCESS! Got line info: [XXX, YYY]
  Function starts at line: XXX
  Function ends at line: YYY

================================================================================
All tests passed! ✓
================================================================================
```

**Test 2: C++ type name normalization fix**
```bash
python3 test_type_normalization.py
```

Expected output:
```
================================================================================
Test _normalize_cpp_types Function
================================================================================
✓ "resize(unsignedlong,unsignedlong)" -> "resize(unsigned long,unsigned long)"
✓ "func(unsignedint)" -> "func(unsigned int)"
✓ "process(unsignedshort,unsignedchar)" -> "process(unsigned short,unsigned char)"
✓ "calculate(longlong)" -> "calculate(long long)"
✓ "convert(longdouble)" -> "convert(long double)"

================================================================================
C++ Type Name Normalization Test
================================================================================
Simulating cross-references API returning function with compact type names...

Testing normalization on simulated function names:
  ✓ SomeClass::method(unsignedint,unsignedlong)
      -> SomeClass::method(unsigned int,unsigned long)
  ✓ resize(unsignedlong,unsignedlong)
      -> resize(unsigned long,unsigned long)
  ...

Testing API integration with libraw project...
  ✓ Successfully queried signature: void LibRaw::crxLoadDecodeLoop(void *img, int nPlanes)

================================================================================
Test Summary
================================================================================
✓ All tests passed!
```

## Implementation Details

### Function Name Extraction (Solution 1)

The fix includes a helper function `_extract_function_name_from_signature()` that uses regex to extract function names from C++ signatures:

```python
def _extract_function_name_from_signature(func_sig: str) -> str:
    """Extracts the function name from a function signature.
    
    Args:
        func_sig: Function signature like "void LibRaw::crxLoadDecodeLoop(void *, int)"
    
    Returns:
        Function name like "LibRaw::crxLoadDecodeLoop", or empty string if extraction fails.
    """
    import re
    # Match pattern: [return_type] [namespace::]*function_name(params)
    match = re.search(r'[\w:]+\([^)]*\)', func_sig)
    if match:
        func_name_with_params = match.group(0)
        func_name = func_name_with_params.split('(')[0]
        return func_name
    return ''
```

This helper function is reused across all query functions to avoid code duplication.

### C++ Type Name Normalization (Solution 2)

The fix includes a helper function `_normalize_cpp_types()` that standardizes C++ type names:

```python
def _normalize_cpp_types(function_name: str) -> str:
    """Normalizes C++ type names in a function signature or name.
    
    FuzzIntrospector APIs may return type names in different formats:
    - Cross-references API: "unsignedlong", "unsignedint" (no spaces)
    - Function signature API: "unsigned long", "unsigned int" (with spaces)
    
    This function standardizes type names to the format with spaces.
    
    Args:
        function_name: Function name or signature like "resize(unsignedlong,unsignedlong)"
    
    Returns:
        Normalized function name like "resize(unsigned long,unsigned long)"
    """
    import re
    
    # Map of common C++ type variations (without space -> with space)
    type_mappings = [
        (r'\bunsignedlong\b', 'unsigned long'),
        (r'\bunsignedint\b', 'unsigned int'),
        (r'\bunsignedshort\b', 'unsigned short'),
        (r'\bunsignedchar\b', 'unsigned char'),
        (r'\blonglong\b', 'long long'),
        (r'\blongunsigned\b', 'unsigned long'),
        (r'\blongdouble\b', 'long double'),
        (r'\bsignedchar\b', 'signed char'),
        (r'\bsignedint\b', 'signed int'),
        (r'\bsignedshort\b', 'signed short'),
        (r'\bsignedlong\b', 'signed long'),
    ]
    
    normalized = function_name
    for pattern, replacement in type_mappings:
        normalized = re.sub(pattern, replacement, normalized)
    
    return normalized
```

This normalization function is used by `query_introspector_function_signature()` to handle type name variations.

### Signature Resolution Flows

**Flow 1: Parameter Name Resolution**
```
User Query with Incomplete Signature (missing parameter names)
    ↓
Try Direct Query to FuzzIntrospector
    ↓
    ├─ Success → Return Result
    │
    └─ Failure (empty result)
        ↓
    Extract Function Name
        ↓
    Query FuzzIntrospector for Full Signature
        ↓
    Retry with Complete Signature
        ↓
    Return Result
```

**Flow 2: Type Name Normalization**
```
User Query with Compact Type Names (e.g., "unsignedlong")
    ↓
Try Direct Query to FuzzIntrospector
    ↓
    ├─ Success → Return Result
    │
    └─ Failure (empty result)
        ↓
    Normalize C++ Type Names (add spaces)
        ↓
    Retry Query with Normalized Function Name
        ↓
    Return Result
```

## Benefits

1. **Backward Compatible**: Works with existing YAML files and FuzzIntrospector data
2. **No FuzzIntrospector Changes**: Uses existing API endpoints without modifications
3. **Transparent**: Users don't need to know about signature format differences
4. **Robust**: Automatically handles both parameter name mismatches and type name variations
5. **Comprehensive**: Covers multiple signature mismatch scenarios
6. **Logging**: Provides clear log messages for debugging
7. **Minimal Performance Impact**: Fallback mechanisms only trigger when initial query fails

## Affected Files

- `data_prep/introspector.py` - Core fix implementation (both solutions)
- `test_signature_fix.py` - Test script for parameter name resolution
- `test_type_normalization.py` - Test script for type name normalization
- `debug_fi_functions.py` - Debugging utility to explore FI function signatures
- `docs/SIGNATURE_FIX_README.md` - This documentation

## Future Considerations

These fixes bridge compatibility gaps in FuzzIntrospector's API. They may become unnecessary if:

1. **Parameter Name Resolution**: FuzzIntrospector implements fuzzy signature matching that ignores parameter names
2. **Type Name Normalization**: FuzzIntrospector standardizes type name formats across all API endpoints
3. **Unified API**: FuzzIntrospector provides a unified query API that handles signature variations internally

Until then, these fixes ensure robust and reliable function signature queries across different FuzzIntrospector API endpoints.

