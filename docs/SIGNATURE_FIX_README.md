# Function Signature Resolution Fix

## Problem

When querying FuzzIntrospector API for function information, Logic-Fuzz was using incomplete function signatures (without parameter names) from YAML benchmark files. However, FuzzIntrospector stores function signatures with full parameter names, causing query failures. 

### Example

**YAML file signature (incomplete):**

```
void LibRaw::crxLoadDecodeLoop(void *, int)
```

**FuzzIntrospector database signature (complete):**

```
void LibRaw::crxLoadDecodeLoop(void *img, int nPlanes)
```

This mismatch caused errors like:
```
Could not find function
```

## Solution

Modified five functions in `data_prep/introspector.py`:

1. **`query_introspector_source_file_path()`** - Gets source file path for a function
2. **`query_introspector_function_source()`** - Gets function source code
3. **`query_introspector_function_line()`** - Gets function line numbers
4. **`query_introspector_sample_xrefs()`** - Gets sample cross-references

Additionally, added a helper function:
5. **`_extract_function_name_from_signature()`** - Extracts function name from signature

All query functions now implement a **fallback mechanism**:

1. First, try to query with the provided signature
2. If query fails (returns empty result):
   - Extract function name from signature
   - Query FuzzIntrospector's `/api/function-signature` to get full signature
   - Retry query with the complete signature

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

### Run Test Script

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

## Implementation Details

### Function Name Extraction

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

### Signature Resolution Flow

```
User Query with Incomplete Signature
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

## Benefits

1. **Backward Compatible**: Works with existing YAML files
2. **No FuzzIntrospector Changes**: Uses existing API endpoints
3. **Transparent**: Users don't need to know about signature differences
4. **Robust**: Automatically handles parameter name mismatches
5. **Logging**: Provides clear log messages for debugging

## Affected Files

- `data_prep/introspector.py` - Core fix implementation
- `test_signature_fix.py` - Test script
- `SIGNATURE_FIX_README.md` - This documentation

## Future Considerations

If FuzzIntrospector ever changes its signature storage format or adds fuzzy matching capabilities, this fix can be removed. For now, it bridges the gap between incomplete and complete function signatures.

