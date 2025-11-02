# API Analyzer for conti-benchmark

A unified tool for analyzing and managing valueless APIs in conti-benchmark YAML files.

## Overview

This tool identifies APIs that are unsuitable as fuzzing targets and optionally removes them from YAML files.

## Quick Start

```bash
# Analyze and generate JSON report
python3 api_analyzer.py --analyze

# Preview which APIs would be removed (dry-run)
python3 api_analyzer.py --analyze --remove --dry-run

# Analyze and remove valueless APIs (with confirmation prompt)
python3 api_analyzer.py --analyze --remove

# Specify custom output file
python3 api_analyzer.py --analyze --output my_report.json
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--analyze` | `-a` | Analyze YAML files for valueless APIs |
| `--remove` | `-r` | Remove valueless APIs from YAML files (requires `--analyze`) |
| `--dry-run` | | Preview removal without modifying files (use with `--remove`) |
| `--output` | `-o` | Output JSON file path (default: `api_analysis_report.json`) |
| `--dir` | `-d` | Benchmark directory path (default: auto-detect) |

## Valueless API Classification

The tool identifies the following types of APIs as valueless for fuzzing:

### 1. C++ Internal Implementation Details

**Anonymous Namespace Functions**
- **Pattern**: Contains `_GLOBAL__N_`
- **Reason**: Internal compiler-generated symbols, not part of public API
- **Example**: `_GLOBAL__N_1::helper_function`

**Lambda Expressions**
- **Pattern**: Contains `$_` followed by digits
- **Reason**: Anonymous lambda functions, not stable API surface
- **Example**: `MyClass::process()::$_0`

**Destructor Functions**
- **Pattern**: Starts with `~` or matches destructor mangling pattern
- **Reason**: Implicitly called by compiler, not directly fuzzable
- **Example**: `~MyClass()`, `_ZN7MyClassD1Ev`

### 2. Memory Management Functions

**Keywords**: `_alloc`, `_free`, `finalize`, `destroy`, `_cleanup`, `_release`, `_dispose`

- **Reason**: Low-level memory operations that require specific calling contexts
- **Risk**: Calling in isolation often leads to crashes or undefined behavior
- **Note**: Keywords now use underscore prefix to avoid false positives
- **Exceptions**: Functions containing "freeze" are not filtered (e.g., `FreezeImage`)
- **Examples**:
  - `af_gb_alloc_data` - internal allocation
  - `argon2_finalize` - cleanup function
  - `custom_object_release` - resource deallocation

### 3. Internal Helper Functions

**Keywords**: `_init`, `_copy`, `_clone`, `_reset`

- **Reason**: Auxiliary functions meant to be called by other public APIs
- **Risk**: May require specific pre-conditions or object states
- **Note**: Reduced keyword list to avoid filtering legitimate APIs
- **Examples**:
  - `_init_context` - initialization helper
  - `_copy_metadata` - internal copy operation

### 4. Test/Mock Functions

**Keywords**: `mock`, `stub`, `test_`, `fake`, `dummy`

- **Reason**: Testing infrastructure, not production code
- **Examples**:
  - `mock_request_handler` - mock for testing
  - `test_parse_data` - test function
  - `fake_network_client` - test double

### 5. Private/Internal APIs

**Keywords**: `_internal`, `_private`, `_impl`, `_priv`

- **Reason**: Explicitly marked as internal implementation details
- **Note**: Double underscore (`__`) removed to avoid false positives with compiler attributes
- **Additional Check**: Single underscore prefix (`_functionName`) also filtered
- **Examples**:
  - `_parse_internal` - single underscore prefix
  - `process_data_internal` - internal API
  - `_private_validate` - private method

### 6. Parameterless Functions

**C++ Parameterless Member Methods**
- **Pattern**: Only parameter is `this` pointer
- **Reason**: Typically used for internal state access (getters) or state management
- **Risk**: Limited fuzzing value without input variation
- **Example**: `MyClass::getCurrentState()` (only has implicit `this`)

**Functions with No Parameters**
- **Pattern**: Zero parameters
- **Reason**: Usually stateless utilities or state management functions
- **Risk**: Cannot fuzz input space
- **Example**: `initialize_global_state()`

### 7. Opaque State Handlers (NEW - Replaces low_level_decoder)

**Pattern**: Functions with `void*` parameter AND specific indicators

**State Indicators in Parameter Name**: `state`, `context`, `ctx`, `handle`, `priv`, `internal`, `opaque`
- **Example**: `process_data(void *state, uint8_t *data, size_t size)`
- **Reason**: `void* state` indicates internal opaque state structure

**Sub-Component Indicators in Function Name**: `plane`, `iteration`, `band`
- **Example**: `LibRaw::crxDecodePlane(void *plane, uint32_t idx)`
- **Reason**: Processes internal sub-components, not full input

**Key Improvement**: 
- ❌ OLD: Filtered all functions with keywords like `block`, `chunk`, `decode`, `parse`
- ✅ NEW: Only filters when `void*` parameter suggests opaque internal state
- ✅ **Preserves**: `jpeg_decode_block()`, `png_read_chunk()`, `WebPDecode()` - these are excellent fuzzing targets!

## Output Format

### JSON Report Structure

```json
{
  "summary": {
    "total_projects": 34,
    "total_apis": 44,
    "valueless_apis": 10,
    "valuable_apis": 34,
    "valueless_percentage": 22.73
  },
  "valueless_api_rules": {
    "anonymous_namespace": "C++ anonymous namespace internal function",
    "lambda_expression": "C++ lambda expression",
    "memory_management": "Internal memory management function",
    "internal_helper": "Internal helper/utility function",
    "mock_test": "Mock/Test/Stub function",
    "destructor": "Destructor function",
    "private_internal": "Private/internal method"
  },
  "valueless_apis_by_project": {
    "libraw": [
      {
        "file": "comparison/libraw.yaml",
        "api": "LibRaw::crxDecodePlane",
        "signature": "void LibRaw::crxDecodePlane(void *, uint32_t)",
        "reasons": [
          "C++ parameterless member method (likely internal state access)"
        ]
      }
    ]
  },
  "all_files": [
    {
      "file": "comparison/libraw.yaml",
      "project": "libraw",
      "total_apis": 2,
      "valueless_count": 1,
      "valuable_count": 1,
      "valueless_apis": [...],
      "valuable_apis": [...]
    }
  ]
}
```

## Workflow Examples

### Example 1: Initial Analysis

```bash
$ python3 api_analyzer.py --analyze
Found 36 YAML files

Analyzing: abseil-cpp.yaml...
Analyzing: cjson.yaml...
...

================================================================================
Analysis Summary
================================================================================
Total projects: 34
Total APIs: 44
Valueless APIs: 10 (22.73%)
Valuable APIs: 34 (77.27%)
✓ JSON report saved to: api_analysis_report.json
```

### Example 2: Preview Removal (Dry-Run)

```bash
$ python3 api_analyzer.py --analyze --remove --dry-run

[DRY RUN] Found 10 valueless APIs in 7 files

[DRY RUN] Processing: comparison/libraw.yaml
  APIs to remove: 2
    - LibRaw::crxDecodePlane
    - LibRaw::crxLoadDecodeLoop
```

### Example 3: Actual Removal

```bash
$ python3 api_analyzer.py --analyze --remove

Found 10 valueless APIs in 7 files

⚠️  This will modify YAML files. Continue? (yes/no): yes

Processing: comparison/libraw.yaml
  APIs to remove: 2
    - LibRaw::crxDecodePlane
    - LibRaw::crxLoadDecodeLoop
  ✓ Backed up to: libraw.yaml.backup_20251030_143022
  ✓ Modified

✓ Modified 7 files
```

## Customizing Classification Rules

To modify the identification rules, edit the `VALUELESS_PATTERNS` dictionary in `api_analyzer.py`:

```python
VALUELESS_PATTERNS = {
    'your_rule_name': {
        'keywords': ['keyword1', 'keyword2'],  # For keyword matching
        # OR
        'pattern': r'regex_pattern',            # For regex matching
        'description': 'Rule description'
    }
}
```

Then update the `is_valueless_api()` function to check your new pattern.

## Safety Features

1. **Backup**: Original files are automatically backed up with timestamps before modification
2. **Confirmation**: Interactive confirmation prompt before making changes
3. **Dry-run**: Preview changes without modifying files using `--dry-run`
4. **Reversible**: Backup files allow easy recovery if needed

## Programmatic Access

```python
import json

# Load analysis report
with open('api_analysis_report.json', 'r') as f:
    report = json.load(f)

# Access summary statistics
summary = report['summary']
print(f"Valueless APIs: {summary['valueless_apis']}")

# Iterate through valueless APIs by project
for project, apis in report['valueless_apis_by_project'].items():
    print(f"\nProject: {project}")
    for api in apis:
        print(f"  - {api['api']}")
        print(f"    Reasons: {', '.join(api['reasons'])}")
```

## Edge Cases and Manual Review

Some APIs may require human judgment:

1. **Functions containing "free" that aren't memory deallocation** ✅ FIXED
   - Example: `FreezeRequestHandler` (handles freeze requests, not memory)
   - **Fix Applied**: Added "freeze" to exceptions list
   - **Status**: Now automatically handled

2. **Parameterless but public APIs**
   - Example: `getVersion()` might be a legitimate public API
   - **Action**: Consider fuzzing value on case-by-case basis
   - **Note**: These have minimal fuzzing value since they can't vary inputs

3. **Internal-looking but actually public interfaces**
   - Example: Some projects use `_internal` for public internal modules
   - **Action**: Check project documentation
   - **Mitigation**: Excluded "public_internal" patterns from filtering

4. **Decoder/parser functions with descriptive names** ✅ FIXED
   - Example: `jpeg_decode_block()`, `png_read_chunk()`, `WebPDecode()`
   - **Old Behavior**: Incorrectly filtered due to keywords
   - **Fix Applied**: Removed overly broad keyword matching
   - **Status**: These excellent targets are now preserved!

## Troubleshooting

### YAML Parsing Errors

If standard YAML parsing fails, the tool automatically falls back to custom parsing. If both fail:

1. Check YAML file syntax
2. Ensure proper indentation
3. Look for special characters that need escaping

### Incorrect Classifications

If an API is incorrectly classified:

1. Review the `reasons` field in the JSON report
2. Adjust the `VALUELESS_PATTERNS` rules
3. Add exceptions for specific API patterns

### File Not Found Errors

If removal fails with "File not found":

1. Ensure you're running from the correct directory
2. Use `--dir` to specify the benchmark directory explicitly
3. Check that file paths in YAML are correct

## Migration from Old Scripts

If you were using the old separate scripts:

```bash
# Old workflow (deprecated)
python3 analyze_apis.py          # Generate text report
python3 generate_json_report.py  # Generate JSON report
python3 remove_valueless_apis.py # Remove APIs

# New unified workflow
python3 api_analyzer.py --analyze --remove
```

**Benefits of new tool**:
- ✅ Single script, simpler maintenance
- ✅ Command-line arguments for flexibility
- ✅ JSON-only output (cleaner)
- ✅ Dry-run capability
- ✅ Better error handling

## License

This tool follows the original project's license.

---
**Tool Version**: 2.0  
**Dataset**: conti-benchmark (comparison + conti-cmp)

