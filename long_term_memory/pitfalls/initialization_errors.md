# Initialization Errors

## Category
Missing or incorrect library/object initialization

## Impact
- Crash from accessing uninitialized memory
- Undefined behavior
- False-positive bugs

## Common Patterns

### 1. Missing Library Init

**Error**:
```c
// Missing: initGEOS(handler, handler);
Geometry *g = GEOSGeomFromWKT(wkt);  // Crash: library not initialized
```

**Fix**:
```c
initGEOS(msg_handler, msg_handler);  // Initialize first
Geometry *g = GEOSGeomFromWKT(wkt);  // Now safe
```

**Detection**: Function names containing "init", "initialize", "setup"

**Specification Mark**:
```yaml
setup_sequence:
  - initGEOS(handler, handler)  # Must call first
  - GEOSGeomFromWKT(...)        # Then call target
```

---

### 2. Missing Error Handler Setup

**Error**:
```c
ContextHandle *ctx = GEOS_init_r();
// Missing: Context_setErrorHandler_r(ctx, handler);
GEOSNormalize_r(ctx, geom);  // Crash: no error handler
```

**Fix**:
```c
void handler(const char *fmt, ...) { exit(1); }

ContextHandle *ctx = GEOS_init_r();
Context_setErrorHandler_r(ctx, handler);  // Set handler
GEOSNormalize_r(ctx, geom);               // Now safe
```

**Detection**: APIs with error/message handler parameters

**Specification Mark**:
```yaml
preconditions:
  - error_handler_set: true
  - reason: "API uses handler to report internal errors"
  
setup_sequence:
  - define_handler_function()
  - set_error_handler(ctx, handler)
```

---

### 3. Wrong Initialization Order

**Error**:
```c
parser_parse(parser, data);     // Crash: parser not configured
parser_set_option(parser, opt); // Too late
```

**Fix**:
```c
parser_set_option(parser, opt); // Configure first
parser_parse(parser, data);     // Then parse
```

**Detection**: Multi-step state machine pattern

**Specification Mark**:
```yaml
setup_sequence:
  - parser_create()
  - parser_set_option()  # Must be before parse
  - parser_parse()       # Depends on options
```

---

### 4. Missing LLVMFuzzerInitialize

**Error**:
```c
// Missing LLVMFuzzerInitialize
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Library needs one-time global init
  library_function(data, size);  // Crash or undefined
}
```

**Fix**:
```c
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  library_global_init();  // One-time initialization
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  library_function(data, size);  // Now safe
}
```

**Detection**: Global state initialization in docs

**Specification Mark**:
```yaml
global_init_required: true
function: library_global_init()
reason: "Must be called once before any API usage"
```

---

## Real Examples

### libGEOS
```c
// WRONG
GEOSGeometry *g = GEOSGeomFromWKT("POINT(0 0)");  // Crash

// RIGHT
initGEOS(notice_handler, error_handler);
GEOSGeometry *g = GEOSGeomFromWKT("POINT(0 0)");  // OK
```

### SQLite
```c
// WRONG
sqlite3 *db;
sqlite3_open(":memory:", &db);  // Crash: not initialized

// RIGHT
sqlite3_initialize();  // Global init
sqlite3 *db;
sqlite3_open(":memory:", &db);  // OK
```

### libxml2
```c
// WRONG
xmlDoc *doc = xmlReadMemory(data, size, NULL, NULL, 0);  // Unsafe

// RIGHT
xmlInitParser();  // In LLVMFuzzerInitialize
xmlDoc *doc = xmlReadMemory(data, size, NULL, NULL, 0);  // OK
```

---

## Prevention Checklist

-  Check API documentation for initialization functions
-  Look for function names with "init", "setup", "initialize"
-  Check if API has global state
-  Verify initialization order in specification
-  Add error handler setup if API supports it
-  Use LLVMFuzzerInitialize for one-time setup

---

## Specification Template

```yaml
initialization:
  global_init:
    function: library_init()
    location: LLVMFuzzerInitialize
    
  error_handler:
    required: true
    setup: set_error_handler(handler)
    
  setup_sequence:
    - library_init()         # Step 1
    - set_error_handler()    # Step 2
    - create_object()        # Step 3
    - configure_object()     # Step 4
    - use_object()           # Step 5
```

