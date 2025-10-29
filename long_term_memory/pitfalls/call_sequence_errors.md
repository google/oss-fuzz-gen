# Call Sequence Errors

## Category
Functions called in wrong order or lifecycle violations

## Impact
- Double-free
- Use-after-free
- Invalid state transitions
- Crash from unexpected order

## Common Patterns

### 1. Double-Free

**Error**:
```c
WKBReader *r = WKBReader_create_r(ctx);
WKBReader_destroy(r);        // Free once
WKBReader_destroy_r(ctx, r); // Free again - CRASH
```

**Fix**:
```c
WKBReader *r = WKBReader_create_r(ctx);
WKBReader_destroy_r(ctx, r); // Free once only
```

**Detection**: Multiple cleanup calls on same object

**Specification Mark**:
```yaml
postcondition:
  function: WKBReader_destroy_r
  effect: "Frees reader object"
  note: "Object invalid after this call, do not destroy again"
  
setup_sequence:
  - WKBReader_create_r()
  - use_reader()
  - WKBReader_destroy_r()  # Only this cleanup, not both
```

---

### 2. Use-After-Free

**Error**:
```c
Geometry *g = createGeometry();
destroyGeometry(g);
double area = getArea(g);  // Use after free - CRASH
```

**Fix**:
```c
Geometry *g = createGeometry();
double area = getArea(g);  // Use before free
destroyGeometry(g);        // Free at end
```

**Detection**: Object used after destroy()

**Specification Mark**:
```yaml
setup_sequence:
  - g = createGeometry()
  - area = getArea(g)      # Use first
  - destroyGeometry(g)     # Then free
  # No operations on g after this point
```

---

### 3. Premature Cleanup

**Error**:
```c
Geometry *g1 = createGeometry();
Geometry *g2 = intersection(g1, g2_data);
destroyGeometry(g1);       // Premature
double area = getArea(g2); // Crash: g2 might reference g1
```

**Fix**:
```c
Geometry *g1 = createGeometry();
Geometry *g2 = intersection(g1, g2_data);
double area = getArea(g2); // Use g2
destroyGeometry(g2);       // Free dependent first
destroyGeometry(g1);       // Then free g1
```

**Detection**: Cleanup order violates dependencies

**Specification Mark**:
```yaml
cleanup_sequence:
  # Reverse order of creation
  - destroyGeometry(g2)  # Dependent object first
  - destroyGeometry(g1)  # Then owner
  
dependency:
  g2_depends_on: g1
  reason: "g2 may hold references to g1 internals"
```

---

### 4. Operations After Close

**Error**:
```c
File *f = file_open(path);
file_read(f, buffer, size);
file_close(f);
file_read(f, buffer2, size);  // Crash: file closed
```

**Fix**:
```c
File *f = file_open(path);
file_read(f, buffer, size);
file_read(f, buffer2, size);  // Both reads before close
file_close(f);
```

**Detection**: Operations after close/finalize

**Specification Mark**:
```yaml
state_transitions:
  OPEN → read() → OPEN      # Can read multiple times
  OPEN → close() → CLOSED   # Close transitions to CLOSED
  CLOSED → read() → ERROR   # Invalid: can't read after close
```

---

### 5. Missing Initialization Step

**Error**:
```c
Parser *p = parser_create();
// Missing: parser_set_input(p, data);
parser_parse(p);  // Crash: no input set
```

**Fix**:
```c
Parser *p = parser_create();
parser_set_input(p, data, size);  // Required step
parser_parse(p);                  // Now safe
```

**Detection**: Required setup step skipped

**Specification Mark**:
```yaml
setup_sequence:
  - p = parser_create()
  - parser_set_input(p, data)  # REQUIRED before parse
  - parser_parse(p)
  
precondition:
  function: parser_parse
  requires: "input must be set via parser_set_input()"
```

---

### 6. Wrong Cleanup Order in Multi-Resource

**Error**:
```c
Context *ctx = init_context();
Buffer *buf = create_buffer(ctx);

free_context(ctx);  // WRONG: ctx freed first
free_buffer(buf);   // Crash: buf needs ctx
```

**Fix**:
```c
Context *ctx = init_context();
Buffer *buf = create_buffer(ctx);

free_buffer(buf);   // Free dependent first
free_context(ctx);  // Then free owner
```

**Detection**: Cleanup order doesn't reverse creation order

**Specification Mark**:
```yaml
setup_sequence:
  - ctx = init_context()
  - buf = create_buffer(ctx)
  
cleanup_sequence:
  # MUST be reverse order
  - free_buffer(buf)
  - free_context(ctx)
  
dependency:
  buf_depends_on: ctx
```

---

## Real Examples

### libGEOS: Double-Free
```c
// WRONG
WKBReader *r = WKBReader_create_r(ctx);
WKBReader_destroy(r);         // Non-reentrant version
WKBReader_destroy_r(ctx, r);  // Reentrant version - double free

// RIGHT - pick ONE
WKBReader_destroy_r(ctx, r);  // Use reentrant version only
```

### HDF5: Use-After-Close
```c
// WRONG
hid_t file = H5Fopen(filename, H5F_ACC_RDONLY, H5P_DEFAULT);
hid_t dataset = H5Dopen(file, "/dataset", H5P_DEFAULT);
H5Fclose(file);         // Close file
H5Dread(dataset, ...);  // Crash: file already closed

// RIGHT
hid_t file = H5Fopen(filename, H5F_ACC_RDONLY, H5P_DEFAULT);
hid_t dataset = H5Dopen(file, "/dataset", H5P_DEFAULT);
H5Dread(dataset, ...);  // Read before close
H5Dclose(dataset);
H5Fclose(file);
```

### tidy-html5: Missing Configuration
```c
// WRONG
TidyDoc doc = tidyCreate();
tidyParseBuffer(doc, &buf);  // Crash: no error buffer set

// RIGHT
TidyDoc doc = tidyCreate();
TidyBuffer errbuf;
tidyBufInit(&errbuf);
tidySetErrorBuffer(doc, &errbuf);  // Set error buffer first
tidyParseBuffer(doc, &buf);         // Now safe
```

---

## Prevention Checklist

- [ ] Cleanup in reverse order of creation
- [ ] Don't use objects after destroy/close/free
- [ ] Don't destroy same object twice
- [ ] Complete all setup steps before use
- [ ] Check for dependencies between objects
- [ ] Follow state machine transitions
- [ ] Ensure cleanup happens on all error paths

---

## Specification Template

```yaml
setup_sequence:
  - step1: init_context()
  - step2: create_object(ctx)
  - step3: configure_object(obj)
  - step4: use_object(obj)
  
cleanup_sequence:
  # Reverse order
  - step1: destroy_object(obj)
  - step2: cleanup_context(ctx)
  
state_machine:
  states: [INIT, CONFIGURED, ACTIVE, CLOSED]
  transitions:
    - from: INIT
      to: CONFIGURED
      via: configure()
    - from: CONFIGURED
      to: ACTIVE
      via: activate()
    - from: ACTIVE
      to: CLOSED
      via: close()
  
  invalid_transitions:
    - from: CLOSED
      to: ACTIVE
      reason: "Cannot use after close"
```

