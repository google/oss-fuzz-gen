# Call Sequence Errors in OSS-Fuzz

## Key Principle: LIFO (Last In, First Out)

**Cleanup order must reverse creation order**:
```c
// Create: A → B → C
// Cleanup: C → B → A
```

---

## Common OSS-Fuzz Pitfalls

### 1. Wrong Cleanup Order

**❌ Wrong**:
```c
Context *ctx = init_context();
Buffer *buf = create_buffer(ctx);  // buf depends on ctx

free_context(ctx);  // Free ctx first - WRONG
free_buffer(buf);   // Crash: buf still needs ctx
```

**✅ Right (LIFO)**:
```c
Context *ctx = init_context();
Buffer *buf = create_buffer(ctx);

free_buffer(buf);   // Free dependent first
free_context(ctx);  // Then free owner
```

---

### 2. Missing Required Setup Step

**❌ Wrong**:
```c
TidyDoc doc = tidyCreate();
tidyParseBuffer(doc, &buf);  // Crash: no error buffer set
```

**✅ Right**:
```c
TidyDoc doc = tidyCreate();
TidyBuffer errbuf;
tidyBufInit(&errbuf);
tidySetErrorBuffer(doc, &errbuf);  // Required before parsing
tidyParseBuffer(doc, &buf);         // Now safe
```

---

### 3. Use After Destroy

**❌ Wrong**:
```c
Geometry *g = createGeometry();
destroyGeometry(g);
double area = getArea(g);  // Crash: use after free
```

**✅ Right**:
```c
Geometry *g = createGeometry();
double area = getArea(g);  // Use first
destroyGeometry(g);        // Free last
```

---

## Real OSS-Fuzz Examples

### libGEOS: Mixing reentrant and non-reentrant APIs (double-free)
```c
// ❌ Wrong - calling both destroy functions
WKBReader *r = WKBReader_create_r(ctx);
WKBReader_destroy(r);         // Non-reentrant
WKBReader_destroy_r(ctx, r);  // Reentrant - double free!

// ✅ Right - pick ONE destroy function
WKBReader_destroy_r(ctx, r);  // Use reentrant version only
```

### HDF5: Closing file before dataset (wrong order)
```c
// ❌ Wrong
hid_t file = H5Fopen(filename, H5F_ACC_RDONLY, H5P_DEFAULT);
hid_t dataset = H5Dopen(file, "/dataset", H5P_DEFAULT);
H5Fclose(file);         // Close file first - WRONG
H5Dread(dataset, ...);  // Crash: file already closed

// ✅ Right (LIFO)
hid_t file = H5Fopen(filename, H5F_ACC_RDONLY, H5P_DEFAULT);
hid_t dataset = H5Dopen(file, "/dataset", H5P_DEFAULT);
H5Dread(dataset, ...);  // Use first
H5Dclose(dataset);      // Close dataset first
H5Fclose(file);         // Then close file
```

### tidy-html5: Missing required setup step
```c
// ❌ Wrong
TidyDoc doc = tidyCreate();
tidyParseBuffer(doc, &buf);  // Crash: no error buffer

// ✅ Right - must set error buffer first
TidyDoc doc = tidyCreate();
TidyBuffer errbuf;
tidyBufInit(&errbuf);
tidySetErrorBuffer(doc, &errbuf);  // Setup before use
tidyParseBuffer(doc, &buf);
```

---

## Quick Checklist

- [ ] Cleanup in **reverse order** of creation (LIFO)
- [ ] Complete all required setup steps **before** using object
- [ ] Don't use object after destroy/close/free
- [ ] Don't call destroy twice on same object
- [ ] Close dependent resources **before** owners

