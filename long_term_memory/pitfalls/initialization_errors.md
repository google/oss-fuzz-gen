# Initialization Errors in OSS-Fuzz

## OSS-Fuzz Critical Patterns

### 1. Missing LLVMFuzzerInitialize (Global Init)

**When**: Library requires one-time global initialization

**❌ Wrong**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Missing global init
  library_function(data, size);  // Crash or undefined behavior
}
```

**✅ Right**:
```c
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  library_global_init();  // One-time init before fuzzing
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  library_function(data, size);  // Now safe
}
```

**Key Point**: `LLVMFuzzerInitialize` is called **once** before fuzzing starts.

---

### 2. Missing Error/Notice Handler Setup

**When**: Library requires error handler (common in C libraries)

**❌ Wrong**:
```c
// Missing handler setup
GEOSGeometry *g = GEOSGeomFromWKT("POINT(0 0)");  // Crash
```

**✅ Right**:
```c
static void notice_handler(const char *fmt, ...) { /* ignore */ }
static void error_handler(const char *fmt, ...) { /* ignore */ }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  initGEOS(notice_handler, error_handler);  // Setup handlers
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  GEOSGeometry *g = GEOSGeomFromWKT(...);  // Now safe
  // ...
}
```

---

### 3. Wrong Initialization Order

**When**: Multi-step initialization required

**❌ Wrong**:
```c
tidyParseBuffer(doc, &buf);       // Crash: no error buffer set
tidySetErrorBuffer(doc, &errbuf); // Too late
```

**✅ Right**:
```c
TidyDoc doc = tidyCreate();
TidyBuffer errbuf;
tidyBufInit(&errbuf);
tidySetErrorBuffer(doc, &errbuf);  // Setup first
tidyParseBuffer(doc, &buf);         // Then use
```

---

## Real OSS-Fuzz Examples

### libGEOS: Missing initGEOS()
```c
// ❌ Wrong
GEOSGeometry *g = GEOSGeomFromWKT("POINT(0 0)");  // Crash

// ✅ Right
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  initGEOS(notice_handler, error_handler);  // Must init first
  return 0;
}
```

### SQLite: Missing sqlite3_initialize()
```c
// ❌ Wrong
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  sqlite3 *db;
  sqlite3_open(":memory:", &db);  // Crash: library not initialized
}

// ✅ Right
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  sqlite3_initialize();  // Global init
  return 0;
}
```

### libxml2: Missing xmlInitParser()
```c
// ❌ Wrong
xmlDoc *doc = xmlReadMemory(data, size, NULL, NULL, 0);  // Crash

// ✅ Right - in LLVMFuzzerInitialize
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  xmlInitParser();  // One-time init
  return 0;
}
```

### tidy-html5: Wrong order (error buffer must be set before parsing)
```c
// ❌ Wrong
TidyDoc doc = tidyCreate();
tidyParseBuffer(doc, &buf);       // Crash: no error buffer
tidySetErrorBuffer(doc, &errbuf); // Too late

// ✅ Right
TidyDoc doc = tidyCreate();
TidyBuffer errbuf;
tidyBufInit(&errbuf);
tidySetErrorBuffer(doc, &errbuf);  // Before parsing
tidyParseBuffer(doc, &buf);         // Now safe
```

---

## Quick Checklist

- [ ] Check if library needs global init (→ use `LLVMFuzzerInitialize`)
- [ ] Setup error handlers **before** any API calls
- [ ] Follow correct initialization order (config → parse → use)
- [ ] Look for `*_init()`, `*_initialize()`, `*_setup()` functions in docs

