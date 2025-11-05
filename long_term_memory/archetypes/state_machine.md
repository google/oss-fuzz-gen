# State Machine (Multi-Step Sequence)

## Pattern
```c
init() → configure() → parse() → finalize() → cleanup()
```

Strict order required - each step depends on previous.

---

## OSS-Fuzz Notes

### ⚠️ Must Follow Exact Order

**❌ Wrong**:
```c
TidyDoc doc = tidyCreate();
tidyParseBuffer(doc, &buf);       // Parse first - WRONG
tidySetErrorBuffer(doc, &errbuf); // Config after - too late
```

**✅ Right**:
```c
TidyDoc doc = tidyCreate();
TidyBuffer errbuf;
tidyBufInit(&errbuf);
tidySetErrorBuffer(doc, &errbuf);  // Config BEFORE parse
tidyParseBuffer(doc, &buf);         // Then parse
```

### ⚠️ Check Each Step

```c
if (tidySetErrorBuffer(doc, &errbuf) < 0) goto cleanup;
if (tidyParseBuffer(doc, &buf) < 0) goto cleanup;
if (tidyCleanAndRepair(doc) < 0) goto cleanup;
```

---

## Real Examples

- **tidy-html5**: `tidyCreate()` → `tidySetErrorBuffer()` → `tidyParseBuffer()` → `tidyCleanAndRepair()` → `tidyRelease()`
- **libxml2 SAX**: `xmlCreatePushParserCtxt()` → `xmlParseChunk()` (loop) → `xmlParseChunk(NULL)` (finalize)
- **HDF5**: `H5Fopen()` → `H5Screate()` → `H5Dcreate()` → `H5Dwrite()` → `H5Dclose()` → `H5Sclose()` → `H5Fclose()`
