# Resource Management Errors

## Category
Memory leaks, file descriptor leaks, unbounded resource usage

## Impact
- Memory leak (fuzzer slowdown)
- File descriptor exhaustion
- Stack overflow
- Timeout (unbounded loops)

## Common Patterns

### 1. Memory Leak on Error Path

**Error**:
```c
obj_t *obj = obj_create();
uint8_t *buffer = malloc(SIZE);

if (condition) return 0;  // Leak: obj and buffer not freed

obj_process(obj, buffer);
obj_destroy(obj);
free(buffer);
```

**Fix (C - goto cleanup)**:
```c
obj_t *obj = obj_create();
if (!obj) return 0;

uint8_t *buffer = malloc(SIZE);
if (!buffer) goto cleanup_obj;

if (condition) goto cleanup_all;

obj_process(obj, buffer);

cleanup_all:
  free(buffer);
cleanup_obj:
  obj_destroy(obj);
  return 0;
```

**Fix (C++ - RAII)**:
```cpp
std::unique_ptr<obj_t, decltype(&obj_destroy)> obj(obj_create(), obj_destroy);
std::vector<uint8_t> buffer(SIZE);

if (condition) return 0;  // Auto cleanup

obj_process(obj.get(), buffer.data());
```

**Detection**: Early return after allocation

**Specification Mark**:
```yaml
cleanup:
  strategy: "goto cleanup labels"
  order: [free(buffer), obj_destroy(obj)]
  ensure: "All paths lead to cleanup"
```

---

### 2. File Descriptor Leak

**Error**:
```c
int fd = open(filename, O_RDONLY);
if (error) return 0;  // Leak: fd not closed
read(fd, buffer, size);
close(fd);
```

**Fix**:
```c
int fd = open(filename, O_RDONLY);
if (fd < 0) return 0;

if (error) {
  close(fd);
  return 0;
}

read(fd, buffer, size);
close(fd);
```

**Better (always close)**:
```c
int fd = open(filename, O_RDONLY);
if (fd < 0) return 0;

if (!error) {
  read(fd, buffer, size);
}

close(fd);  // Always close
return 0;
```

**Detection**: File/socket operations

**Specification Mark**:
```yaml
resource:
  type: file_descriptor
  acquire: open(filename)
  release: close(fd)
  ensure_cleanup: true
```

---

### 3. Stack Overflow (Large Stack Arrays)

**Error**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t buffer[10 * 1024 * 1024];  // 10MB on stack - CRASH
  memcpy(buffer, data, size);
}
```

**Fix (Use heap)**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buffer = malloc(size);
  if (!buffer) return 0;
  
  memcpy(buffer, data, size);
  api_function(buffer, size);
  
  free(buffer);
  return 0;
}
```

**Fix (Use static - reuse across calls)**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static uint8_t buffer[256 * 1024];  // Reused, not on stack per call
  
  if (size > sizeof(buffer)) return 0;
  memcpy(buffer, data, size);
  api_function(buffer, size);
  return 0;
}
```

**Detection**: Large stack allocations

**Specification Mark**:
```yaml
resource:
  type: buffer
  size: "up to MAX_SIZE"
  allocation: heap  # or: static
  reason: "Too large for stack"
```

---

### 4. Unbounded Loop (Timeout)

**Error**:
```c
while (has_more_data()) {  // Could be infinite
  process_next();
}
```

**Fix**:
```c
int max_iterations = 1000;
while (has_more_data() && max_iterations-- > 0) {
  process_next();
}
```

**Detection**: Loops dependent on input data

**Specification Mark**:
```yaml
loop_protection:
  max_iterations: 1000
  reason: "Prevent timeout on malformed input"
  code: |
    int max_iter = 1000;
    while (condition && max_iter-- > 0) {
      // loop body
    }
```

---

### 5. Temp File Not Cleaned Up

**Error**:
```c
char filename[] = "/tmp/fuzz.dat";
FILE *fp = fopen(filename, "wb");
fwrite(data, size, 1, fp);
fclose(fp);

api_load_file(filename);
// Missing: unlink(filename) - disk fills up
```

**Fix**:
```c
char filename[256];
snprintf(filename, sizeof(filename), "/tmp/fuzz_%d", getpid());

FILE *fp = fopen(filename, "wb");
fwrite(data, size, 1, fp);
fclose(fp);

api_load_file(filename);
unlink(filename);  // Always clean up
```

**Detection**: File creation without unlink

**Specification Mark**:
```yaml
resource:
  type: temp_file
  create: "fopen(/tmp/fuzz_PID, wb)"
  cleanup: "unlink(filename)"
  ensure: "Cleanup even on error"
```

---

### 6. Growing Memory in Loop

**Error**:
```c
while (has_entries()) {
  Entry *e = allocate_entry();
  process(e);
  // Missing: free(e) - memory grows
}
```

**Fix**:
```c
while (has_entries()) {
  Entry *e = allocate_entry();
  if (!e) break;
  
  process(e);
  free(e);  // Free in each iteration
}
```

**Detection**: Allocation inside loop

**Specification Mark**:
```yaml
loop_pattern:
  allocations: "per iteration"
  cleanup: "per iteration (not after loop)"
  reason: "Prevent memory accumulation"
```

---

## Real Examples

### libarchive: Memory Leak
```c
// WRONG
archive_t *a = archive_read_new();
if (archive_read_open(a, ...) != OK) {
  return 0;  // Leak: archive not freed
}

// RIGHT
archive_t *a = archive_read_new();
if (archive_read_open(a, ...) != OK) {
  archive_read_free(a);
  return 0;
}
```

### zlib: Stack Overflow
```c
// WRONG
uint8_t buffer[10 * 1024 * 1024];  // Stack overflow

// RIGHT
static uint8_t buffer[256 * 1024];  // Static, reused
// OR
uint8_t *buffer = malloc(size);  // Heap
```

### SQLite: Unbounded Query
```c
// WRONG
while (sqlite3_step(stmt) == SQLITE_ROW) {
  // Potentially infinite with malicious DB
}

// RIGHT
int max_rows = 10000;
while (sqlite3_step(stmt) == SQLITE_ROW && max_rows-- > 0) {
  // Limited iterations
}
```

---

## Prevention Checklist

- [ ] Free all allocated memory on all code paths
- [ ] Close all file descriptors
- [ ] Clean up temp files
- [ ] Use heap for large buffers (>1MB)
- [ ] Limit loop iterations
- [ ] Free resources in loops per iteration
- [ ] Use goto cleanup or RAII for complex cleanup
- [ ] Check that cleanup happens on early returns

---

## Specification Template

```yaml
resources:
  - type: memory
    allocation: malloc(size)
    cleanup: free(ptr)
    ensure_all_paths: true
    
  - type: file_descriptor
    allocation: open(filename)
    cleanup: close(fd)
    
  - type: temp_file
    allocation: fopen(/tmp/fuzz_PID, wb)
    cleanup: unlink(filename)
    
cleanup_pattern: |
  cleanup_all:
    free(buffer);
  cleanup_obj:
    obj_destroy(obj);
    return 0;
    
loop_limits:
  max_entries: 100
  max_reads_per_entry: 1000
  max_buffer_size: 10MB
```

