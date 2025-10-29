# File-based API Archetype

## Pattern Signature
```
write_temp_file(data) → api_load_file(path) → unlink(path)
```

## Characteristics
- API requires file path, not memory buffer
- Temp file creation necessary
- File cleanup critical
- Process isolation via filesystem

## Typical APIs
- Image loaders (imread, not imdecode)
- Document processors (PDF, Office)
- Archive extractors
- File format validators

## Preconditions
1. Temp file writable
2. Unique filename (avoid collision)
3. Data written completely
4. File closed before API call

## Postconditions
1. API reads from file
2. File can be deleted after
3. Cleanup happens even on crash
4. No file descriptor leaks

## Driver Pattern
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  // Create unique temp file
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/fuzz_%d_%p", 
           getpid(), (void*)data);
  
  // Write data
  FILE *fp = fopen(filename, "wb");
  if (!fp) return 0;
  
  fwrite(data, 1, size, fp);
  fclose(fp);
  
  // Call API
  result_t *result = api_load_file(filename);
  
  if (result) {
    // Use result
    api_free_result(result);
  }
  
  // Cleanup
  unlink(filename);
  return 0;
}
```

## C++ RAII Version
```cpp
class TempFile {
  char path_[256];
  
public:
  TempFile(const uint8_t *data, size_t size) {
    snprintf(path_, sizeof(path_), "/tmp/fuzz_%d_%p", 
             getpid(), (void*)this);
    
    FILE *fp = fopen(path_, "wb");
    if (fp) {
      fwrite(data, size, 1, fp);
      fclose(fp);
    }
  }
  
  ~TempFile() { unlink(path_); }
  
  const char* path() const { return path_; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  TempFile tmp(data, size);
  api_load_file(tmp.path());
  
  return 0;  // Auto cleanup
}
```

## Parameter Strategy
- File data: DIRECT_FUZZ
- Filename: FIX (unique temp path)
- Options: CONSTRAIN or FIX

## Filename Uniqueness

**WRONG**: Fixed name (race condition)
```c
char filename[] = "/tmp/fuzz.dat";  // Multiple instances collide
```

**RIGHT**: PID + pointer (unique)
```c
snprintf(filename, sizeof(filename), "/tmp/fuzz_%d_%p", 
         getpid(), (void*)data);
```

**BETTER**: Use mkstemp (atomic)
```c
char template[] = "/tmp/fuzzXXXXXX";
int fd = mkstemp(template);
write(fd, data, size);
close(fd);
// use template as filename
unlink(template);
```

## Common Pitfalls
- Fixed filename (collision)
- Not closing file before API call
- Forgetting to unlink (disk fills)
- File descriptor leak
- Path traversal in API (use absolute path)

## Cleanup Guarantees

**Problem**: Crash before unlink
```c
api_load_file(filename);  // Crashes here
unlink(filename);         // Never reached
```

**Solution 1**: OS cleans /tmp on reboot (acceptable for fuzzing)

**Solution 2**: RAII (C++)
```cpp
{
  TempFile tmp(data, size);
  api_load_file(tmp.path());
}  // Destructor called even on exception
```

**Solution 3**: Signal handler (complex, not recommended)

## Multiple Files

Some APIs need multiple files:
```c
char file1[256], file2[256];
snprintf(file1, sizeof(file1), "/tmp/fuzz1_%d", getpid());
snprintf(file2, sizeof(file2), "/tmp/fuzz2_%d", getpid());

// Split input data
size_t split = data[0];  // First byte determines split
if (split > size) split = size / 2;

write_file(file1, data, split);
write_file(file2, data + split, size - split);

api_process_two_files(file1, file2);

unlink(file1);
unlink(file2);
```

## Real Examples
- OpenCV: `cv::imread(filename)` (not `cv::imdecode()`)
- HDF5: `H5Fopen(filename, ...)`
- Many image/video libraries

## Disk Space Considerations

Some fuzzing environments have small /tmp:
```c
// Check input size
if (size > 10 * 1024 * 1024) return 0;  // Limit 10MB
```

## Reference
See FUZZER_COOKBOOK.md Scenario 2

