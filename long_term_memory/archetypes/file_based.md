# File-based API (Requires File Path)

## Pattern
```c
write_temp_file(data) → api_load_file(path) → unlink(path)
```

API needs filename, not memory buffer.

---

## OSS-Fuzz Notes

### ⚠️ Must Use Unique Filename

**❌ Wrong - race condition**:
```c
char filename[] = "/tmp/fuzz.dat";  // Fixed name - multiple instances collide
```

**✅ Right - unique per process**:
```c
char filename[256];
snprintf(filename, sizeof(filename), "/tmp/fuzz_%d_%p", getpid(), (void*)data);
```

**✅ Better - atomic creation**:
```c
char template[] = "/tmp/fuzzXXXXXX";
int fd = mkstemp(template);  // Atomic, unique
write(fd, data, size);
close(fd);
api_load_file(template);
unlink(template);
```

### ⚠️ Must Close File Before API Call

**❌ Wrong**:
```c
FILE *fp = fopen(filename, "wb");
fwrite(data, size, 1, fp);
// Missing fclose(fp)
api_load_file(filename);  // Might not see all data
```

**✅ Right**:
```c
FILE *fp = fopen(filename, "wb");
fwrite(data, size, 1, fp);
fclose(fp);  // Close before loading
api_load_file(filename);
```

### ⚠️ Always Cleanup Temp File

```c
api_load_file(filename);
unlink(filename);  // Always cleanup (even if API crashes)
```

---

## Real Examples

- **OpenCV**: `cv::imread(filename)` - needs file path
- **HDF5**: `H5Fopen(filename, ...)` - file-based
- **ImageMagick**: Many image loaders require file path
- **libarchive**: `archive_read_open_filename()`
