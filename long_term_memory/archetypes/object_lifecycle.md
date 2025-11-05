# Object Lifecycle (create → use → destroy)

## Pattern
```c
obj_t *obj = obj_create();
if (!obj) return 0;

obj_process(obj, data, size);

cleanup:
  obj_destroy(obj);
  return 0;
```

---

## OSS-Fuzz Notes

### ⚠️ Critical: Always Check create() Return

**❌ Wrong**:
```c
obj_t *obj = obj_create();  // Might return NULL
obj_process(obj, data);     // Crash if NULL
```

**✅ Right**:
```c
obj_t *obj = obj_create();
if (!obj) return 0;  // Must check
obj_process(obj, data);
```

### ⚠️ Must Destroy on All Paths

```c
obj_t *obj = obj_create();
if (!obj) return 0;

if (condition) goto cleanup;  // ✅ OK
// NOT: if (condition) return 0;  // ❌ Leaks obj

obj_process(obj, data);

cleanup:
  obj_destroy(obj);
  return 0;
```

---

## Real Examples

- **libGEOS**: `GEOS_init_r()` → `GEOSGeomFromWKT()` → `GEOSGeom_destroy()`
- **HDF5**: `H5Fopen()` → `H5Dread()` → `H5Fclose()`
- **libyaml**: `yaml_parser_initialize()` → `yaml_parser_delete()`
- **mbedTLS**: `mbedtls_x509_crt_init()` → `mbedtls_x509_crt_free()`
