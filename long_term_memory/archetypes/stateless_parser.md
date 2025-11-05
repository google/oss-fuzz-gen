# Stateless Parser (Single-Call Pattern)

## Pattern
```c
result = parse_function(data, size);
```

Single function, no state, no setup/cleanup needed.

---

## OSS-Fuzz Notes

### ✅ What Makes It "Stateless"
- No `LLVMFuzzerInitialize` needed (usually)
- No object creation/destruction
- Direct `data` → `parse()` → `result`

### ⚠️ Common Pitfalls

**1. Not all "parsers" are stateless**
```c
// ❌ Looks stateless, but needs parser object
yaml_parser_t parser;
yaml_parser_initialize(&parser);  // ← NOT stateless!
yaml_parser_parse(&parser, event);
```

**2. Size validation**
```c
// ❌ Wrong - no size check
result = parse(data, size);  // Crashes on size=0

// ✅ Right
if (size < MIN_SIZE) return 0;  // Check first
result = parse(data, size);
```

---

## Real Examples

- **cJSON**: `json_parse(data, size)` - truly stateless
- **libpng** (memory variant): `png_decode()` - stateless
- **libyaml**: `yaml_parser_parse()` - NOT stateless (needs parser object)
- **protobuf-c**: `message__unpack(data, size)` - stateless

