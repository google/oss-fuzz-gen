# Long-term Memory Knowledge Base

## Overview

This directory contains structured knowledge extracted from:
- FUZZER_BEHAVIOR_TAXONOMY.md (empirical analysis)
- FUZZER_COOKBOOK.md (practical templates)
- Real-world fuzzer patterns

The knowledge is organized for efficient retrieval during spec generation and driver prototyping.

---

## Directory Structure

```
long_term_memory/
├── archetypes/           # 6 behavioral patterns
│   ├── stateless_parser.md
│   ├── object_lifecycle.md
│   ├── state_machine.md
│   ├── stream_processor.md
│   ├── round_trip.md
│   └── file_based.md
│
├── skeletons/            # Code templates per archetype
│   ├── stateless_parser_skeleton.c
│   ├── object_lifecycle_skeleton.c
│   ├── state_machine_skeleton.c
│   ├── stream_processor_skeleton.c
│   ├── round_trip_skeleton.c
│   └── file_based_skeleton.c
│
├── pitfalls/             # Common error patterns
│   ├── initialization_errors.md
│   ├── data_argument_errors.md
│   ├── call_sequence_errors.md
│   └── resource_management.md
│
└── retrieval.py          # Retrieval implementation
```

---

## Archetypes

Each archetype file contains:
- **Pattern Signature**: Visual representation
- **Characteristics**: When to use this pattern
- **Preconditions**: What must be true before calling
- **Postconditions**: What's guaranteed after calling
- **Driver Pattern**: Complete code example
- **Parameter Strategy**: How to construct each parameter
- **Common Pitfalls**: What to avoid
- **Real Examples**: Actual APIs using this pattern

### The 6 Archetypes

1. **Stateless Parser**: Single function, no state
   - Example: `json_parse(data, size)`
   - Use when: Pure parsing, no setup needed

2. **Object Lifecycle**: create → use → destroy
   - Example: `obj_create()` → `obj_process()` → `obj_destroy()`
   - Use when: Explicit resource management

3. **State Machine**: Multi-step sequence
   - Example: `init()` → `configure()` → `parse()` → `finalize()`
   - Use when: Strict operation order required

4. **Stream Processor**: Incremental processing
   - Example: `while(has_data) { process_chunk() }`
   - Use when: Large data, chunk-by-chunk

5. **Round-trip**: Encode + decode validation
   - Example: `encode()` → `decode()` → `verify()`
   - Use when: Symmetric operations exist

6. **File-based**: Requires file path
   - Example: `write_temp()` → `api_load_file()` → `unlink()`
   - Use when: API needs filename, not buffer

---

## Skeletons

Each skeleton is a compilable template with placeholders:
- `PARSE_FUNCTION`: Replace with actual function name
- `OBJECT_TYPE`: Replace with actual type
- `MIN_SIZE`, `MAX_SIZE`: Adjust based on API

Skeletons include:
- Proper structure for the archetype
- Postcondition checks at correct locations
- Resource cleanup patterns
- Comments explaining each section

---

## Pitfalls

Four categories of common errors:

1. **Initialization Errors**
   - Missing library init
   - Missing error handler setup
   - Wrong initialization order

2. **Data & Argument Errors**
   - Unchecked NULL pointers
   - Missing bounds validation
   - Buffer size mismatches

3. **Call Sequence Errors**
   - Double-free
   - Use-after-free
   - Wrong cleanup order

4. **Resource Management**
   - Memory leaks
   - Stack overflow
   - Unbounded loops

Each pitfall file contains:
- Error examples (what NOT to do)
- Fix examples (correct approach)
- Detection methods
- Specification markings

---

## Usage in Workflow

### Stage 1: Function Analyzer

When identifying archetype:
```python
# Pseudo-code
archetype = identify_archetype(function_analysis)
# archetype = "object_lifecycle"

# Retrieve knowledge
knowledge = read_file(f"long_term_memory/archetypes/{archetype}.md")

# Inject into context
context = f"""
Relevant Pattern:
{knowledge}

Use this as reference for your specification.
"""
```

### Stage 2: Prototyper

When generating driver:
```python
# Extract archetype from spec
archetype = extract_from_spec(specification)

# Retrieve skeleton
skeleton = read_file(f"long_term_memory/skeletons/{archetype}_skeleton.c")

# Inject into prompt
prompt = f"""
Base skeleton:
{skeleton}

Fill in the placeholders according to the specification.
"""
```

---

## Retrieval API

See `retrieval.py` for implementation:

```python
from long_term_memory.retrieval import KnowledgeRetriever

retriever = KnowledgeRetriever()

# Get archetype knowledge
archetype_doc = retriever.get_archetype("object_lifecycle")

# Get skeleton
skeleton = retriever.get_skeleton("object_lifecycle")

# Get relevant pitfalls
pitfalls = retriever.get_pitfalls(["initialization", "resource_management"])

# Get all knowledge for an archetype
bundle = retriever.get_bundle("object_lifecycle")
# Returns: {
#   'archetype': '<markdown content>',
#   'skeleton': '<C code>',
#   'relevant_pitfalls': ['<pitfall1>', '<pitfall2>']
# }
```

---

## Maintenance

### Adding New Archetypes

1. Create `archetypes/new_pattern.md`
2. Create `skeletons/new_pattern_skeleton.c`
3. Update `retrieval.py` archetype list

### Adding New Pitfalls

1. Create `pitfalls/new_category.md`
2. Follow template: Error → Fix → Detection → Spec
3. Update `retrieval.py` pitfall mappings

### Updating Existing Knowledge

- Keep examples updated with real-world cases
- Add new pitfalls as discovered
- Refine skeletons based on feedback

---

## Statistics

Current knowledge base:
- **6** archetypes (covers 95%+ of APIs)
- **6** code skeletons (ready-to-use templates)
- **4** pitfall categories (prevents most false positives)
- **50+** real-world examples cited

Extracted from:
- 4,699 OSS-Fuzz drivers
- FUZZER_TAXONOMY 5 dimensions × 25 patterns
- FUZZER_COOKBOOK 11 scenarios

---

## Benefits

### For Function Analyzer
- Quick reference for archetype characteristics
- Evidence-based precondition/postcondition patterns
- Real examples to cite in specifications

### For Prototyper
- Ready-made skeletons (no guessing structure)
- Correct postcondition check locations
- Proven cleanup patterns

### For Quality
- Prevent common pitfalls proactively
- Consistent driver structure
- Reduce false positives

---

## Future Enhancements

- [ ] Semantic search (embedding-based retrieval)
- [ ] Pattern combinations (multi-archetype support)
- [ ] Language-specific variants (C++ RAII versions)
- [ ] Learning loop (update knowledge from results)
- [ ] Cross-references between patterns

---

**Version**: 1.0
**Last Updated**: 2025-10-29
**Maintained by**: OSS-Fuzz-Gen Team

