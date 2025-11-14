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
├── archetypes/           # 6 behavioral patterns (unified SRS JSON format)
│   ├── stateless_parser.srs.json
│   ├── object_lifecycle.srs.json
│   ├── state_machine.srs.json
│   ├── stream_processor.srs.json
│   ├── round_trip.srs.json
│   └── file_based.srs.json
│
└── retrieval.py          # Retrieval implementation
```

Each SRS JSON file contains:
- Pattern description and when to use
- Functional requirements with implementation code
- Preconditions and postconditions
- Constraints (execution order, resource limits)
- Parameter strategies
- Common pitfalls
- Real-world examples

---

## Archetypes

Each archetype SRS JSON file contains:
- **Pattern Description**: When to use this pattern
- **Functional Requirements**: Mandatory and recommended requirements with code examples
- **Preconditions**: What must be true before calling (with validation checks)
- **Postconditions**: What's guaranteed after calling
- **Constraints**: Execution order, resource limits, and implementation sequences
- **Parameter Strategies**: How to construct each parameter for fuzzing
- **Common Pitfalls**: Error patterns with wrong/right examples
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

## SRS JSON Format

Each archetype is stored as a unified SRS (Software Requirements Specification) JSON file that combines:
- **Pattern knowledge**: When and how to use the archetype
- **Code skeletons**: Implementation examples embedded in functional requirements
- **Pitfalls**: Common errors integrated into requirements and constraints

The SRS format ensures consistency with Function Analyzer output and provides structured guidance for Prototyper.

### Common Pitfall Categories

Pitfalls are integrated into each archetype's SRS JSON:

1. **Initialization Errors**: Missing library init, wrong initialization order
2. **Data & Argument Errors**: Unchecked NULL pointers, missing bounds validation
3. **Call Sequence Errors**: Double-free, use-after-free, wrong cleanup order
4. **Resource Management**: Memory leaks, file descriptor leaks, stack overflow

Each pitfall includes:
- Wrong example (what NOT to do)
- Right example (correct approach)
- Impact description

---

## Usage in Workflow

### Stage 1: Function Analyzer

When identifying archetype:
```python
from long_term_memory.retrieval import KnowledgeRetriever

retriever = KnowledgeRetriever()
archetype = "object_lifecycle"

# Retrieve SRS knowledge
srs = retriever.get_srs(archetype)
# Returns full SRS JSON with pattern description, requirements, constraints

# Or get archetype description only
archetype_doc = retriever.get_archetype(archetype)

# Inject into context
context = f"""
Relevant Pattern:
{archetype_doc}

Use this as reference for your specification.
"""
```

### Stage 2: Prototyper

When generating driver:
```python
from long_term_memory.retrieval import KnowledgeRetriever

retriever = KnowledgeRetriever()
archetype = "object_lifecycle"

# Get skeleton code from SRS
skeleton = retriever.get_skeleton(archetype)
# Extracts implementation code from functional requirements

# Or get full bundle
bundle = retriever.get_bundle(archetype)
# Returns: {'archetype': str, 'skeleton': str, 'pitfalls': dict, 'srs': dict}

# Inject into prompt
prompt = f"""
Base skeleton:
{skeleton}

Fill in according to the specification.
"""
```

---

## Retrieval API

See `retrieval.py` for implementation:

```python
from long_term_memory.retrieval import KnowledgeRetriever

retriever = KnowledgeRetriever()

# Get archetype description (markdown format)
archetype_doc = retriever.get_archetype("object_lifecycle")

# Get skeleton code (extracted from SRS functional requirements)
skeleton = retriever.get_skeleton("object_lifecycle")

# Get relevant pitfalls for an archetype
pitfalls = retriever.get_pitfalls("object_lifecycle")
# Returns: dict of pitfall categories with wrong/right examples

# Get full SRS JSON
srs = retriever.get_srs("object_lifecycle")
# Returns: complete SRS JSON dict

# Get all knowledge for an archetype (convenience method)
bundle = retriever.get_bundle("object_lifecycle")
# Returns: {
#   'archetype': '<markdown description>',
#   'skeleton': '<C code>',
#   'pitfalls': {'category': {'issue': str, 'wrong': str, 'right': str, ...}},
#   'srs': '<full SRS JSON dict>'
# }
```

---

## Maintenance

### Adding New Archetypes

1. Create `archetypes/new_pattern.srs.json` following the SRS JSON format
2. Add archetype name to `KnowledgeRetriever.ARCHETYPES` list in `retrieval.py`
3. Ensure JSON includes: pattern_description, functional_requirements, preconditions, postconditions, constraints, parameter_strategies, common_pitfalls, real_examples, metadata

### Updating Existing Knowledge

- Edit the corresponding `.srs.json` file directly
- Keep examples updated with real-world cases
- Add new pitfalls to `common_pitfalls` array
- Refine implementation code in `functional_requirements`

---

## Statistics

Current knowledge base:
- **6** archetypes in unified SRS JSON format (covers 95%+ of APIs)
  - stateless_parser
  - object_lifecycle
  - state_machine
  - stream_processor
  - round_trip
  - file_based
- **6** code skeletons embedded in SRS functional requirements
- **4** pitfall categories integrated into each archetype
  - Initialization errors
  - Data/argument errors
  - Call sequence errors
  - Resource management errors
- **50+** real-world examples cited across all archetypes

Knowledge extracted from:
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
- Ready-made skeletons extracted from SRS functional requirements
- Correct postcondition check locations
- Proven cleanup patterns
- Structured implementation guidance from constraints

### For Quality
- Prevent common pitfalls proactively
- Consistent driver structure
- Reduce false positives

---

## Future Enhancements

-  Semantic search (embedding-based retrieval)
-  Pattern combinations (multi-archetype support)
-  Language-specific variants (C++ RAII versions)
-  Learning loop (update knowledge from results)
-  Cross-references between patterns

---

**Version**: 1.0
**Last Updated**: 2025-10-29
**Maintained by**: OSS-Fuzz-Gen Team

