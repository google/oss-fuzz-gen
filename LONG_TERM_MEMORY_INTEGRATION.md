# Long-term Memory Integration Guide

**Date**: 2025-10-29
**Status**: ✅ Completed

---

## 🎯 Overview

This document describes how long-term memory knowledge base is integrated into the fuzzing workflow.

The integration enables:
1. **Function Analyzer**: Retrieves archetype knowledge to guide specification generation
2. **Prototyper**: Retrieves code skeletons to structure driver generation

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Fuzzing Workflow                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐           ┌──────────────────┐        │
│  │ Function         │  Archetype │ Long-term        │        │
│  │ Analyzer         │◄──────────►│ Memory           │        │
│  │                  │  Knowledge  │ Knowledge Base   │        │
│  └────────┬─────────┘            │                  │        │
│           │                       │ • Archetypes     │        │
│           │ Specification         │ • Skeletons      │        │
│           │                       │ • Pitfalls       │        │
│           ▼                       └────────▲─────────┘        │
│  ┌──────────────────┐                     │                  │
│  │ Prototyper       │  Skeleton           │                  │
│  │                  │◄────────────────────┘                  │
│  │                  │                                         │
│  └────────┬─────────┘                                        │
│           │                                                   │
│           ▼                                                   │
│     Fuzz Driver                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Integration Points

### 1. Function Analyzer Integration

**Location**: `agent_graph/agents/langgraph_agent.py` - `LangGraphFunctionAnalyzer`

**Method**: `_execute_iterative_analysis()` (lines 364-381)

**What it does**:
1. Analyzes function through iterative conversation
2. Before generating final summary, calls `_retrieve_archetype_knowledge()`
3. Injects archetype knowledge into the final summary prompt
4. LLM uses this knowledge as reference when generating specification

**Code Flow**:
```python
# Phase 4: Generate final comprehensive analysis
archetype_knowledge = self._retrieve_archetype_knowledge(state)

final_prompt = prompt_manager.build_user_prompt(
    "function_analyzer_final_summary",
    PROJECT_NAME=project_name,
    FUNCTION_SIGNATURE=function_signature,
    EXAMPLES_COUNT=examples_analyzed,
    ARCHETYPE_KNOWLEDGE=archetype_knowledge  # ← Injected here
)

final_response = self.chat_llm(state, final_prompt)
```

**Archetype Inference**:
```python
def _infer_archetype_from_history(self, state) -> Optional[str]:
    """Infer archetype from conversation history."""
    # Checks last 5 messages for archetype keywords
    # Scores each archetype based on keyword matches
    # Returns highest-scoring archetype
```

**Keyword Matching**:
```python
archetype_keywords = {
    "stateless_parser": ["stateless", "parse", "single call", "no state"],
    "object_lifecycle": ["create", "destroy", "lifecycle", "init", "free"],
    "state_machine": ["state machine", "multi-step", "sequence", "configure"],
    "stream_processor": ["stream", "chunk", "incremental", "loop"],
    "round_trip": ["round-trip", "encode", "decode", "compress"],
    "file_based": ["file path", "filename", "temp file"]
}
```

**Retrieved Knowledge Format**:
```markdown
# Relevant Pattern Knowledge

## Archetype: object_lifecycle

{full archetype documentation}

## Common Pitfalls
### initialization_errors
{first 500 chars of pitfall doc}...

### data_argument_errors
{first 500 chars of pitfall doc}...
```

---

### 2. Prototyper Integration

**Location**: `agent_graph/agents/langgraph_agent.py` - `LangGraphPrototyper`

**Method**: `execute()` (lines 652-664)

**What it does**:
1. Receives function analysis specification
2. Extracts archetype from specification using regex
3. Retrieves corresponding skeleton code
4. Injects skeleton into prototyper prompt
5. LLM adapts skeleton to generate actual driver

**Code Flow**:
```python
# Retrieve skeleton from long-term memory based on archetype
skeleton_code = self._retrieve_skeleton(function_analysis)

base_prompt = prompt_manager.build_user_prompt(
    "prototyper",
    project_name=benchmark.get('project', 'unknown'),
    function_name=benchmark.get('function_name', 'unknown'),
    function_signature=benchmark.get('function_signature', 'unknown'),
    language=language,
    function_analysis=function_analysis.get('raw_analysis', '...'),
    additional_context=additional_context,
    skeleton_code=skeleton_code  # ← Injected here
)
```

**Archetype Extraction**:
```python
def _extract_archetype_from_analysis(self, analysis_text) -> Optional[str]:
    """Extract archetype from function analysis text."""
    # Pattern 1: "Primary pattern: Object Lifecycle"
    pattern1 = r"Primary pattern:\s*([A-Za-z\-\s]+)"
    
    # Pattern 2: "Archetype: Object Lifecycle"
    pattern2 = r"Archetype:\s*([A-Za-z\-\s]+)"
    
    # Normalize to archetype names
    mapping = {
        "stateless parser": "stateless_parser",
        "object lifecycle": "object_lifecycle",
        "state machine": "state_machine",
        "stream processor": "stream_processor",
        "round-trip": "round_trip",
        "file-based": "file_based"
    }
```

**Retrieved Skeleton Format**:
```markdown
# Reference Skeleton (adapt this structure)

```c
// Object Lifecycle Skeleton
// Pattern: create → use → destroy

#include <stddef.h>
#include <stdint.h>
// Include target API headers here

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation
  if (size < MIN_SIZE) return 0;
  
  // Step 1: Create object
  OBJECT_TYPE *obj = OBJECT_CREATE();
  if (!obj) return 0;  // Postcondition: check NULL
  
  // Step 2: Use object
  int ret = OBJECT_PROCESS(obj, data, size);
  if (ret < 0) goto cleanup;
  
  // Step 3: Destroy
cleanup:
  OBJECT_DESTROY(obj);
  return 0;
}
```

Adapt this skeleton according to the specification above.
```

---

## 📝 Prompt Template Updates

### 1. function_analyzer_final_summary_prompt.txt

**Change**:
```diff
Based on {EXAMPLES_COUNT} usage examples, generate a driver specification for `{FUNCTION_SIGNATURE}`.

Accumulated analysis: {API_MODEL_JSON}

+{ARCHETYPE_KNOWLEDGE}
+
---

OUTPUT SPECIFICATION
```

**Purpose**: Inject archetype knowledge before the LLM starts writing the specification.

---

### 2. prototyper_prompt.txt

**Change**:
```diff
Translate the following specification into a compilable fuzz target:

**Project**: {PROJECT_NAME}
**Function**: {FUNCTION_NAME}
**Signature**: {FUNCTION_SIGNATURE}

**Specification**:
{FUNCTION_ANALYSIS}

+{SKELETON_CODE}
+
{ADDITIONAL_CONTEXT}

**Task**: Generate the fuzz target by:
```

**Purpose**: Provide skeleton code as a structural reference for the LLM.

---

## 🔄 Data Flow

### End-to-End Example

```
1. Function Analyzer starts
   └─> Analyzes usage examples through conversation
   └─> Conversation mentions "create", "destroy", "lifecycle"
   └─> _infer_archetype_from_history() → "object_lifecycle"
   └─> Retrieves archetype knowledge + relevant pitfalls
   └─> Injects knowledge into final summary prompt
   └─> Generates specification with archetype="Object Lifecycle"
   
2. Prototyper starts
   └─> Receives specification
   └─> _extract_archetype_from_analysis() finds "Primary pattern: Object Lifecycle"
   └─> Retrieves object_lifecycle_skeleton.c
   └─> Injects skeleton into prompt
   └─> LLM adapts skeleton:
       - Replace OBJECT_TYPE with actual type
       - Replace OBJECT_CREATE with actual function
       - Replace OBJECT_PROCESS with actual function
       - Replace OBJECT_DESTROY with actual function
   └─> Generates complete, compilable driver
```

---

## 📊 Benefits

### Before Integration

```
Function Analyzer:
  - Generic prompt
  - No pattern reference
  - LLM guesses structure
  
Prototyper:
  - Generic prompt
  - LLM writes driver from scratch
  - Inconsistent structure
```

### After Integration

```
Function Analyzer:
  - Archetype knowledge injected
  - LLM references concrete patterns
  - Structured specification
  
Prototyper:
  - Skeleton code provided
  - LLM fills in details
  - Consistent structure
  - Correct postcondition check locations
```

---

## 🧪 Testing

### Manual Test

Run on a sample API:
```bash
cd /home/likaixuan/fuzzing/oss-fuzz-gen

# Test on libGEOS (object lifecycle pattern)
python run_one_experiment.py \
  --model gpt-4 \
  --project libgeos \
  --function "GEOSGeomFromWKT_r" \
  --num-samples 1
```

**Expected**:
1. Function Analyzer logs: "Inferred archetype: object_lifecycle"
2. Specification contains: "Primary pattern: Object Lifecycle"
3. Prototyper logs: "Retrieving skeleton for archetype: object_lifecycle"
4. Generated driver follows object_lifecycle_skeleton structure

---

### Verification Points

**Function Analyzer**:
- [ ] Check logs for "Inferred archetype: {name}"
- [ ] Check requirements file contains archetype knowledge
- [ ] Verify specification has "Primary pattern: ..." section

**Prototyper**:
- [ ] Check logs for "Retrieving skeleton for archetype: {name}"
- [ ] Verify generated code structure matches skeleton
- [ ] Verify postcondition checks are in correct locations

---

## 🔍 Debugging

### Enable Debug Logging

Add to your run script:
```python
import logging
logging.getLogger('agent_graph').setLevel(logging.DEBUG)
```

**Key Log Messages**:
```
# Function Analyzer
INFO: Inferred archetype: {archetype}, retrieving knowledge
DEBUG: Retrieved {N} chars of archetype knowledge

# Prototyper  
INFO: Retrieving skeleton for archetype: {archetype}
DEBUG: Extracted archetype: {archetype} from analysis
```

### Common Issues

**Issue**: Archetype not inferred
- **Cause**: Keywords not found in conversation
- **Solution**: Check `archetype_keywords` mapping, add more keywords

**Issue**: Skeleton not retrieved
- **Cause**: Archetype name mismatch
- **Solution**: Check `mapping` in `_extract_archetype_from_analysis()`

**Issue**: Knowledge not injected
- **Cause**: Template placeholder not found
- **Solution**: Verify `{ARCHETYPE_KNOWLEDGE}` and `{SKELETON_CODE}` in prompts

---

## 📁 File Changes Summary

### Modified Files

1. **agent_graph/agents/langgraph_agent.py**
   - Added `_retrieve_archetype_knowledge()` to `LangGraphFunctionAnalyzer`
   - Added `_infer_archetype_from_history()` to `LangGraphFunctionAnalyzer`
   - Added `_retrieve_skeleton()` to `LangGraphPrototyper`
   - Added `_extract_archetype_from_analysis()` to `LangGraphPrototyper`

2. **prompts/agent_graph/function_analyzer_final_summary_prompt.txt**
   - Added `{ARCHETYPE_KNOWLEDGE}` placeholder

3. **prompts/agent_graph/prototyper_prompt.txt**
   - Added `{SKELETON_CODE}` placeholder

### New Files Created (Phase 2)

- `long_term_memory/` directory structure
- 6 archetype files
- 6 skeleton files
- 4 pitfall files
- `retrieval.py`
- `README.md`

---

## 🚀 Next Steps

### Immediate
- [x] Test on 3-5 APIs with different archetypes
- [ ] Verify compile rate (should be ≥90%)
- [ ] Validate postcondition checks are present

### Short-term
- [ ] Add metrics tracking (archetype distribution, skeleton usage)
- [ ] Refine keyword matching based on results
- [ ] Add more archetype patterns if needed

### Long-term
- [ ] Implement semantic search (embedding-based archetype matching)
- [ ] Add learning loop (update knowledge from successful drivers)
- [ ] Create C++ RAII variants of skeletons

---

## ✅ Integration Checklist

- [x] Function Analyzer retrieves archetype knowledge
- [x] Knowledge injected into final summary prompt
- [x] Prototyper retrieves skeleton code
- [x] Skeleton injected into prototyper prompt
- [x] Prompt templates updated
- [x] No linter errors
- [x] Documentation complete

**Status**: ✅ **Integration Complete and Ready for Testing**

---

## 📞 Contact

For issues or questions about the integration:
- Check logs for DEBUG messages
- Review this document
- Test with known APIs first
- Validate against skeleton structure

**The long-term memory integration is now live!** 🎉

