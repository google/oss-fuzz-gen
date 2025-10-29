# Function Analyzer Prompts Optimization Summary

**Date**: 2025-10-29
**Optimized Files**: 4 prompt files in `prompts/agent_graph/`

---

## 🎯 Optimization Goals

1. **Theory-guided**: Integrate Hoare Logic (preconditions/postconditions) and Typestate (lifecycle analysis)
2. **Evidence-based**: Reference empirical patterns from 4,699 OSS-Fuzz drivers
3. **Structured output**: Reduce LLM free-form generation with clear sections
4. **Actionable**: Generate concrete driver specifications, not abstract descriptions
5. **Concise**: Keep prompts short (35-60 lines) for better LLM compliance

---

## 📐 Key Design Principles

### 1. Hoare Logic Framework
Every analysis follows: **Preconditions → [API Call] → Postconditions**
- Preconditions: What must be true before calling (null checks, state requirements)
- Postconditions: What's guaranteed after calling (return values, state changes)

### 2. Typestate Analysis
Track object lifecycle: `uninitialized → initialized → active → closed → freed`
- Identify which functions transition states
- Flag invalid transitions that cause crashes

### 3. Archetype Recognition
Classify APIs by behavioral patterns (from FUZZER_BEHAVIOR_TAXONOMY.md):
- Stateless Parser
- Object Lifecycle
- State Machine
- Stream Processor
- Round-trip Validator
- File-based

### 4. Evidence-Driven
- Cite source code (file:line) or example numbers
- Distinguish high-confidence (N examples) vs. low-confidence (1 example)
- Identify precondition violations that cause crashes

---

## 🔧 Changes by File

### 1. `function_analyzer_system.txt` (18 → 36 lines)

**Added**:
- ARCHETYPE RECOGNITION section with 6 pattern types
- CRITICAL section emphasizing return value checks

**Kept**:
- Core Hoare Logic framework (preconditions/postconditions)
- Evidence requirements
- Concise output style

### 2. `function_analyzer_initial_prompt.txt` (18 → 35 lines)

**Added**:
- Structured sections with numbered headers
- Archetype hypothesis checklist (6 options)
- Explicit questions for preconditions/postconditions

**Improved**:
- From open-ended "provide analysis" to specific questions
- Checkboxes for archetype selection
- Evidence field for every choice

### 3. `function_analyzer_iteration_prompt.txt` (41 → 59 lines)

**Added**:
- 6 structured sections (Preconditions, Postconditions, Setup Sequence, etc.)
- Explicit questions for each section
- Comparison with previous examples
- Fuzzing implications for parameters

**Improved**:
- From "note any insights" to specific extraction tasks
- Evidence requirements for each claim
- Archetype validation per example

### 4. `function_analyzer_final_summary_prompt.txt` (72 → 180 lines)

**Major restructuring**:

**Section 1: Archetype & Reference Template**
- Choose ONE archetype from 6 options
- Reference FUZZER_COOKBOOK.md scenario
- Evidence from N examples

**Section 2: Preconditions**
- Structured format: MUST / Reason / Evidence / Violation / Driver code
- CRITICAL tag to emphasize importance

**Section 3: Setup Sequence**
- Standard flow with confidence levels
- Alternative flows if multiple patterns exist

**Section 4: Parameter Fuzzing Strategy**
- YAML format per parameter
- Strategy: DIRECT_FUZZ | CONSTRAIN | FIX
- Actual C code for driver

**Section 5: Postconditions & Error Handling** (NEW - key improvement)
- Return value semantics with evidence
- Status checks in YAML format
- Common error patterns (NULL, negative, false)
- Driver template with inline comments explaining postconditions
- Resource management checklist

**Section 6: Driver Skeleton**
- Complete C code template
- Comments for each section
- Explicit return value checks

**Section 7: Common Pitfalls to Avoid** (NEW)
- 4 categories of errors
- Checklist format

**Section 8: Confidence Assessment**
- High/Medium/Low confidence levels
- Transparency about uncertainty

**Session Memory Updates**:
- JSON format for structured data
- Archetype, setup, constraints

---

## 🎓 Theoretical Foundations Integrated

### From Formal Methods
- **Hoare Logic**: {P} C {Q} - precondition P, command C, postcondition Q
- **Typestate**: Object state machines with valid/invalid transitions

### From Empirical Studies
- **FUZZER_BEHAVIOR_TAXONOMY.md**: 5 dimensions of fuzzer behavior
- **FUZZER_COOKBOOK.md**: Concrete scenarios with code templates

---

## ✅ Quality Improvements

### Reduced LLM Hallucination
- Structured questions → less free-form speculation
- Evidence requirements → grounded in source code
- Confidence levels → transparent about uncertainty

### Increased Actionability
- Concrete code snippets → not pseudo-code
- FUZZER_COOKBOOK references → reuse proven patterns
- YAML/JSON formats → machine-parseable

### Better Specification Quality
- Archetype identification → correct driver skeleton
- Postcondition analysis → prevent false positives
- Pitfalls checklist → catch common mistakes

---

## 📊 Metrics to Track

After deployment, measure:
1. **Specification completeness**: % with setup sequence, preconditions, postconditions
2. **Driver correctness**: % that compile, pass sanitizers, find bugs
3. **False positive rate**: crashes from API misuse vs. real bugs
4. **Coverage**: compared to manual harnesses

---

## 🔄 Future Enhancements

Potential improvements for later iterations:
1. Add constraint solver hints for complex preconditions
2. Integrate taint analysis for data flow tracking
3. Add C++ specific patterns (RAII, exceptions, templates)
4. Generate initial seeds based on archetype

---

## 📚 References

- Hoare Logic: Hoare, C.A.R. (1969). "An axiomatic basis for computer programming"
- Typestate: Strom & Yemini (1986). "Typestate: A programming language concept"
- FUZZER_BEHAVIOR_TAXONOMY.md: Empirical analysis of OSS-Fuzz drivers
- FUZZER_COOKBOOK.md: Practical templates from real-world fuzzers

