# Agent Graph Prompt Refactoring

**Date**: 2025-10-21  
**Status**: ✅ Complete

## Overview

Refactored the LangGraph agent system to store prompts in external files, following the same pattern as the legacy agent system. This makes prompts easier to maintain, test, and modify without touching code.

## Motivation

The original LangGraph agents had prompts hardcoded as Python strings in `agent_graph/agents/langgraph_agent.py`:

```python
# Before
class LangGraphFunctionAnalyzer(LangGraphAgent):
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        system_message = """You are an expert at analyzing C/C++ functions for fuzzing.
Your job is to analyze function signatures, parameters, and return types..."""
```

This made it difficult to:
- Modify prompts without editing code
- Version control prompts separately
- A/B test different prompt variations
- Allow non-programmers to improve prompts
- Maintain consistency across the codebase

## Changes Made

### 1. Created Prompt Template Files

Created directory structure: `prompts/agent_graph/`

For each agent, created two files:
- `{agent_name}_system.txt` - System prompt defining the agent's role
- `{agent_name}_prompt.txt` - User prompt template with `{PLACEHOLDER}` variables

**Agents with prompts:**
- `function_analyzer` - Analyzes function signatures for fuzzing
- `prototyper` - Generates initial fuzz target code
- `enhancer` - Fixes compilation errors
- `crash_analyzer` - Analyzes crash reports

### 2. Created Prompt Loader System

**File:** `agent_graph/prompt_loader.py`

Key components:

```python
class PromptManager:
    def get_system_prompt(agent_name: str) -> str
    def get_user_prompt_template(agent_name: str) -> str
    def build_user_prompt(agent_name: str, **kwargs) -> str
    def clear_cache()

# Global singleton
get_prompt_manager() -> PromptManager
```

Features:
- ✅ Loads prompts from `prompts/agent_graph/`
- ✅ Caches loaded prompts for performance
- ✅ Formats templates with variable substitution
- ✅ Clean, simple API

### 3. Refactored Agent Classes

Updated all LangGraph agent classes to use the prompt loader:

**Before:**
```python
class LangGraphFunctionAnalyzer(LangGraphAgent):
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        system_message = """Hardcoded prompt here..."""
        super().__init__(name="function_analyzer", ...)
    
    def execute(self, state):
        prompt = f"""Hardcoded template with {variables}..."""
        response = self.chat_llm(state, prompt)
```

**After:**
```python
class LangGraphFunctionAnalyzer(LangGraphAgent):
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("function_analyzer")
        super().__init__(name="function_analyzer", ...)
    
    def execute(self, state):
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "function_analyzer",
            project_name=benchmark.get('project'),
            function_name=benchmark.get('function_name'),
            ...
        )
        response = self.chat_llm(state, prompt)
```

### 4. Added Documentation

- **`prompts/agent_graph/README.md`** - Usage guide for prompts
- **`docs/AGENT_GRAPH_PROMPT_REFACTORING.md`** - This document

### 5. Created Test Suite

**File:** `test_prompt_loading.py`

Tests:
- ✅ All prompt files load correctly
- ✅ Template formatting works
- ✅ Variable substitution is correct
- ✅ Caching functionality works
- ✅ All placeholders are replaced

Test results: **All tests passed** ✅

## File Structure

```
logic-fuzz/
├── prompts/
│   └── agent_graph/          # NEW
│       ├── README.md
│       ├── function_analyzer_system.txt
│       ├── function_analyzer_prompt.txt
│       ├── prototyper_system.txt
│       ├── prototyper_prompt.txt
│       ├── enhancer_system.txt
│       ├── enhancer_prompt.txt
│       ├── crash_analyzer_system.txt
│       └── crash_analyzer_prompt.txt
│
├── agent_graph/
│   ├── agents/
│   │   └── langgraph_agent.py    # MODIFIED
│   └── prompt_loader.py           # NEW
│
├── test_prompt_loading.py         # NEW
└── docs/
    └── AGENT_GRAPH_PROMPT_REFACTORING.md  # NEW
```

## Usage Examples

### Loading a System Prompt

```python
from agent_graph.prompt_loader import get_prompt_manager

pm = get_prompt_manager()
system_prompt = pm.get_system_prompt("function_analyzer")
```

### Building a User Prompt

```python
user_prompt = pm.build_user_prompt(
    "function_analyzer",
    project_name="libxml2",
    function_name="xmlParseDocument",
    function_signature="int xmlParseDocument(xmlDocPtr doc)",
    additional_context="Context about the function"
)
```

### Editing Prompts

To change a prompt:
1. Edit the `.txt` file in `prompts/agent_graph/`
2. Save the file
3. Restart the application (prompts are cached)

### Adding a New Agent

1. Create `{agent_name}_system.txt`
2. Create `{agent_name}_prompt.txt`
3. Create agent class in `langgraph_agent.py`
4. Use `get_prompt_manager()` to load prompts

## Benefits

| Benefit | Description |
|---------|-------------|
| **Maintainability** | Prompts separated from code logic |
| **Version Control** | Track prompt evolution separately |
| **Collaboration** | Non-programmers can improve prompts |
| **Testing** | Easy to A/B test prompt variations |
| **Consistency** | Same pattern as legacy agent system |
| **Performance** | Prompts cached after first load |

## Comparison: Legacy vs New System

| Aspect | Legacy (`prompts/agent/`) | New (`prompts/agent_graph/`) |
|--------|---------------------------|------------------------------|
| Files per agent | Multiple (priming, instruction, context) | 2 (system + prompt) |
| Format | XML tags, complex structure | Simple text with `{PLACEHOLDERS}` |
| Loading | Custom per agent | Unified `PromptManager` |
| Caching | Per-agent implementation | Built-in `PromptManager` |
| Complexity | High | Low |
| Maintenance | Difficult | Easy |

## Testing

Run the test suite:

```bash
python3 test_prompt_loading.py
```

Expected output:
```
🧪 Prompt Loading Test Suite

✅ PASS: Load All Prompts
✅ PASS: Prompt Formatting
✅ PASS: Prompt Caching
✅ PASS: format_prompt() Function

🎉 All tests passed!
```

## Migration Notes

### What Changed
- All agent classes now load prompts from files
- Prompt templates use `{VARIABLE}` syntax (uppercase)
- System prompts stored separately from user prompts

### What Didn't Change
- Agent execution logic remains the same
- State management unchanged
- Message history unchanged
- LLM interaction unchanged

### Backward Compatibility
- All existing agent APIs remain the same
- No breaking changes to public interfaces
- Agents work exactly as before, just with external prompts

## Future Enhancements

Potential improvements:
- [ ] JSON schema validation for prompt variables
- [ ] Multi-language prompt support
- [ ] Prompt versioning system
- [ ] A/B testing framework
- [ ] Automated prompt optimization
- [ ] Hot-reloading (no restart needed)
- [ ] Prompt templates with conditions/loops

## Implementation Details

### Prompt Template Format

Templates use simple `{VARIABLE_NAME}` placeholders:

```
Function: {FUNCTION_NAME}
Signature: {FUNCTION_SIGNATURE}
Project: {PROJECT_NAME}
```

Variables are **case-insensitive** when passed to `build_user_prompt()`:
```python
# These are equivalent:
pm.build_user_prompt("agent", function_name="foo")
pm.build_user_prompt("agent", FUNCTION_NAME="foo")
```

### Caching Strategy

Prompts are cached in memory after first load:
- System prompts: Loaded once per agent type
- User templates: Loaded once per agent type
- Formatted prompts: Generated each time (not cached)

Cache can be cleared with `pm.clear_cache()`.

### Error Handling

```python
try:
    prompt = pm.get_system_prompt("nonexistent_agent")
except FileNotFoundError as e:
    print(f"Prompt file not found: {e}")
```

## Verification

All tests pass:
```bash
$ python3 test_prompt_loading.py
🎉 All tests passed!
```

All linters pass:
```bash
$ # No linter errors in modified files
```

## Conclusion

This refactoring successfully:
- ✅ Moved all LangGraph agent prompts to external files
- ✅ Created a clean, simple prompt loading system
- ✅ Maintained backward compatibility
- ✅ Added comprehensive tests
- ✅ Documented the new system
- ✅ Follows the same pattern as legacy agents

The agent_graph system now has the same prompt management benefits as the legacy system, but with a simpler, cleaner implementation.

## References

- Prompt files: `prompts/agent_graph/`
- Prompt loader: `agent_graph/prompt_loader.py`
- Agent classes: `agent_graph/agents/langgraph_agent.py`
- Test suite: `test_prompt_loading.py`
- Usage guide: `prompts/agent_graph/README.md`

