# Agent Graph Prompts

This directory contains prompt templates for LangGraph agents. Each agent has two types of prompts:

## Prompt Files Structure

For each agent (e.g., `function_analyzer`), there are two files:

1. **`{agent_name}_system.txt`** - System prompt that defines the agent's role and capabilities
2. **`{agent_name}_prompt.txt`** - User prompt template with placeholders for dynamic content

## Available Agents

### 1. Function Analyzer
- **System**: `function_analyzer_system.txt`
- **Prompt**: `function_analyzer_prompt.txt`
- **Purpose**: Analyze C/C++ functions to understand their parameters, types, and fuzzing requirements
- **Key Features**: Analyzes caller patterns, identifies implicit requirements, determines initialization methods

### 2. Prototyper
- **System**: `prototyper_system.txt`
- **Prompt**: `prototyper_prompt.txt`
- **Purpose**: Generate initial LibFuzzer fuzz target code based on function analysis
- **Key Features**: Handles complex type initialization, follows LibFuzzer best practices, ensures deterministic behavior

### 3. Enhancer
- **System**: `enhancer_system.txt`
- **Prompt**: `enhancer_prompt.txt`
- **Purpose**: Fix compilation and runtime errors in fuzz targets
- **Key Features**: Minimal changes to preserve fuzzing logic, handles header/type/linker errors, respects function requirements

### 4. Crash Analyzer
- **System**: `crash_analyzer_system.txt`
- **Prompt**: `crash_analyzer_prompt.txt`
- **Purpose**: Analyze crash reports to determine if bugs are in the driver or target code
- **Key Features**: Distinguishes driver bugs from project bugs, assesses severity, provides actionable recommendations

### 5. Context Analyzer
- **System**: `context_analyzer_system.txt`
- **Prompt**: `context_analyzer_prompt.txt`
- **Purpose**: Determine if crashes are feasible from the project's public entry points
- **Key Features**: Traces execution paths, analyzes variable relationships, provides source code evidence

### 6. Coverage Analyzer
- **System**: `coverage_analyzer_system.txt`
- **Prompt**: `coverage_analyzer_prompt.txt`
- **Purpose**: Analyze and improve code coverage in fuzz targets
- **Key Features**: Identifies uncovered blocks, suggests input preprocessing improvements, recommends setup functions

## Prompt Template Syntax

Prompts use `{VARIABLE_NAME}` placeholders that get replaced with actual values at runtime.

Example from `function_analyzer_prompt.txt`:
```
Function: {FUNCTION_NAME}
Signature: {FUNCTION_SIGNATURE}
```

When used in code:
```python
prompt_manager.build_user_prompt(
    "function_analyzer",
    function_name="foo",
    function_signature="void foo(int x)"
)
```

Results in:
```
Function: foo
Signature: void foo(int x)
```

## Usage in Code

### Loading Prompts

```python
from agent_graph.prompt_loader import get_prompt_manager

# Get the global prompt manager
pm = get_prompt_manager()

# Load system prompt
system_prompt = pm.get_system_prompt("function_analyzer")

# Load and format user prompt
user_prompt = pm.build_user_prompt(
    "function_analyzer",
    project_name="libxml2",
    function_name="xmlParseDocument",
    function_signature="int xmlParseDocument(xmlDocPtr doc)",
    additional_context="This function is part of the XML parsing API"
)
```

### In Agent Classes

```python
class LangGraphFunctionAnalyzer(LangGraphAgent):
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("function_analyzer")
        
        super().__init__(
            name="function_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        # Build user prompt from template
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "function_analyzer",
            project_name=state["benchmark"]["project"],
            function_name=state["benchmark"]["function_name"],
            ...
        )
        
        response = self.chat_llm(state, prompt)
        ...
```

## Benefits of This Architecture

1. **Easy to Modify**: Change prompts without touching code
2. **Version Control**: Track prompt changes separately from code
3. **Testing**: Easy to experiment with different prompts
4. **Collaboration**: Non-programmers can improve prompts
5. **Consistency**: Same pattern as legacy agent system
6. **Caching**: Prompts are cached after first load for performance

## Editing Prompts

To modify a prompt:

1. Open the relevant `.txt` file in `prompts/agent_graph/`
2. Edit the text (preserve `{PLACEHOLDER}` syntax)
3. Save the file
4. Restart the application (prompts are cached)

To add a new agent:

1. Create `{agent_name}_system.txt` with system prompt
2. Create `{agent_name}_prompt.txt` with user prompt template
3. Create agent class in `agent_graph/agents/langgraph_agent.py`
4. Load prompts using `get_prompt_manager()`

## Prompt Content Unification

The prompts in this directory have been carefully designed to unify and improve upon the legacy system in `prompts/agent/`:

**Unification Strategy:**
1. **Content Reuse**: Core knowledge and best practices from legacy prompts have been integrated into the new system
2. **Simplified Structure**: Complex multi-file structures collapsed into clear system + user prompt pairs
3. **Enhanced Guidance**: Added detailed analysis frameworks, step-by-step instructions, and evidence requirements
4. **Consistent Format**: All agents follow the same structure for easier maintenance

**Key Improvements:**
- **Detailed Analysis Frameworks**: Each agent now has explicit analysis steps and decision criteria
- **Evidence Requirements**: Clear guidelines on what evidence to provide (e.g., source code quotes, line numbers)
- **Best Practices**: Incorporated lessons learned from legacy system (e.g., "preserve fuzzing logic", "minimal changes")
- **Comprehensive Coverage**: Added prompts for all agents (Context Analyzer, Coverage Analyzer) previously missing

**Content Sources:**
- `function_analyzer`: Unified from `function-analyzer-{description,instruction,priming}.txt`
- `prototyper`: Enhanced from `prototyper-priming.txt` with OSS-Fuzz best practices
- `enhancer`: Combined from `enhancer-{priming,crash-priming,coverage-priming}.txt`
- `crash_analyzer`: Improved from `crash_analyzer-priming.txt` with severity assessment
- `context_analyzer`: Adapted from `context-analyzer-{description,instruction,priming}.txt`
- `coverage_analyzer`: Enhanced from `coverage-analyzer-priming.txt` with detailed strategies

## Comparison with Legacy System

The legacy agent system (in `prompts/agent/` and `prompts/template_xml/`) used a more complex structure with multiple files and XML-style tags. This new system is simpler:

| Aspect | Legacy System | New System |
|--------|--------------|------------|
| Files per agent | Multiple (priming, instruction, etc.) | 2 (system + prompt) |
| Format | Mixed (XML tags, complex structure) | Simple text with placeholders |
| Loading | Custom per agent type | Unified `PromptManager` |
| Caching | Per-agent implementation | Built into `PromptManager` |
| Complexity | High | Low |
| Coverage | 4 agents fully supported | 6 agents fully supported |
| Maintainability | Harder (scattered across files) | Easier (clear structure) |

## Future Enhancements

Possible improvements:

- Add JSON schema validation for prompt variables
- Support for multi-language prompts
- Prompt versioning system
- A/B testing framework for prompts
- Automated prompt optimization based on results

