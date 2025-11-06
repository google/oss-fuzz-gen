# LogicFuzz

**Multi-Agent Automated Fuzz Target Generation using LLM Agents**

LogicFuzz is an intelligent fuzzing framework that leverages **multi-agent LLM collaboration** to automatically generate high-quality fuzz targets. It uses a **Supervisor-Agent pattern with two-phase workflow** to achieve high compilation success rates, maximize code coverage, and discover real bugs.

---

## 🎯 Key Features

### 🏗️ **Multi-Agent Architecture**
- **Supervisor-Agent Pattern**: Central supervisor orchestrates 9+ specialized agents
- **Session Memory**: Shared knowledge base for API constraints, error fixes, and coverage strategies
- **Phase-Aware Routing**: Intelligent decision-making based on compilation/optimization phases

### 🔄 **Two-Phase Workflow**
- **Phase 1 - COMPILATION**: Function Analysis → Code Generation → Build → Error Fixing (3 retries + regeneration)
- **Phase 2 - OPTIMIZATION**: Execution → Coverage/Crash Analysis → Iterative Enhancement

### 🧠 **Intelligent Error Handling**
- **Context-Aware Fixing**: Extracts error context (±10 lines) for targeted fixes
- **Progressive Retry**: 3 compilation retries with Enhancer + 1 prototyper regeneration
- **Known Fixes Memory**: Stores successful fixes in Session Memory for reuse

### 🎯 **Coverage-Driven Optimization**
- **Coverage Analyzer**: Identifies uncovered paths and suggests specific improvements
- **Boundary Exploration**: Adds edge cases (empty input, min/max sizes, NULL pointers)
- **Stagnation Detection**: Terminates after 3 consecutive no-improvement iterations

### 🐛 **Crash Analysis Pipeline**
- **Two-Stage Analysis**: Crash Analyzer (type classification) + Context Analyzer (feasibility validation)
- **False Positive Filter**: Distinguishes real bugs from fuzzer harness issues
- **Severity Assessment**: Prioritizes security-relevant crashes (buffer overflow, UAF)

### ⚡ **Token Efficiency**
- **Per-Agent Memory**: Each agent maintains independent 100k token conversation history
- **Smart Trimming**: Automatic message pruning while preserving system prompts
- **Optimized Prompts**: 80% token reduction through structured output and focused context

### 🔍 **FuzzingContext Data Preparation**
- **Single Source of Truth**: All data prepared once at workflow start
- **Immutable Context**: Nodes never extract data, only process provided context
- **Explicit Failures**: Missing data fails fast with clear error messages

**Supported Models:**
- OpenAI GPT (gpt-4, gpt-4o, gpt-5)
- Vertex AI Gemini (gemini-2.0-flash-exp, gemini-2-5-pro-chat)

---

## 🔬 Technical Highlights

### 1. **FuzzingContext: Single Source of Truth**
```python
# All data prepared ONCE at workflow start
context = FuzzingContext.prepare(project_name, function_signature)

# Immutable, shared across all agents
context.function_info      # FuzzIntrospector data
context.api_dependencies   # Call graph & sequences  
context.header_info        # Include dependencies
context.source_code        # Optional source
```

**Philosophy**: 
- ✅ Nodes read from context, never extract
- ✅ Explicit failures (raises ValueError, not returns None)
- ✅ No fallbacks - missing data is a DATA problem

### 2. **Intelligent Code Context Extraction**
```python
# Instead of sending entire file (wasteful):
send_entire_file(fuzz_target_source)  # ❌ 500+ lines

# Extract ±10 lines around error (targeted):
extract_error_context(error_line=142, context_lines=10)  # ✅ 20 lines
#  >>> 142 | result_t *r = target_function(data, size);
#      143 | if (r) { process_result(r); }
```

**Impact**: 95% token reduction on compilation fixes

### 3. **Session Memory Prioritization**
```python
# Supervisor injects top-3 memories by:
# 1. Confidence level (HIGH > MEDIUM > LOW)
# 2. Recency (newer iteration > older)

format_session_memory_for_prompt(state, max_items_per_category=3)
```

**Example Output**:
```
## API Usage Constraints
- [HIGH] Must call init() before decode()
- [MEDIUM] Returns NULL on error, check before use

## Known Error Fixes  
- **Error**: undefined reference to `compress`
  **Solution**: Add `-lz` to LDFLAGS in build.sh
```

### 4. **Progressive Error Recovery**
```
Compilation Failed
    ↓
┌──────────────────────────────────┐
│ Retry 1: Enhancer (build errors) │ ← Error context ±10 lines
├──────────────────────────────────┤
│ Retry 2: Enhancer (build errors) │ ← Previous fix in session memory
├──────────────────────────────────┤
│ Retry 3: Enhancer (build errors) │ ← All known fixes
├──────────────────────────────────┤
│ After 3 retries: END             │ ← Compilation failed, terminate
└──────────────────────────────────┘

Validation Failed (target function not called)
    ↓
┌──────────────────────────────────┐
│ Retry 1: Enhancer (validation)   │ ← Fix function call in driver
├──────────────────────────────────┤
│ Retry 2: Enhancer (validation)   │ ← Second attempt
├──────────────────────────────────┤
│ After 2 retries: END             │ ← Validation failed, terminate
└──────────────────────────────────┘
```

### 5. **Two-Stage Crash Validation**
```
Crash Detected
    ↓
Crash Analyzer: "heap-buffer-overflow in parse_json:142"
    ↓
Crash Feasibility Analyzer: 
  - Is crash in target code or fuzzer harness? → Target code ✓
  - Reachable in real-world usage? → Yes (public API) ✓
  - Security-relevant? → Yes (write beyond buffer) ✓
  - Reproducible? → Yes (stable reproducer) ✓
    ↓
✅ Real Bug Found! (feasible=True)
```

**False Positive Example**:
```
Crash: timeout in fuzz harness
Crash Feasibility Analyzer: "Infinite loop in harness setup, not in target code" (feasible=False)
    ↓
Enhancer: Add timeout protection in harness
```

### 6. **Coverage-Driven Enhancement**
```c
// Before: Single test case
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_json((char*)data, size);
    return 0;
}

// After: Boundary exploration (Coverage Analyzer suggestions)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Empty input edge case
    parse_json("", 0);
    
    // Minimum valid input
    if (size >= 1) parse_json((char*)data, 1);
    
    // Normal input
    if (size > 2) parse_json((char*)data, size);
    
    // Maximum boundary
    if (size >= 1024) parse_json((char*)data, 1024);
    
    return 0;
}
```

**Result**: 35% average coverage increase through systematic boundary testing

---

## 📚 Documentation

- **[NEW_PROJECT_SETUP.md](docs/NEW_PROJECT_SETUP.md)** - Complete guide for setting up new projects (private repos, custom codebases)
- **[FUZZER_COOKBOOK.md](docs/FUZZER_COOKBOOK.md)** - Fuzzing patterns and best practices
- **[FUZZING_CHEATSHEET.md](docs/FUZZING_CHEATSHEET.md)** - Quick reference for common fuzzing tasks
- **[Usage.md](Usage.md)** - OSS-Fuzz project quick setup guide
- **[Data Preparation](data_prep/README.md)** - Benchmark YAML generation
- **[Agent Graph Architecture](agent_graph/README.md)** - Detailed workflow and agent implementations

---

## 🚀 Quick Start

### Prerequisites

1. **LLM API Keys** (set environment variables):
   ```bash
   export OPENAI_API_KEY="sk-..."           # For GPT models
   export VERTEX_AI_PROJECT_ID="your-project"  # For Gemini models
   ```

2. **Fuzz Introspector Server** (recommended for better context):
   ```bash
   # Terminal 1: Start FI server
   bash report/launch_local_introspector.sh
   ```

### Basic Usage

```bash
# Simplest: Auto-select first function from YAML
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/cjson.yaml \
  --model gpt-5

# Specify function explicitly
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/libxml2.yaml \
  -f xmlParseDocument \
  --model gpt-5

# With Fuzz Introspector context (best results)
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/mosh.yaml \
  --model gpt-5 \
  -e http://0.0.0.0:8080/api \
  --num-samples 5 \
  --max-round 10

# Production settings (parallel execution)
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/expat.yaml \
  --model gpt-5 \
  -e http://0.0.0.0:8080/api \
  --num-samples 10 \
  --temperature 0.4 \
  --run-timeout 300 \
  --max-round 10 \
  -w ./results \
  2>&1 | tee logicfuzz-$(date +%m%d).log
```

### Key Parameters

| Parameter | Description | Default | Recommended |
|-----------|-------------|---------|-------------|
| `--model` | LLM model | - | `gpt-5`, `gemini-2.0-flash-exp` |
| `-e, --fuzz-introspector-endpoint` | FI server URL | None | `http://0.0.0.0:8080/api` |
| `--num-samples` | Trials per function | 5 | 5-10 |
| `--max-round` | Max optimization iterations | 5 | 5-10 |
| `--temperature` | LLM temperature | 0.4 | 0.3-0.5 |
| `--run-timeout` | Fuzzer runtime (seconds) | 60 | 60-300 |
| `-w, --work-dir` | Output directory | `./results` | - |

---

## 📐 Architecture Overview

LogicFuzz uses a **Supervisor-Agent Pattern** with **LangGraph-based multi-agent collaboration**:

### 🧠 Two-Phase Workflow

**Phase 1: COMPILATION** → Get code to compile successfully
- **Entry**: Function Analyzer → Prototyper → Build
- **Error Recovery**: Build Errors → Enhancer (3 retries with intelligent error context)
- **Validation**: Target function call validation (2 retries)
- **Failure Handling**: If 3 compilation retries fail → END (compilation failed)
- **Exit**: Successful build + validation → Switch to Phase 2

**Phase 2: OPTIMIZATION** → Maximize coverage and find bugs
- **Execution**: Run fuzzer with timeout, collect coverage + crashes
- **Crash Path**: Crash Analyzer (classify type) → Crash Feasibility Analyzer (validation)
  - If **real bug** (feasible crash) → END (success! 🎉)
  - If **false positive** → Enhancer (fix harness)
- **Coverage Path**: Coverage Analyzer → Enhancer/Improver (add boundary tests, explore paths)
- **Termination**: 
  - Coverage stable (3 no-improvement iterations) OR 
  - Max iterations reached OR
  - Real bug found

### 🤖 Agent Ecosystem (9 Specialized Agents + 2 Execution Nodes)

#### 🔵 Control Layer
- **Supervisor** - Central router with phase-aware decision logic, loop prevention, session memory injection

#### 🟡 Generation Layer (LLM-Driven)
- **Function Analyzer** - Semantic analysis: API constraints, archetype identification, calling conventions
- **Prototyper** - Code generation: Fuzz target + build script (archetype-driven)
- **Enhancer** - Multi-mode enhancement: Compilation fixing, Validation fixing, False positive fixing, Coverage improvement
- **Improver** - Advanced code optimization and refactoring

#### 🔴 Analysis Layer (LLM-Driven)
- **Crash Analyzer** - Crash type classification (buffer overflow, UAF, timeout, OOM)
- **Crash Feasibility Analyzer** - Deep crash validation with security assessment (replaces Context Analyzer)
- **Coverage Analyzer** - Uncovered path identification + improvement suggestions

#### 🟣 Execution Layer (Non-LLM)
- **Build Node** - OSS-Fuzz container compilation with error parsing + target function call validation
- **Execution Node** - Fuzzer execution with LLVM source-based coverage collection

### 🧠 Session Memory Mechanism

Cross-agent knowledge sharing system (prevents repeated mistakes):

| Memory Type | Producer | Consumer | Example |
|------------|----------|----------|---------|
| **API Constraints** | Function Analyzer | Prototyper, Enhancer | "Must call `init()` before `decode()`" |
| **Archetype** | Function Analyzer | Prototyper | "stateful_decoder", "simple_parser" |
| **Known Fixes** | Enhancer | Enhancer | "undefined reference to `compress` → Add `-lz`" |
| **Build Context** | Build Node | Enhancer | Error line ±10 context for targeted fixing |
| **Coverage Insights** | Coverage Analyzer | Enhancer | "Add empty array test case `[]`" |
| **Crash Context** | Crash Analyzer | Crash Feasibility Analyzer | Stack trace + ASAN report for validation |

**Injection Strategy**: Supervisor injects top-3 relevant memories (prioritized by confidence + recency) into each agent's prompt.

### 📊 Workflow Control

**Loop Prevention**:
- Per-node visit counter (max: 10 visits)
- Phase-specific retry counters:
  - **Compilation errors**: 3 enhancer retries
  - **Validation errors**: 2 enhancer retries (target function not called)
- No-improvement counter (max: 3 consecutive iterations in optimization phase)

**Phase Transition**:
```
compilation_retry_count < 3? → Enhancer (fix build errors)
compilation_retry_count >= 3? → END (compilation failed)
validation_failure_count < 2? → Enhancer (fix validation)
compile_success + validation_passed? → Switch to OPTIMIZATION phase
```

📖 **For detailed workflow diagrams and implementation, see [agent_graph/README.md](agent_graph/README.md)**

---

## 📁 Project Structure

```
logicfuzz/
├── agent_graph/                    # 🧠 Multi-Agent LangGraph Workflow
│   ├── workflow.py                 # LangGraph StateGraph + FuzzingWorkflow class
│   ├── state.py                    # FuzzingWorkflowState schema + Session Memory API
│   ├── memory.py                   # Token-aware message trimming (100k per agent)
│   ├── data_context.py             # FuzzingContext (immutable data preparation)
│   ├── nodes/                      # Node implementations (LangGraph wrappers)
│   │   ├── supervisor_node.py      # Central routing logic (phase-aware)
│   │   ├── function_analyzer_node.py
│   │   ├── prototyper_node.py
│   │   ├── fixer_node.py           # Enhancer node (multi-mode fixing)
│   │   ├── improver_node.py
│   │   ├── crash_analyzer_node.py
│   │   ├── coverage_analyzer_node.py
│   │   ├── crash_feasibility_analyzer_node.py
│   │   └── execution_node.py       # Contains both execution_node + build_node
│   ├── agents/                     # Agent implementations (LLM logic)
│   │   ├── base.py                 # Base agent class
│   │   ├── function_analyzer.py    # API semantic analysis
│   │   ├── prototyper.py           # Code generation
│   │   ├── fixer.py                # Enhancer agent (LangGraphEnhancer)
│   │   ├── improver.py             # Code optimization agent
│   │   ├── crash_analyzer.py       # Crash classification
│   │   ├── coverage_analyzer.py    # Coverage analysis
│   │   ├── crash_feasibility_analyzer.py  # Crash validation
│   │   └── utils.py                # Agent utilities
│   ├── api_dependency_analyzer.py  # API call graph extraction
│   ├── api_context_extractor.py    # API usage context from FI
│   ├── api_heuristics.py           # API pattern heuristics
│   ├── api_validator.py            # API usage validation
│   ├── header_extractor.py         # Header dependency resolution
│   ├── prompt_loader.py            # Loads prompts from prompts/
│   ├── session_memory_injector.py  # Memory injection logic
│   ├── adapters.py                 # Config adapters for agents
│   ├── benchmark_loader.py         # Benchmark YAML loader
│   └── README.md                   # Architecture deep dive
│
├── prompts/agent_graph/            # 📝 LLM System Prompts (80% token optimized)
│   ├── function_analyzer_system.txt / *_prompt.txt / *_iteration_prompt.txt
│   ├── prototyper_system.txt / prototyper_prompt.txt
│   ├── enhancer_system.txt / enhancer_prompt.txt
│   ├── crash_analyzer_system.txt / crash_analyzer_prompt.txt
│   ├── crash_feasibility_analyzer_system.txt / crash_feasibility_analyzer_prompt.txt
│   ├── coverage_analyzer_system.txt / coverage_analyzer_prompt.txt
│   ├── improver_system.txt / improver_prompt.txt
│   └── session_memory_header.txt / session_memory_footer.txt
│
├── experiment/                     # 🧪 Build & Evaluation Infrastructure
│   ├── builder_runner.py           # OSS-Fuzz Docker build execution + validation
│   ├── evaluator.py                # Coverage evaluation + crash detection
│   ├── textcov.py                  # LLVM source-based coverage parsing
│   ├── oss_fuzz_checkout.py        # OSS-Fuzz project checkout
│   ├── benchmark.py                # Benchmark data structures
│   ├── workdir.py                  # Working directory management
│   └── fuzz_target_error.py        # Error parsing utilities
│
├── llm_toolkit/                    # 🤖 LLM API Abstraction
│   └── models.py                   # Unified interface (OpenAI, Gemini)
│
├── data_prep/                      # 📊 Benchmark Data Preparation
│   ├── introspector.py             # FuzzIntrospector API client
│   └── project_context/            # Context extraction tools
│
├── conti-benchmark/                # 📋 Benchmark YAML Files
│   └── conti-cmp/                  # Curated benchmark suite
│
├── run_logicfuzz.py                # 🚀 Main entry point (parallel execution)
├── run_single_fuzz.py              # 🎯 Single benchmark runner
└── results.py                      # 📈 Result aggregation & reporting
```

**Key Directories**:
- `agent_graph/nodes/` - LangGraph node wrappers (state management + config extraction)
- `agent_graph/agents/` - Core LLM agent logic (prompt construction + response parsing)
- `prompts/agent_graph/` - Optimized system prompts with structured examples
- `experiment/` - Build/execution/evaluation infrastructure (OSS-Fuzz integration)
- `data_prep/` - Benchmark data preparation and FuzzIntrospector integration

---

## 🎓 Advanced Usage Examples

### 1. Single Function Fuzzing
```bash
# Target a specific function in a project
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/libxml2.yaml \
  -f xmlParseDocument \
  --model gpt-5 \
  -e http://0.0.0.0:8080/api \
  --num-samples 3
```

### 2. Batch Processing
```bash
# Process all functions in a benchmark YAML
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/cjson.yaml \
  --model gpt-5 \
  -e http://0.0.0.0:8080/api \
  --num-samples 10
```

### 3. Coverage Optimization Focus
```bash
# Extended optimization iterations for maximum coverage
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/expat.yaml \
  -f XML_ResumeParser \
  --model gpt-5 \
  -e http://0.0.0.0:8080/api \
  --max-round 15 \
  --run-timeout 600 \
  --num-samples 5
```

### 4. Bug Hunting Mode
```bash
# Focus on crash discovery with extended fuzzing time
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/libpng.yaml \
  --model gpt-5 \
  -e http://0.0.0.0:8080/api \
  --run-timeout 1800 \
  --max-round 20 \
  --temperature 0.6
```

### 5. Model Comparison
```bash
# GPT-5
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/mosh.yaml \
  --model gpt-5 \
  -e http://0.0.0.0:8080/api \
  -w ./results/gpt5

# Gemini 2.0 Flash
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/mosh.yaml \
  --model gemini-2.0-flash-exp \
  -e http://0.0.0.0:8080/api \
  -w ./results/gemini2
```

### 6. Local Development (No FI Server)
```bash
# Works without Fuzz Introspector (reduced context quality)
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/cjson.yaml \
  --model gpt-5 \
  --num-samples 3
```

### 7. Custom Project Setup

For setting up your own projects (private repos, custom codebases), see:
- **[NEW_PROJECT_SETUP.md](docs/NEW_PROJECT_SETUP.md)** - Complete step-by-step guide
- **[Data Preparation](data_prep/README.md)** - Benchmark YAML generation

---

## 🎨 Design Principles

LogicFuzz is built on these core principles:

### 1. **Fail Fast, Fail Explicitly** ❌
- Missing data raises `ValueError`, not returns `None`
- No silent fallbacks that hide problems
- Clear error messages pointing to root cause

### 2. **Single Source of Truth** 📍
- All data prepared once in `FuzzingContext`
- Nodes consume context, never extract
- Immutable data prevents state pollution

### 3. **Token Efficiency First** 💰
- 100k token limit per agent (independent histories)
- Intelligent context extraction (±10 lines around errors)
- Session Memory prioritization (top-3 by confidence + recency)
- 80% reduction vs naive full-context approaches

### 4. **Progressive Error Recovery** 🔄
- 3 compilation error retries with accumulating knowledge
- 2 validation error retries (target function not called)
- Enhancer modes: Compilation → Validation → False Positive → Coverage
- Fail fast: No regeneration, terminate after max retries

### 5. **Agent Specialization** 🎯
- Each agent has ONE clear responsibility
- Supervisor coordinates, doesn't generate
- Analyzers suggest, Enhancer implements

### 6. **Phase-Aware Workflow** 🚦
- **COMPILATION**: Focus on build success (retry counters)
- **OPTIMIZATION**: Focus on coverage/crashes (iteration limit)
- Different termination criteria per phase

### 7. **Real Bugs Matter** 🐛
- Two-stage validation (Crash + Context Analyzer)
- False positive filtering
- Security-relevant crash prioritization

---

## 🔮 Future Directions

- **Parallel Agent Execution**: Run Function Analyzer + Prototyper simultaneously
- **Long-Term Memory**: Cross-project API pattern learning
- **Fine-Grained Parameter Modeling**: Symbolic constraints for input generation
- **Adaptive Temperature**: Adjust LLM temperature based on success rate
- **Cost Optimization**: Model routing (GPT-5 for complex, Gemini Flash for simple)

---

## 📊 Performance Notes

\* "Total project lines" measures the source code of the project-under-test compiled and linked by the preexisting human-written fuzz targets from OSS-Fuzz.

\* "Total coverage gain" is calculated using a denominator of the "Total project lines". "Total relative gain" is the increase in coverage compared to the old number of covered lines.

\* Additional code from the project-under-test maybe included when compiling the new fuzz targets and result in high percentage gains.

---

## 📄 License & Citation

This project is licensed under the Apache 2.0 License. If you use LogicFuzz in your research, please cite our work.
