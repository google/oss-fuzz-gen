# LogicFuzz

**Automated Fuzz Target Generation using LLM Agents**

LogicFuzz is an intelligent fuzzing framework that leverages Large Language Models (LLMs) to automatically generate high-quality fuzz targets. It uses a **two-phase agentic workflow** to achieve high compilation success rates and maximize code coverage.

---

## 🎯 Key Features

- **🤖 AI-Powered Generation**: Uses LLM agents to analyze functions and generate fuzz targets
- **📊 High Success Rate**: 70-85% compilation success through intelligent error fixing
- **🔄 Iterative Improvement**: Automatically optimizes coverage and discovers real bugs
- **🛡️ Robust Workflow**: Two-phase design with multi-layer protection against failures
- **⚡ Token Efficient**: Optimized prompts with 80% token reduction
- **🔍 FI Integration**: Leverages Fuzz Introspector for enhanced context and better generation quality

**Supported Models:**
- OpenAI GPT (gpt-4, gpt-5)
- Vertex AI Gemini (gemini-2-5-pro-chat)

---

## 📚 Documentation

- **[NEW_PROJECT_SETUP.md](docs/NEW_PROJECT_SETUP.md)** - Complete guide for setting up new projects (private repos, custom codebases)
- **[SIGNATURE_FIX_README.md](docs/SIGNATURE_FIX_README.md)** - Function signature extraction and fixing
- **[Usage.md](Usage.md)** - OSS-Fuzz project quick setup guide
- **[Data Preparation](data_prep/README.md)** - Benchmark YAML generation

---

## 🚀 Quick Start

### Basic Usage

```bash
# Run with default settings
python agent_graph/main.py -y conti-benchmark/cjson.yaml --model gpt-5

# Run with specific function
python agent_graph/main.py -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse --model gpt-5

# Run with Fuzz Introspector context (recommended for better results)
# Note: First launch FI server in a separate terminal - see "With Local FI" section below
python agent_graph/main.py -y conti-benchmark/conti-cmp/mosh.yaml -l gpt-5 -n 5 --context -e http://0.0.0.0:8080/api 2>&1 |tee logicfuzz-1029.log

# Run with custom options
python agent_graph/main.py -y conti-benchmark/cjson.yaml \
  --model gpt-5 \
  --context --max-iterations 5 --run-timeout 600
```

### Alternative Entry Point

```bash
# Using run_logicfuzz.py (equivalent to above)
python run_logicfuzz.py --agent -y conti-benchmark/cjson.yaml --model gpt-5
```

---

## 📐 Architecture Overview

LogicFuzz uses a **Supervisor-Agent Pattern** with multi-agent collaboration:

### 🧠 Two-Phase Workflow

**Phase 1: COMPILATION** → Get the code to compile successfully
- Function Analyzer → Prototyper → Build → Enhancer (up to 3 retries)

**Phase 2: OPTIMIZATION** → Maximize coverage and find bugs  
- Execution → Crash/Coverage Analysis → Enhancer → Iterate

### 🤖 Key Agents

- 🔵 **Supervisor** - Central router deciding next action
- 🟡 **Function Analyzer** - Analyzes API semantics and constraints
- 🟡 **Prototyper** - Generates fuzz target code
- 🟡 **Enhancer** - Fixes errors and improves coverage
- 🔴 **Crash/Context Analyzer** - Validates real bugs vs false positives
- 🔴 **Coverage Analyzer** - Suggests optimization strategies
- 🟣 **Build/Execution** - Compiles and runs fuzzer

### 🧠 Session Memory

Agents share knowledge through **Session Memory**:
- API constraints and usage patterns
- Known error fixes
- Coverage optimization strategies

📖 **For detailed workflow diagrams and agent details, see [agent_graph/README.md](agent_graph/README.md)**

---

## 📁 Project Structure

```
logicfuzz/
├── agent_graph/          # LangGraph workflow & agents
│   ├── workflow.py       # Workflow orchestration
│   ├── nodes/           # Agent implementations
│   └── prompts/         # LLM system prompts
├── conti-benchmark/     # Benchmark YAML files
├── run_logicfuzz.py    # Main runner
└── run_single_fuzz.py  # Single execution
```

---

## 🎓 Usage Examples

### Single Function
```bash
python agent_graph/main.py \
  -y conti-benchmark/libxml2.yaml \
  -f xmlParseDocument \
  --model gpt-5
```

### Multiple Trials
```bash
python agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  --model gpt-5 \
  -n 5
```

### With Fuzz Introspector (Recommended)

For better results, use Fuzz Introspector context:

```bash
# Terminal 1: Start FI server
bash report/launch_local_introspector.sh

# Terminal 2: Run with FI context
python agent_graph/main.py \
  -y conti-benchmark/mosh.yaml \
  --model gpt-5 \
  --context \
  -e http://0.0.0.0:8080/api
```

### New Project Setup

See **[NEW_PROJECT_SETUP.md](docs/NEW_PROJECT_SETUP.md)** for complete guide on testing your own projects

---

\* "Total project lines" measures the source code of the project-under-test compiled and linked by the preexisting human-written fuzz targets from OSS-Fuzz.

\* "Total coverage gain" is calculated using a denominator of the "Total project lines". "Total relative gain" is the increase in coverage compared to the old number of covered lines.

\* Additional code from the project-under-test maybe included when compiling the new fuzz targets and result in high percentage gains.
