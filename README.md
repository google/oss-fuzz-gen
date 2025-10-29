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

### Two-Phase Workflow

```mermaid
flowchart LR
    subgraph Phase1["Phase 1: COMPILATION"]
        A[Analyze<br/>Function] --> B[Generate<br/>Code]
        B --> C[Build]
        C -->|Failed| D[Fix<br/>Errors]
        D --> C
    end
    
    subgraph Phase2["Phase 2: OPTIMIZATION"]
        E[Execute<br/>Fuzzer] --> F{Result?}
        F -->|Crash| G[Analyze<br/>Crash]
        F -->|Low Cov| H[Analyze<br/>Coverage]
        G --> I[Improve<br/>Code]
        H --> I
        I --> C
    end
    
    C -->|Success| E
    F -->|Good| J([✓ Done])
    G -->|Real Bug| J
    
    style Phase1 fill:#E3F2FD
    style Phase2 fill:#FFF3E0
    style A fill:#FFD700
    style B fill:#FFD700
    style D fill:#FFD700
    style I fill:#FFD700
    style G fill:#FF6347
    style H fill:#FF6347
    style C fill:#DDA0DD
    style E fill:#DDA0DD
    style J fill:#90EE90
```

**Phase 1 (COMPILATION)**: Focus on getting the fuzz target to build
- Analyze target function semantics and constraints
- Generate initial fuzz target with proper setup
- Intelligently fix compilation errors with code context
- Fallback to regeneration if fixing fails

**Phase 2 (OPTIMIZATION)**: Focus on maximizing effectiveness
- Execute fuzzer and collect coverage metrics
- Analyze crashes to distinguish real bugs from false positives
- Suggest and implement coverage improvements
- Iterate until goals achieved or coverage stabilizes

### Agent Components

| Agent | Type | Purpose |
|-------|------|---------|
| **Function Analyzer** | 🟡 LLM | Analyze API semantics, preconditions, constraints |
| **Prototyper** | 🟡 LLM | Generate initial fuzz target and build scripts |
| **Enhancer** | 🟡 LLM | Fix errors and improve code quality |
| **Crash Analyzer** | 🔴 LLM | Classify crash types and severity |
| **Coverage Analyzer** | 🔴 LLM | Suggest coverage improvements |
| **Context Analyzer** | 🔴 LLM | Validate crash feasibility |
| **Build** | 🟣 Non-LLM | Compile fuzz target |
| **Execution** | 🟣 Non-LLM | Run fuzzer and collect metrics |

📖 **For detailed workflow diagrams and implementation details, see [agent_graph/README.md](agent_graph/README.md)**

---

## 🔧 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   User Entry Points                      │
├─────────────────────────────────────────────────────────┤
│  agent_graph/main.py  or  run_logicfuzz.py --agent     │
└────────────────────┬────────────────────────────────────┘
                     ↓
           ┌─────────────────────┐
           │  run_single_fuzz.py │  (Single source of truth)
           └─────────────────────┘
                     ↓
           ┌─────────────────────┐
           │  LangGraph Workflow │  (State machine)
           └─────────────────────┘
                     ↓
      ┌──────────────┴──────────────┐
      ↓                              ↓
┌──────────┐                  ┌──────────┐
│ LLM Nodes│                  │ Non-LLM  │
│ (Agents) │                  │  Nodes   │
└──────────┘                  └──────────┘
      ↓                              ↓
┌─────────────────────────────────────────┐
│         Standard Result Saving          │
└─────────────────────────────────────────┘
```

**Design Principles:**
- ✅ Single source of truth for workflow execution
- ✅ Consistent result format across all modes
- ✅ Standard file structure and behavior
- ✅ Modular agent design for easy extension

---

## 📁 Project Structure

```
logic-fuzz/
├── agent_graph/           # LangGraph workflow implementation
│   ├── agents/           # Agent base classes
│   ├── nodes/            # Workflow nodes (Function Analyzer, Prototyper, etc.)
│   ├── workflow.py       # State machine definition
│   ├── state.py          # Workflow state management
│   └── main.py           # Entry point
├── conti-benchmark/      # Benchmark YAML files
├── prompts/              # LLM prompt templates
├── experiment/           # Evaluation and metrics
├── report/               # Result analysis and reporting
└── run_logicfuzz.py     # Main runner
```

---

## 📖 Documentation

- **[agent_graph/README.md](agent_graph/README.md)** - Detailed workflow diagrams and state machine
- **[data_prep/README.md](data_prep/README.md)** - Benchmark preparation guide

---

## 🎓 Usage Examples

### Testing a New Project (Not in OSS-Fuzz)

Want to test your own project? See our comprehensive guide: **[NEW_PROJECT_SETUP.md](docs/NEW_PROJECT_SETUP.md)**

Quick overview:

```bash
# 1. Create OSS-Fuzz project structure
mkdir -p oss-fuzz/projects/my-project

# 2. Create Dockerfile, build.sh, project.yaml
# See docs/NEW_PROJECT_SETUP.md for templates

# 3. Create benchmark YAML
cat > conti-benchmark/my-project.yaml << 'EOF'
"functions":
- "name": "my_function"
  "params":
  - "name": "data"
    "type": "uint8_t*"
  - "name": "size"
    "type": "size_t"
  "return_type": "int"
  "signature": "int my_function(uint8_t*, size_t)"
"language": "c"
"project": "my-project"
"target_name": "my_fuzzer"
"target_path": "/src/my-project/fuzzer.c"
EOF

# 4. Run LogicFuzz
python agent_graph/main.py -y conti-benchmark/my-project.yaml --model gpt-5
```

**Automated setup from GitHub URL:**

```bash
# Generate OSS-Fuzz project from repository
echo "https://github.com/your-org/your-project" > projects.txt

python3 -m experimental.build_generator.runner \
  -i projects.txt \
  -o generated-builds \
  -m gpt-5 \
  --oss-fuzz oss-fuzz
```

### Generate for Single Function
```bash
python agent_graph/main.py \
  -y conti-benchmark/libxml2.yaml \
  -f xmlParseDocument \
  --model gpt-5
```

### Batch Processing with Multiple Trials
```bash
python agent_graph/main.py \
  -y conti-benchmark/conti-cmp/mosh.yaml \
  --model gpt-5 \
  -n 5
```

### With Local Fuzz Introspector (FI)

LogicFuzz can leverage **Fuzz Introspector** to provide rich context about target functions, including call graphs, complexity analysis, and reachability information. This significantly improves generation quality.

#### Step 1: Launch Local FI Server

Open a **separate terminal window** and run our setup script:

```bash
# From the project root directory
bash report/launch_local_introspector.sh
```

This script will:
- Clone the Fuzz Introspector repository
- Install required dependencies
- Create a database for your benchmark projects
- Start the FI web server on `http://0.0.0.0:8080`

**Note:** Keep this terminal window open while running LogicFuzz. The FI server must remain active.

#### Step 2: Run LogicFuzz with FI Context

In your **main terminal window**, run LogicFuzz with FI integration:

```bash
python agent_graph/main.py \
  -y conti-benchmark/conti-cmp/mosh.yaml \
  --model gpt-5 \
  -n 5 \
  --context \
  -mr 5 \
  -e http://0.0.0.0:8080/api \
  2>&1 | tee logicfuzz-output-1025-fi.log
```

**Parameters explained:**
- `-y conti-benchmark/conti-cmp/mosh.yaml` - Target project configuration
- `--model gpt-5` - LLM model to use
- `-n 5` - Generate 5 fuzz targets per function
- `--context` - **Enable Fuzz Introspector context retrieval**
- `-mr 5` - Maximum retry attempts (5)
- `-e http://0.0.0.0:8080/api` - **FI server endpoint**
- `2>&1 | tee logicfuzz-output-1025-fi.log` - Save output to log file

**💡 Tip:** The `--context` and `-e` flags work together to enable FI integration. Without these, LogicFuzz runs in standalone mode.

**Benefits of using FI:**
- 📊 **Better API Understanding** - Access to function signatures, parameters, and types
- 🔗 **Call Graph Analysis** - Understand function dependencies and relationships
- 🎯 **Targeted Generation** - Focus on complex, high-value functions
- 📈 **Higher Success Rate** - Context-aware code generation reduces errors

#### Workflow Diagram

```
Terminal Window 1              Terminal Window 2
┌─────────────────┐           ┌──────────────────┐
│  FI Server      │           │   LogicFuzz      │
│  (Port 8080)    │◄─────────┤   Main Process   │
└─────────────────┘  Context  └──────────────────┘
        │             Queries
        │
   [Database]
   - Call Graphs
   - Function Info
   - Complexity Data
```

#### Troubleshooting

**FI server not responding?**
```bash
# Check if FI is running
curl http://0.0.0.0:8080

# If not running, restart the server
bash report/launch_local_introspector.sh
```

**Port 8080 already in use?**
```bash
# Find and kill the process using port 8080
lsof -ti:8080 | xargs kill -9

# Restart FI server
bash report/launch_local_introspector.sh
```

### Batch Processing Multiple Projects
```bash
python run_logicfuzz.py \
  --benchmarks-directory conti-benchmark/all \
  --model gpt-5 \
  --num-samples 10
```

---

\* "Total project lines" measures the source code of the project-under-test compiled and linked by the preexisting human-written fuzz targets from OSS-Fuzz.

\* "Total coverage gain" is calculated using a denominator of the "Total project lines". "Total relative gain" is the increase in coverage compared to the old number of covered lines.

\* Additional code from the project-under-test maybe included when compiling the new fuzz targets and result in high percentage gains.
