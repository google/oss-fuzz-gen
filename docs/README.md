# LogicFuzz Documentation

Welcome to the LogicFuzz documentation hub! This directory contains comprehensive guides for using LogicFuzz with various types of projects.

## 📚 Documentation Index

### 🆕 [NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md) - **Complete Guide for New Projects**
**Best for:** Private repositories, custom codebases, non-OSS-Fuzz projects

Comprehensive 770+ line guide covering:
- ✅ **3 Setup Methods**: Manual, automated, and from existing codebase
- ✅ **Detailed Templates**: Dockerfile, build.sh, project.yaml, benchmark YAML
- ✅ **Real-World Examples**: JSON parser, image processing, multi-function projects
- ✅ **Language Support**: C, C++, Python, Java, Rust
- ✅ **Private Repos**: Special instructions for internal/proprietary code
- ✅ **Troubleshooting**: Common issues and solutions
- ✅ **Build Generator**: Automated OSS-Fuzz project creation from GitHub URLs

**When to use:**
- 🔒 Testing private/internal codebases
- 🆕 Setting up projects not yet in OSS-Fuzz
- 🛠️ Need complete setup instructions from scratch
- 🤖 Want automated build script generation

---

### 🔧 [SIGNATURE_FIX_README.md](SIGNATURE_FIX_README.md) - Function Signature Handling
**Best for:** Understanding signature extraction and fixing

Detailed guide on:
- Function signature extraction from C/C++ code
- Parsing and fixing malformed signatures
- Type resolution and parameter handling
- Integration with LogicFuzz workflow

**When to use:**
- 🔍 Debugging signature parsing errors
- 🛠️ Manual signature extraction needed
- 📝 Creating custom benchmark YAMLs
- 🐛 Fixing signature-related generation issues

---

### 📖 Additional Documentation

#### [../README.md](../README.md) - **Main Project Overview**
- Key features and capabilities
- Quick start examples
- Installation instructions
- FI integration setup
- Performance metrics

#### [../Usage.md](../Usage.md) - **OSS-Fuzz Quick Setup**
- OSS-Fuzz project templates
- Standard conventions and environment variables
- Language-specific configurations (C/C++, Java, Python, Rust)
- Testing and running workflows
- Best practices and common issues

#### [../data_prep/README.md](../data_prep/README.md) - **Benchmark Preparation**
- Generating benchmark YAML files
- Using introspector for function discovery
- Fuzz target examples
- Training data generation

#### [../agent_graph/README.md](../agent_graph/README.md) - **Workflow Architecture**
- Two-phase agentic workflow
- State machine diagrams
- Node definitions
- Error handling strategies

---

## 🚀 Quick Navigation

### I want to...

#### Test an existing OSS-Fuzz project
```bash
# See: ../README.md Quick Start section
python agent_graph/main.py -y conti-benchmark/cjson.yaml --model gpt-5
```
📖 **Read:** [Main README](../README.md) → Quick Start

#### Set up my private repository for fuzzing
```bash
# See: NEW_PROJECT_SETUP.md → Method 3
# Complete guide for private/internal codebases
```
📖 **Read:** [NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md) → Method 3: From Existing Codebase

#### Automatically generate OSS-Fuzz project from GitHub
```bash
# See: NEW_PROJECT_SETUP.md → Method 2
echo "https://github.com/your-org/your-project" > projects.txt
python3 -m experimental.build_generator.runner \
  -i projects.txt -o generated-builds -m gpt-5 --oss-fuzz oss-fuzz
```
📖 **Read:** [NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md) → Method 2: Automated Build Generation

#### Create a benchmark YAML file
```bash
# Option 1: Use introspector for OSS-Fuzz projects
python -m data_prep.introspector my-project -m 5 -o conti-benchmark/

# Option 2: Manual creation (see template)
```
📖 **Read:** 
- [NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md) → Configuration Files
- [../data_prep/README.md](../data_prep/README.md)

#### Fix function signature issues
```bash
# Use signature fixing tools
python -m llm_toolkit.signature_fixer <signature>
```
📖 **Read:** [SIGNATURE_FIX_README.md](SIGNATURE_FIX_README.md)

#### Integrate with Fuzz Introspector
```bash
# Terminal 1: Start FI server
bash report/launch_local_introspector.sh

# Terminal 2: Run with FI context
python agent_graph/main.py \
  -y conti-benchmark/my-project.yaml \
  --model gpt-5 --context -e http://0.0.0.0:8080/api
```
📖 **Read:** [Main README](../README.md) → With Local Fuzz Introspector

---

## 📝 Documentation Comparison

| Document | Focus | Length | Best For |
|----------|-------|--------|----------|
| [NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md) | Complete new project setup | 770+ lines | Private repos, custom projects, step-by-step |
| [SIGNATURE_FIX_README.md](SIGNATURE_FIX_README.md) | Function signature handling | 160+ lines | Debugging signatures, manual extraction |
| [../README.md](../README.md) | Project overview & quick start | 360+ lines | First-time users, feature overview |
| [../Usage.md](../Usage.md) | OSS-Fuzz templates | 280+ lines | Standard OSS-Fuzz project setup |
| [../data_prep/README.md](../data_prep/README.md) | Benchmark generation | Short | Automated YAML creation |

---

## 🎯 Recommended Reading Order

### For New Users (OSS-Fuzz projects)
1. [../README.md](../README.md) - Understand LogicFuzz capabilities
2. [../Usage.md](../Usage.md) - Learn OSS-Fuzz conventions
3. [../data_prep/README.md](../data_prep/README.md) - Generate benchmarks

### For Custom/Private Projects
1. [../README.md](../README.md) - Understand LogicFuzz capabilities
2. **[NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md)** - Complete setup guide ⭐
3. [SIGNATURE_FIX_README.md](SIGNATURE_FIX_README.md) - Handle signature issues

### For Advanced Users
1. [../agent_graph/README.md](../agent_graph/README.md) - Workflow internals
2. [SIGNATURE_FIX_README.md](SIGNATURE_FIX_README.md) - Advanced debugging
3. [NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md) - Build automation

---

## 💡 Tips for Success

### 1. Start Simple
Begin with a single function in your project:
```bash
python agent_graph/main.py -y conti-benchmark/my-project.yaml \
  -f simple_function --model gpt-5
```

### 2. Use FI for Better Results
Always use Fuzz Introspector context when available:
```bash
# Significantly improves generation quality
--context -e http://0.0.0.0:8080/api
```

### 3. Choose Good Fuzzing Targets
Focus on:
- ✅ Parsing/deserialization functions
- ✅ Input validation routines
- ✅ Complex algorithms with branches
- ❌ Avoid simple getters/setters

### 4. Iterate and Refine
```bash
# First attempt: basic generation
python agent_graph/main.py -y my-project.yaml --model gpt-5

# Review errors, fix signatures
# Second attempt: with more samples
python agent_graph/main.py -y my-project.yaml --model gpt-5 -n 10
```

---

## 🔗 External Resources

### OSS-Fuzz
- [OSS-Fuzz Documentation](https://google.github.io/oss-fuzz/)
- [New Project Guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
- [Project Examples](https://github.com/google/oss-fuzz/tree/master/projects)

### Fuzz Introspector
- [FI Repository](https://github.com/ossf/fuzz-introspector)
- [FI Documentation](https://github.com/ossf/fuzz-introspector/tree/main/doc)

### Fuzzing Resources
- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)

---

## 🤝 Contributing

Found an issue or want to improve the documentation? Please:
1. Open an issue describing the problem
2. Submit a pull request with improvements
3. Share your use cases and examples

---

## 📬 Need Help?

- 📖 Check the [Troubleshooting](NEW_PROJECT_SETUP.md#troubleshooting) section
- 🐛 File an issue on GitHub
- 💬 Ask questions in discussions

**Happy Fuzzing! 🎉**

