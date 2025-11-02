# LogicFuzz Documentation

Welcome to the LogicFuzz documentation hub! This directory contains comprehensive guides for using LogicFuzz with various types of projects.

**最后更新**: 2025-11-01

---

## 📚 文档分类

### 🎯 实现状态文档

#### [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) - **当前实现状态** ⭐
**推荐优先阅读**

全面记录 LogicFuzz v2.0 的实现状态：
- ✅ **已实现功能**: LangGraph 工作流、Session Memory、SRS 格式等
- 🔴 **设计方案**: 知识库、Skeleton Refinement 等未实现特性
- 📊 **功能对比**: 清晰区分实现和设计
- 🗺️ **架构总览**: 11个核心功能模块详解

**适合**:
- 想了解当前系统能力
- 需要区分已实现和设计中的功能
- 计划贡献代码前的参考

---

### 🚀 使用指南

#### 🆕 [NEW_PROJECT_SETUP.md](NEW_PROJECT_SETUP.md) - **新项目设置完整指南**
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

#### 🔧 [SIGNATURE_FIX_README.md](SIGNATURE_FIX_README.md) - **函数签名处理**
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

### 📚 Fuzzer 编写参考文档

这些是独立的参考/教学文档，基于 4699 个真实 OSS-Fuzz fuzzer 的分析：

#### [README_FUZZING.md](README_FUZZING.md) - **Fuzzer 编写总目录**
- 文档导航和索引
- 快速开始指南
- 按场景选择文档

#### [FUZZER_COOKBOOK.md](FUZZER_COOKBOOK.md) - **实战手册** 🔥
- 11 种典型场景的完整代码模板
- 可直接复制粘贴使用
- 包含真实项目参考
- 常见问题解决方案

#### [FUZZER_BEHAVIOR_TAXONOMY.md](FUZZER_BEHAVIOR_TAXONOMY.md) - **行为分类体系**
- 系统化的 5 维度分类框架
- 8 个典型组合模式
- 决策流程图
- 深入学习材料

#### [FUZZING_CHEATSHEET.md](FUZZING_CHEATSHEET.md) - **速查表**
- 一页纸快速参考
- 3 个标准模板
- 常见错误和解决方案
- 命令行参考

---

### 🏗️ 架构文档

#### [../agent_graph/README.md](../agent_graph/README.md) - **Workflow 架构详解**
- Two-phase agentic workflow (Compilation + Optimization)
- 8 个 agent/node 详细说明
- Session Memory 机制
- State machine 流程图
- Loop control 和终止条件
- 实现模式和代码示例

#### [../README.md](../README.md) - **项目总览**
- Key features and capabilities
- Quick start examples
- Installation instructions
- FI integration setup
- Architecture overview

#### [../SRS_IMPLEMENTATION_SUMMARY.md](../SRS_IMPLEMENTATION_SUMMARY.md) - **SRS 格式实施总结**
- 结构化需求规范（SRS）实施细节
- Function Analyzer → Prototyper 数据格式
- JSON schema 定义
- 测试结果和预期效果

#### [../long_term_memory/README.md](../long_term_memory/README.md) - **Long-term Memory 指南**
- Archetypes (6种行为模式)
- Skeletons (代码模板)
- Pitfalls (通用错误模式)
- 检索和使用方式

---

### 🔬 设计方案文档（未完全实现）

⚠️ **注意**: 这些文档描述的是**设计理念**和**未来方向**，不是当前实现状态。

#### [KNOWLEDGE_DATABASE_DESIGN.md](KNOWLEDGE_DATABASE_DESIGN.md) - **知识库设计**
**状态**: 🔴 设计方案（未实现）

- 持久化知识库设计（SQLite + Chroma）
- 历史 driver 学习和检索
- 错误模式和修复转换
- **当前替代**: Session Memory + Long-term Memory

#### [SKELETON_REFINEMENT_DESIGN.md](SKELETON_REFINEMENT_DESIGN.md) - **Skeleton 精炼设计**
**状态**: 🟡 部分理念已实现

- Skeleton 精炼过程设计
- 多源信息融合策略
- **当前实现**: Function Analyzer 选择 archetype + Prototyper 生成代码

#### [HYBRID_SPEC_WITH_SESSION_MEMORY.md](HYBRID_SPEC_WITH_SESSION_MEMORY.md) - **混合规范设计**
**状态**: 🟡 Session Memory 已实现，扩展策略是设计

- Session Memory 驱动的 Skeleton Refinement
- Skeleton 组件的增量构建
- **当前实现**: Session Memory + SRS 规范

#### [HEADER_POST_INJECTION_ANALYSIS.md](HEADER_POST_INJECTION_ANALYSIS.md) - **Header 后处理方案**
**状态**: 🔴 设计方案（未实现）

- LLM 生成后强制注入正确 headers
- 防止 LLM 修改 header 路径
- **当前实现**: Header 提取 + Prompt 注入

---

### 📖 其他文档

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

