# LogicFuzz Documentation

Welcome to the LogicFuzz documentation hub! This directory contains comprehensive guides for using LogicFuzz with various types of projects.

**最后更新**: 2025-11-05

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

#### [MEMORY_ARCHITECTURE.md](MEMORY_ARCHITECTURE.md) - **记忆系统架构**

LogicFuzz 的三层记忆架构设计：
- 📚 **Long-term Memory**: 静态知识库（Archetypes、Skeletons、Pitfalls）
- 💾 **Session Memory**: 任务级共识（API约束、已知修复、决策记录）
- 💬 **Agent Messages**: Agent级对话历史

**适合**:
- 理解系统的知识管理机制
- 了解不同层次记忆的用途和生命周期
- 扩展或优化记忆系统

---

### 🔧 技术实现文档

#### [API_DEPENDENCY_GRAPH.md](API_DEPENDENCY_GRAPH.md) - **API 依赖图系统**

基于 tree-sitter 和 FuzzIntrospector 的 API 依赖分析：
- ✅ **前置依赖识别**: 自动识别初始化函数
- ✅ **数据流分析**: 参数的生产者-消费者关系
- ✅ **调用序列生成**: 拓扑排序生成正确调用顺序
- ✅ **初始化代码模板**: 自动生成初始化片段

**适合**:
- 理解如何自动推断 API 调用依赖
- 了解如何利用 FuzzIntrospector API
- 扩展启发式规则

#### [FINE_GRAINED_PARAMETER_MODELING.md](FINE_GRAINED_PARAMETER_MODELING.md) - **细粒度参数建模**

从类型级别到字段级别的参数建模升级：
- ✅ **CONSTRUCT 策略**: 复杂结构体的字段级建模
- ✅ **field_breakdown**: 为每个字段指定独立 fuzzing 策略
- ✅ **覆盖率提升**: 通过字段组合探索提升覆盖率

**适合**:
- 理解参数建模策略的设计
- 了解如何处理复杂结构体参数
- 优化参数约束和变化策略

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

---

### 📚 Fuzzer 编写参考文档

这些是独立的参考/教学文档，基于真实 OSS-Fuzz fuzzer 的分析：

#### [FUZZER_COOKBOOK.md](FUZZER_COOKBOOK.md) - **实战手册** 🔥
- 11 种典型场景的完整代码模板
- 可直接复制粘贴使用
- 包含真实项目参考
- 常见问题解决方案

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

### For Advanced Users
1. [../agent_graph/README.md](../agent_graph/README.md) - Workflow internals
2. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) - Current implementation status
3. [MEMORY_ARCHITECTURE.md](MEMORY_ARCHITECTURE.md) - Memory system design

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

