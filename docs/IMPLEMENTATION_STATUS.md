# LogicFuzz 实现状态文档

**最后更新**: 2025-11-02  
**版本**: v2.0 (LangGraph-based Multi-Agent Architecture)

**最新变更**:
- ✅ 2025-11-02: 完成 API Context Extractor 到 Function Analyzer 的集成

---

## 📋 概述

本文档记录 LogicFuzz 当前的实现状态，区分**已实现功能**和**设计方案文档**。

---

## ✅ 已实现的核心功能

### 1. LangGraph 工作流架构

**实现文件**:
- `agent_graph/workflow.py` - 工作流编排
- `agent_graph/state.py` - 状态管理
- `agent_graph/nodes/` - 各个节点实现

**核心特性**:
- ✅ Supervisor-Agent 模式
- ✅ 两阶段工作流（Compilation → Optimization）
- ✅ 条件路由和循环控制
- ✅ 错误处理和状态恢复

**工作流图**:
```
Supervisor (中心路由器)
    ↓
Phase 1: COMPILATION
    Function Analyzer → Prototyper → Build → Enhancer (最多3次重试)
    ↓ (如果编译成功)
Phase 2: OPTIMIZATION
    Execution → Crash/Coverage Analyzer → Enhancer → 迭代
```

**详细文档**: `agent_graph/README.md`

---

### 2. 多智能体系统

**已实现的 8 个节点**:

#### 🟡 LLM-Driven Agents (生成/分析)
1. **Function Analyzer** (`nodes/function_analyzer_node.py`)
   - 分析函数语义和 API 约束
   - 提取 API 使用模式
   - 生成 SRS 格式规范

2. **Prototyper** (`nodes/prototyper_node.py`)
   - 生成 fuzz target 源代码
   - 生成 build.sh 脚本
   - 基于 SRS 规范和 archetypes

3. **Enhancer** (`nodes/enhancer_node.py`)
   - 修复编译错误
   - 修复运行时错误
   - 优化代码覆盖率

4. **Crash Analyzer** (`nodes/crash_analyzer_node.py`)
   - 分析崩溃类型和严重性
   - 区分真实漏洞和误报

5. **Context Analyzer** (`nodes/context_analyzer_node.py`)
   - 深度可行性验证
   - 分析崩溃是否可触发

6. **Coverage Analyzer** (`nodes/coverage_analyzer_node.py`)
   - 分析未覆盖代码路径
   - 提供优化建议

#### 🔵 Supervisor (调度中心)
7. **Supervisor** (`nodes/supervisor_node.py`)
   - 决策路由逻辑
   - 阶段切换控制
   - 循环预防机制

#### 🟣 Non-LLM Nodes (执行)
8. **Build Node** (`nodes/execution_node.py` 中的 build_node)
   - 在 Docker 容器中编译
   - 解析编译错误

9. **Execution Node** (`nodes/execution_node.py`)
   - 运行 fuzzer
   - 收集覆盖率和崩溃信息

**详细文档**: `agent_graph/README.md` → "Agent Deep Dive"

---

### 3. Session Memory 机制

**实现文件**: `agent_graph/state.py` (第 356-687 行)

**功能**:
- ✅ 跨 agent 共享知识
- ✅ API 约束记录
- ✅ 已知错误修复模式
- ✅ 覆盖率优化策略
- ✅ 关键决策记录
- ✅ Archetype 识别

**数据结构**:
```python
session_memory = {
    "api_constraints": [],      # API 使用约束
    "archetype": {},            # 识别的架构模式
    "known_fixes": [],          # 已知错误修复
    "decisions": [],            # 关键决策记录
    "coverage_strategies": []   # 覆盖率策略
}
```

**使用方式**:
- Supervisor 注入 session memory 到 agent prompts
- 每个 agent 可以添加新的共识约束
- 去重和长度限制确保内存可控

**详细文档**: `agent_graph/README.md` → "Session Memory Mechanism"

---

### 4. Long-term Memory (静态知识库)

**实现目录**: `long_term_memory/`

**组成部分**:
1. **Archetypes** (`archetypes/*.md`) - 6种行为模式
   - `stateless_parser.md` - 无状态解析器
   - `state_machine.md` - 状态机
   - `object_lifecycle.md` - 对象生命周期
   - `file_based.md` - 基于文件的API
   - `round_trip.md` - 往返转换
   - `stream_processor.md` - 流式处理器

2. **Skeletons** (`skeletons/*.c`) - 代码模板
   - 每个 archetype 对应一个 skeleton 模板
   - Function Analyzer 选择合适的 skeleton
   - Prototyper 基于 skeleton 生成代码

3. **Pitfalls** (`pitfalls/*.md`) - 通用错误模式
   - `initialization_errors.md` - 初始化错误
   - `resource_management.md` - 资源管理错误
   - `call_sequence_errors.md` - 调用序列错误
   - `data_argument_errors.md` - 数据参数错误

**检索实现**: `long_term_memory/retrieval.py`

**详细文档**: `long_term_memory/README.md`

---

### 5. SRS 格式规范（结构化需求规范）

**实施状态**: ✅ 已完成（2025-11-01）

**实现文件**:
- `prompts/agent_graph/function_analyzer_final_summary_prompt.txt`
- `prompts/agent_graph/prototyper_prompt.txt`
- `agent_graph/agents/langgraph_agent.py`

**功能**:
- Function Analyzer 输出结构化的 JSON 规范
- 包含功能需求 (FR-*)、前置条件 (PRE-*)、后置条件 (POST-*)、约束条件 (CON-*)
- Prototyper 基于 SRS 规范生成代码
- 每个需求有优先级和置信度

**数据格式**:
```json
{
  "functional_requirements": [
    {
      "id": "FR-1",
      "requirement": "Must initialize storage structure",
      "priority": "MANDATORY",
      "confidence": "HIGH"
    }
  ],
  "preconditions": [...],
  "postconditions": [...],
  "constraints": [...]
}
```

**详细文档**: `SRS_IMPLEMENTATION_SUMMARY.md`

---

### 6. Token 使用追踪

**实现文件**: `agent_graph/state.py` (第 252-320 行)

**功能**:
- ✅ 总 token 统计
- ✅ 按 agent 分类统计
- ✅ Prompt/Completion tokens 分离
- ✅ 调用次数统计
- ✅ 格式化输出报告

**使用示例**:
```python
update_token_usage(state, "function_analyzer", 
                   prompt_tokens=1000, 
                   completion_tokens=500, 
                   total_tokens=1500)

summary = get_token_usage_summary(state)
print(summary)  # 详细的 token 使用报告
```

---

### 7. 两阶段工作流控制

**实现文件**: `agent_graph/nodes/supervisor_node.py`

**Phase 1: COMPILATION**
- 目标: 生成可编译的 fuzz target
- 策略: 
  - Function Analyzer → Prototyper → Build
  - 失败时: Enhancer 修复（最多3次）
  - 仍失败: Prototyper 重新生成（最多1次）
- 计数器: `compilation_retry_count`, `prototyper_regenerate_count`

**Phase 2: OPTIMIZATION**
- 目标: 最大化代码覆盖率，发现真实漏洞
- 策略:
  - Execution → 分析（Crash/Coverage）→ Enhancer → 迭代
  - 崩溃: Crash Analyzer → Context Analyzer → 验证
  - 低覆盖率: Coverage Analyzer → Enhancer 优化
- 终止条件:
  - 发现真实漏洞
  - 覆盖率稳定（连续3次无改善）
  - 达到最大迭代次数

**详细文档**: `agent_graph/README.md` → "Two-Phase Workflow Design"

---

### 8. 循环预防机制

**实现文件**: `agent_graph/state.py`, `agent_graph/nodes/supervisor_node.py`

**机制**:
1. **Per-node 访问计数**: `node_visit_counts`
   - 每个节点最多访问10次
   - 防止死循环

2. **阶段特定计数器**:
   - `compilation_retry_count` - 编译重试次数（最大3次）
   - `prototyper_regenerate_count` - Prototyper 重新生成次数（最大1次）
   - `no_coverage_improvement_count` - 连续无覆盖率改善次数（最大3次）

3. **全局迭代限制**: `max_iterations`
   - 默认5次迭代
   - 可通过命令行参数调整

**终止原因**:
- `max_iterations_reached` - 达到最大迭代次数
- `node_loop_detected` - 检测到节点循环
- `coverage_stable` - 覆盖率稳定（正常结束）
- `bug_found` - 发现真实漏洞（成功结束）
- `too_many_errors` - 错误过多

---

### 9. Header 提取和注入

**实现文件**: 
- `agent_graph/header_extractor.py` - Header 提取逻辑
- `agent_graph/agents/langgraph_agent.py` - 注入到 prompts

**功能**:
- ✅ 从项目源码中提取正确的 header 路径
- ✅ 区分 standard headers 和 project headers
- ✅ 在 Function Analyzer 阶段提取
- ✅ 在 Prototyper/Enhancer prompts 中注入

**工作流**:
```
Function Analyzer
    ↓
Header Extractor: 提取函数定义位置的 headers
    ↓
存入 state["function_analysis"]["header_information"]
    ↓
Prototyper/Enhancer: 从 state 读取并注入到 prompt
```

---

### 10. API 上下文提取

**实现文件**: `agent_graph/api_context_extractor.py`

**功能**:
- ✅ 提取函数参数和返回类型
- ✅ 提取相关类型定义
- ✅ 提取函数调用示例 (call sites)
- ✅ 识别初始化模式和要求
- ✅ 查找相关的初始化/清理函数
- ✅ 与 Fuzz Introspector 集成
- ✅ 提供丰富的上下文信息给 agents

**集成状态**: ✅ **已集成** (2025-11-02)

**使用**:
- 在 Function Analyzer 的 `execute()` 方法中调用
- 提取的信息注入到 Function Analyzer 的初始 prompt 中
- API 上下文存储在 `function_analysis["api_context"]` 中
- 增强 LLM 对 API 语义的理解，特别是参数初始化要求

**工作流**:
```
Function Analyzer execute()
    ↓
get_api_context(project_name, function_signature)
    ↓ 提取以下信息
    - parameters: 参数列表
    - return_type: 返回类型
    - type_definitions: 类型定义
    - usage_examples: 用法示例
    - initialization_patterns: 初始化模式 ⭐
    - related_functions: 相关函数
    ↓
format_api_context_for_prompt(api_context)
    ↓ 格式化为 markdown
Inject into function_analyzer_initial_prompt.txt
    ↓
LLM 分析时可以看到结构化的 API 上下文
```

**关键价值**:
- 🎯 自动识别需要初始化的复杂类型（如 `storage`, `context`）
- 🎯 提供正确的初始化方法和相关函数
- 🎯 减少 LLM 在参数处理上的错误
- 🎯 提供真实的用法示例作为参考

---

### 11. API 验证

**实现文件**: `agent_graph/api_validator.py`

**功能**:
- ✅ 验证目标函数是否被调用
- ✅ 检查 fuzz target 代码的正确性
- ✅ 防止生成无效的 fuzzer

**验证方式**:
- 静态代码分析
- 检查函数名在生成的代码中是否出现
- 验证调用上下文

---

## 📚 参考文档（保持更新）

这些文档描述了 fuzzing 最佳实践和参考资料，与实现无关：

1. **FUZZER_BEHAVIOR_TAXONOMY.md** - Fuzzer 行为分类体系
   - 基于 4699 个真实 fuzzer 的分析
   - 5 维度分类框架
   - 参考和学习资料

2. **FUZZER_COOKBOOK.md** - Fuzz Driver 实战手册
   - 11 种典型场景的代码模板
   - 可复制粘贴的解决方案
   - 真实项目参考

3. **FUZZING_CHEATSHEET.md** - Fuzzer 速查表
   - 一页纸快速参考
   - 3 个标准模板
   - 常见错误和解决方案

4. **README_FUZZING.md** - Fuzzer 编写指南总目录
   - 导航和索引
   - 文档使用指南

5. **NEW_PROJECT_SETUP.md** - 新项目设置指南
   - 如何设置私有项目
   - 如何创建 OSS-Fuzz 项目结构
   - 配置文件模板

6. **SIGNATURE_FIX_README.md** - 函数签名处理
   - 签名提取和修复
   - 参数解析
   - 集成到工作流

---

## 📝 设计方案文档（未完全实现）

这些文档描述了**设计理念**和**未来方向**，但未完全实现：

### 1. KNOWLEDGE_DATABASE_DESIGN.md

**状态**: 🔴 设计方案（未实现）

**描述内容**:
- 持久化知识库设计
- SQLite + Chroma 向量数据库
- 历史 driver 学习和检索
- 错误模式和修复转换

**当前实现情况**:
- ✅ **Session Memory** 实现了**单次运行的知识共享**
- ✅ **Long-term Memory** 实现了**静态知识库**（archetypes/skeletons/pitfalls）
- ❌ **持久化跨运行学习** 未实现
- ❌ **知识库数据库** 未实现

**如果需要实现**:
1. 创建 `knowledge_db/` 目录
2. 实现 `KnowledgeDatabase` 类
3. 集成到 workflow 中

---

### 2. SKELETON_REFINEMENT_DESIGN.md

**状态**: 🟡 部分理念已实现

**描述内容**:
- Skeleton 精炼过程
- 从初始模板到完整代码的迭代
- 多源信息融合

**当前实现情况**:
- ✅ **Skeleton 模板** 存在于 `long_term_memory/skeletons/`
- ✅ **Function Analyzer 选择 archetype** 已实现
- ✅ **Prototyper 基于 skeleton 生成代码** 已实现
- 🟡 **迭代精炼** 部分实现（通过 Enhancer 迭代）
- ❌ **显式的 skeleton refinement 阶段** 未实现

**当前做法**:
- Function Analyzer 识别 archetype
- Prototyper 直接生成完整代码（参考 skeleton）
- Enhancer 迭代修复和优化

**未来优化**:
- 可以引入显式的 "Skeleton Refiner" 节点
- 在 Function Analyzer 和 Prototyper 之间

---

### 3. HYBRID_SPEC_WITH_SESSION_MEMORY.md

**状态**: 🟡 Session Memory 已实现，混合规范是设计扩展

**描述内容**:
- Session Memory 驱动的 Skeleton Refinement
- Skeleton 组件的增量构建
- 规范和代码的协同

**当前实现情况**:
- ✅ **Session Memory** 完全实现
- ✅ **SRS 格式规范** 已实现
- ✅ **Archetype-based 代码生成** 已实现
- ❌ **Skeleton Components 的细粒度管理** 未实现
- ❌ **Session Memory 的 skeleton_components 字段** 未使用

**当前做法**:
- Session Memory 存储 API 约束和已知修复
- SRS 规范提供结构化需求
- Prototyper 基于这两者生成代码

**未来优化**:
- 可以扩展 session_memory 增加 skeleton_components
- 更细粒度的代码组件管理

---

### 4. HEADER_POST_INJECTION_ANALYSIS.md

**状态**: 🔴 设计方案（未实现）

**描述内容**:
- LLM 生成代码后强制注入正确 headers
- 防止 LLM "自作聪明"修改 header 路径
- 后处理修复机制

**当前实现情况**:
- ✅ **Header 提取** 已实现 (`header_extractor.py`)
- ✅ **Header 信息注入到 prompt** 已实现
- ❌ **生成后强制注入** 未实现

**当前做法**:
- 在 prompt 中明确告知正确的 header 路径
- 依赖 LLM 正确使用提供的信息

**未来优化**:
- 可以在 Prototyper/Enhancer 的 `execute()` 方法中
- 添加 `_force_inject_headers()` 后处理步骤
- 解析生成的代码，强制替换错误的 header 路径

---

## 🗂️ 文档分类总结

### 实现文档（描述当前系统）
- ✅ `agent_graph/README.md` - 工作流架构详解
- ✅ `README.md` - 项目概览
- ✅ `SRS_IMPLEMENTATION_SUMMARY.md` - SRS 格式实施总结
- ✅ `long_term_memory/README.md` - Long-term memory 使用指南

### 参考文档（独立的教学/参考资料）
- 📚 `docs/FUZZER_BEHAVIOR_TAXONOMY.md`
- 📚 `docs/FUZZER_COOKBOOK.md`
- 📚 `docs/FUZZING_CHEATSHEET.md`
- 📚 `docs/README_FUZZING.md`
- 📚 `docs/NEW_PROJECT_SETUP.md`
- 📚 `docs/SIGNATURE_FIX_README.md`

### 设计文档（未来方向/部分实现）
- 🔴 `docs/KNOWLEDGE_DATABASE_DESIGN.md` - 持久化知识库（未实现）
- 🟡 `docs/SKELETON_REFINEMENT_DESIGN.md` - Skeleton 精炼（部分实现）
- 🟡 `docs/HYBRID_SPEC_WITH_SESSION_MEMORY.md` - 混合规范（部分实现）
- 🔴 `docs/HEADER_POST_INJECTION_ANALYSIS.md` - Header 后处理（未实现）

---

## 🚀 快速参考

### 我想了解...

| 主题 | 推荐文档 |
|------|---------|
| **当前实现的架构** | 本文档 + `agent_graph/README.md` |
| **如何使用 LogicFuzz** | `README.md` |
| **如何设置新项目** | `docs/NEW_PROJECT_SETUP.md` |
| **如何编写 fuzzer** | `docs/FUZZER_COOKBOOK.md` |
| **Workflow 工作流程** | `agent_graph/README.md` |
| **Session Memory 机制** | 本文档 → Session Memory |
| **SRS 格式** | `SRS_IMPLEMENTATION_SUMMARY.md` |
| **Long-term Memory** | `long_term_memory/README.md` |
| **未来优化方向** | 本文档 → 设计方案文档 |

---

## 📞 维护信息

**文档维护者**: LogicFuzz Team  
**更新频率**: 随代码实现同步更新  
**反馈方式**: 通过 GitHub Issues

---

## 📅 变更历史

### 2025-11-02
- **API Context Extractor 集成完成**
  - `api_context_extractor.py` 已集成到 Function Analyzer
  - 在函数分析初始阶段提供结构化的 API 上下文
  - 自动识别参数初始化要求和相关函数
  - API 上下文注入到 LLM prompt 中，增强语义理解

### 2025-11-01
- 初始文档创建
- 记录所有已实现和设计中的功能

---

**最后更新**: 2025-11-02

