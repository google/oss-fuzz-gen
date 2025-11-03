# API 依赖图建模系统

## 📋 概述

基于 **tree-sitter** 和 **FuzzIntrospector** 构建的 API 依赖图分析系统，用于自动识别函数调用的前置依赖和数据流依赖，指导 LLM 生成正确的 fuzzer 代码。

---

## 🎯 核心功能

### 1. **前置依赖识别**
自动识别必须在目标函数之前调用的初始化函数：
- `*_init()`, `*_create()`, `*_new()`, `*_alloc()`, `*_open()`
- 基于类型名和命名约定的启发式规则
- 使用 FuzzIntrospector 验证函数存在性

### 2. **数据流依赖分析**
识别参数的生产者-消费者关系：
- 追踪哪些参数需要来自其他函数的返回值
- 识别复杂类型的生产者函数
- 构建数据依赖边

### 3. **调用序列生成**
使用拓扑排序生成正确的调用顺序：
- 确保所有依赖在使用前被满足
- 处理有向无环图 (DAG)
- Fallback 到简单顺序（如果存在环）

### 4. **初始化代码模板**
自动生成初始化代码片段：
- 变量声明
- 初始化函数调用
- 内存清零（memset）

---

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────────┐
│  LangGraphFunctionAnalyzer (函数分析器)                    │
│  ├─ API Context Extraction (现有)                        │
│  └─ API Dependency Analysis (新增)                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  APIDependencyAnalyzer                                  │
│  ├─ 使用 APIContextExtractor 提取函数信息                │
│  ├─ 识别前置依赖 (_find_prerequisite_functions)         │
│  ├─ 分析数据依赖 (_analyze_data_dependencies)           │
│  ├─ 构建图 (NetworkX DiGraph)                           │
│  └─ 生成调用序列 (拓扑排序)                              │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  FuzzIntrospector API                                   │
│  ├─ query_introspector_all_functions                    │
│  ├─ query_introspector_function_source                  │
│  ├─ query_introspector_type_definition                  │
│  └─ query_introspector_call_sites_metadata              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  tree-sitter (Header Extraction)                        │
│  └─ header_extractor.py (已有)                          │
└─────────────────────────────────────────────────────────┘

                     ▼
┌─────────────────────────────────────────────────────────┐
│  LangGraphPrototyper (代码生成器)                          │
│  └─ 在 SRS 规范中注入依赖图信息                           │
│     └─ _format_srs_specification                        │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 依赖

- **tree-sitter** >= 0.25.0 (已有)
- **tree-sitter-cpp** >= 0.23.0 (已有)
- **networkx** >= 3.0 (新增)

```bash
pip install networkx
```

---

## 🚀 使用方法

### 命令行测试

```bash
python test_api_dependency_analyzer.py <project_name> <function_signature>

# 示例：
python test_api_dependency_analyzer.py igraph \
  "igraph_error_t igraph_sparsemat_arpack_rssolve(const igraph_sparsemat_t *, igraph_arpack_options_t *, igraph_arpack_storage_t *, igraph_vector_t *, igraph_matrix_t *, igraph_sparsemat_solve_t)"
```

### 编程接口

```python
from agent_graph.api_dependency_analyzer import APIDependencyAnalyzer

# 创建分析器
analyzer = APIDependencyAnalyzer(project_name="igraph")

# 构建依赖图
dep_graph = analyzer.build_dependency_graph(
    "igraph_error_t igraph_sparsemat_arpack_rssolve(...)"
)

# 访问结果
print(dep_graph['call_sequence'])       # 调用顺序
print(dep_graph['prerequisites'])       # 前置依赖
print(dep_graph['data_dependencies'])   # 数据依赖
print(dep_graph['initialization_code']) # 初始化代码
```

### 集成到工作流

依赖图信息会**自动**注入到 FunctionAnalyzer → Prototyper 流程：

1. **FunctionAnalyzer** 提取依赖图
2. **Prototyper** 在 SRS 规范中看到依赖信息
3. **LLM** 根据依赖图生成正确的初始化序列

---

## 📊 实际案例

### 案例：igraph_sparsemat_arpack_rssolve

**输入**：
```c
igraph_error_t igraph_sparsemat_arpack_rssolve(
    const igraph_sparsemat_t *A,
    igraph_arpack_options_t *options,
    igraph_arpack_storage_t *storage,
    igraph_vector_t *values,
    igraph_matrix_t *vectors,
    igraph_sparsemat_solve_t solvemethod
)
```

**分析结果**：

✅ **调用序列** (6 函数):
1. `igraph_arpack_storage_init`
2. `igraph_sparsemat_init`
3. `igraph_arpack_options_init`
4. `igraph_vector_init`
5. `igraph_matrix_init`
6. `igraph_sparsemat_arpack_rssolve` ← 目标函数

⚠️ **前置依赖** (1 函数):
- `igraph_arpack_storage_init()` - 必须先调用

📊 **数据依赖** (5 条边):
- `igraph_sparsemat_init` → `igraph_sparsemat_arpack_rssolve`
- `igraph_arpack_options_init` → `igraph_sparsemat_arpack_rssolve`
- `igraph_arpack_storage_init` → `igraph_sparsemat_arpack_rssolve`
- `igraph_vector_init` → `igraph_sparsemat_arpack_rssolve`
- `igraph_matrix_init` → `igraph_sparsemat_arpack_rssolve`

💡 **生成的初始化代码**：
```c
// Initialize required data structures
igraph_arpack_storage_t *storage;
memset(&*storage, 0, sizeof(igraph_arpack_storage_t));
// Call prerequisite: igraph_arpack_storage_init
igraph_arpack_storage_init(...);  // TODO: Fill in parameters
```

---

## 🔧 工作原理

### 启发式规则

#### 1. 初始化函数识别
```python
INIT_SUFFIXES = ['_init', '_create', '_new', '_alloc', '_setup', '_open']

# 示例：
# igraph_arpack_storage_t → 查找 igraph_arpack_storage_init
# my_context_t → 查找 my_context_create
```

#### 2. 类型依赖分析
```python
# 如果参数类型是 igraph_vector_t*，查找:
# - igraph_vector_init()
# - igraph_vector_create()
# - igraph_vector_new()
```

#### 3. 初始化模式识别
```python
INIT_REQUIRED_KEYWORDS = [
    'storage', 'context', 'state', 'buffer',
    'data', 'cache', 'pool', 'arena'
]

# 如果参数类型包含这些关键词，标记为需要初始化
```

### 图构建

使用 NetworkX 有向图 (DiGraph):
- **节点**: 函数名
- **边**: 依赖关系
  - `control` 边: 必须先调用 (prerequisites)
  - `data` 边: 数据流依赖

拓扑排序确保正确的调用顺序。

---

## 🎨 Prototyper 集成

### Prompt 增强

在 `prototyper_prompt.txt` 中新增第 6 项要求：

```markdown
6. **API DEPENDENCIES & INITIALIZATION ORDER** (🔗 IMPORTANT)
   - Follow the API dependency graph to ensure correct initialization sequence
   - Call prerequisite functions (init/create/new) BEFORE the target function
   - Respect data flow dependencies (produce data before consumption)
   - Use the provided call sequence to avoid runtime errors
   - See "API Dependency Analysis" section below for details
```

### SRS 规范注入

在 `_format_srs_specification` 中自动添加依赖图部分：

```markdown
### 🔗 API Dependency Analysis

**CRITICAL**: Follow this dependency graph to ensure correct initialization sequence!

#### ✅ Recommended Call Sequence
1. `igraph_arpack_storage_init`
2. `igraph_sparsemat_init`
...

#### ⚠️ Prerequisites (MUST call before target)
- `igraph_arpack_storage_init()` - Initialization function

#### 📊 Data Flow Dependencies
- `igraph_sparsemat_init` produces data consumed by `target_function`

#### 💡 Initialization Code Template
```c
// Initialize required data structures
...
```
```

---

## 🔬 与同类工作对比

| 工具 | 使用者 | logicfuzz 实现 |
|------|--------|---------------|
| **Tree-sitter** | CKGFuzzer | ✅ 用于 header 提取 |
| **FuzzIntrospector** | OSS-Fuzz | ✅ 调用图、类型信息 |
| **NetworkX** | CKGFuzzer | ✅ 图操作、拓扑排序 |
| **Clang LibTooling** | RUBICK, libErator | ⚠️ 未使用（可选增强） |
| **CodeQL** | CKGFuzzer | ❌ 未使用（过于重量） |

**优势**:
- ✅ **轻量级**: 无需编译环境，直接查询 FuzzIntrospector API
- ✅ **快速**: 利用现有基础设施（tree-sitter + FI）
- ✅ **可靠**: Fallback 机制（无 networkx 时使用简单图）
- ✅ **可扩展**: 易于添加新的启发式规则

---

## 🧪 测试

### 运行测试

```bash
# 简单函数（无依赖）
python test_api_dependency_analyzer.py libxml2 xmlParseFile

# 复杂函数（多依赖）
python test_api_dependency_analyzer.py igraph \
  "igraph_error_t igraph_sparsemat_arpack_rssolve(...)"
```

### 预期输出

成功的测试应输出：
- ✅ Call sequence generated
- ✅ Dependencies found (如果有)
- 🎉 Test PASSED!

---

## 📝 文件清单

### 新增文件
- `agent_graph/api_dependency_analyzer.py` - 核心分析器
- `test_api_dependency_analyzer.py` - 测试脚本
- `docs/API_DEPENDENCY_GRAPH.md` - 本文档

### 修改文件
- `agent_graph/agents/langgraph_agent.py`
  - `LangGraphFunctionAnalyzer.execute()` - 添加依赖图分析
  - `LangGraphPrototyper._format_srs_specification()` - 注入依赖信息
- `prompts/agent_graph/prototyper_prompt.txt` - 新增第 6 项要求
- `requirements.txt` - 添加 `networkx>=3.0`

---

## 🚧 未来改进

### 短期（1-2 周）
1. **增强启发式规则**
   - 添加更多初始化函数后缀模式
   - 支持 C++ 构造函数识别
   - 处理析构函数（cleanup 函数）

2. **改进数据流分析**
   - 使用 FuzzIntrospector 的返回类型信息
   - 追踪多层依赖（间接依赖）

### 中期（1-2 月）
3. **集成 Clang LibTooling**（可选）
   - 更精确的类型推断
   - 数据流分析（def-use chains）
   - 需要编译环境

4. **缓存优化**
   - 缓存 FuzzIntrospector 查询结果
   - 缓存依赖图（project-level）

### 长期（2+ 月）
5. **状态机学习**（参考 RUBICK）
   - 从样例学习 API 调用顺序约束
   - 构建 DFA 模型

6. **跨项目知识迁移**
   - 从 igraph 学习的模式应用到其他图库
   - 通用的 API 模式库

---

## 📚 参考文献

1. **RUBICK** (USENIX Security 2023)
   - 状态机学习，从样例推断 API 序列约束
   
2. **CKGFuzzer**
   - 使用 tree-sitter + CodeQL 构建代码知识图

3. **libErator** (FSE 2025)
   - 静态分析构建调用图，推断可组合 API 序列

4. **Scheduzz**
   - 约束提取和类型推断

---

## 🤝 贡献

如需改进或扩展此系统：
1. 在 `api_dependency_analyzer.py` 中添加新的启发式规则
2. 更新 `INIT_SUFFIXES` 和 `INIT_REQUIRED_KEYWORDS`
3. 运行 `test_api_dependency_analyzer.py` 验证
4. 更新本文档

---

## ✅ 总结

基于 **tree-sitter + FuzzIntrospector** 的轻量级 API 依赖图系统已成功集成！

**核心价值**:
- 🎯 **自动识别** 初始化依赖，减少 LLM 幻觉
- 🔗 **构建调用图**，指导正确的调用顺序
- 💡 **生成模板**，加速代码生成
- 📊 **可视化依赖**，提升可解释性

**立即可用**，无需额外配置！

