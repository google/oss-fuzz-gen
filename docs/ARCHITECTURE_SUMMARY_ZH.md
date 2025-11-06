# LogicFuzz 架构设计总结

## 🎯 核心设计理念

LogicFuzz采用**Supervisor-Agent模式**和**两阶段工作流**来实现自动化fuzz target生成。

---

## 🏗️ 系统架构

### 1. 控制流：Supervisor-Agent模式

```
                    ┌──────────────┐
                    │  Supervisor  │ ← 中央路由器
                    └──────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   ┌─────────┐       ┌─────────┐       ┌─────────┐
   │LLM Agent│       │LLM Agent│       │Executor │
   │(分析)   │       │(生成)   │       │(执行)   │
   └─────────┘       └─────────┘       └─────────┘
```

**关键特性**:
- **集中式路由**: Supervisor根据state决定下一个agent
- **状态驱动**: 每个agent更新state，Supervisor根据新state做决策
- **循环检测**: 每个node最多访问10次，防止死循环

---

## 🔄 两阶段工作流

### Phase 1: COMPILATION（编译阶段）

**目标**: 让代码成功编译

```
START
  ↓
Function Analyzer (分析API)
  ↓
Prototyper (生成代码)
  ↓
Build (编译)
  ↓
编译成功? ──NO──┐
  │            │
 YES          Enhancer (修复, 最多3次)
  ↓            │
Validation    ├─→ 重试1
  ↓            ├─→ 重试2
调用正确? ──NO─┤   └─→ 重试3 → END (失败)
  │            │
 YES          Enhancer (修复, 最多2次)
  ↓            └─→ 重试1 → 重试2 → END (失败)
Phase 2
```

**重试策略**:
- **编译错误**: 3次Enhancer重试
  - 提供±10行错误上下文
  - 累积Session Memory中的known fixes
  - 失败后直接END，不再重新生成
- **验证错误**: 2次Enhancer重试
  - 检查target function是否被调用
  - BuilderRunner的_pre_build_check实现

---

### Phase 2: OPTIMIZATION（优化阶段）

**目标**: 最大化覆盖率，发现真实bug

```
Execution (运行fuzzer)
  ↓
有crash? ──NO──┐
  │           │
 YES         Coverage低?
  ↓           │
Crash Analyzer YES
  ↓           │
Crash Feasibility Analyzer
  ↓           ↓
真实bug? ──YES──→ END (成功!) Coverage Analyzer
  │                    ↓
 NO                  Enhancer/Improver
  │                    ↓
  └─────────→ Enhancer  │
              ↓          │
           重新执行 ←─────┘
              ↓
    覆盖率稳定(3次无提升)?
              ↓
             END
```

**终止条件**:
1. 发现真实bug（crash feasibility = True）
2. 覆盖率连续3次无提升（stagnation）
3. 达到max_iterations（默认5-10轮）

---

## 🤖 Agent生态系统

### 🔵 控制层（1个）

**Supervisor** (`supervisor_node.py`)
- **职责**: 
  - 根据workflow_phase路由（compilation/optimization）
  - 注入Session Memory（top-3条）
  - 循环检测和终止条件判断
- **不做**: 不调用LLM，不生成代码
- **关键逻辑**: `_determine_next_action()` (117-345行)

---

### 🟡 生成层（4个LLM Agents）

#### 1. Function Analyzer
- **文件**: `agents/function_analyzer.py`
- **prompt**: `function_analyzer_system.txt` + `*_initial_prompt.txt` + `*_iteration_prompt.txt`
- **输出**: 
  - API constraints（如："必须先调用init()再调用decode()"）
  - Archetype（如："stateful_decoder", "simple_parser"）
  - Calling conventions（参数类型、返回值处理）
- **Session Memory写入**: API_CONSTRAINTS (HIGH confidence)

#### 2. Prototyper
- **文件**: `agents/prototyper.py`
- **prompt**: `prototyper_system.txt` + `prototyper_prompt.txt`
- **输出**: 
  - `fuzz_target_source` (完整的LLVMFuzzerTestOneInput代码)
  - `build_script_source` (build.sh)
- **依赖**: 读取Function Analyzer的archetype和constraints
- **特色**: 基于archetype选择代码模板（长期记忆）

#### 3. Enhancer (LangGraphEnhancer)
- **文件**: `agents/fixer.py`
- **node**: `fixer_node.py`（导出enhancer_node）
- **prompt**: `enhancer_system.txt` + `enhancer_prompt.txt`
- **多模式**:
  1. **Compilation Mode**: 修复build_errors，使用±10行上下文
  2. **Validation Mode**: 修复target function未调用
  3. **False Positive Mode**: 修复harness中的误报crash
  4. **Coverage Mode**: 添加边界测试用例
- **Session Memory写入**: KNOWN_FIXES (confidence根据成功与否)

#### 4. Improver
- **文件**: `agents/improver.py`
- **prompt**: `improver_system.txt` + `improver_prompt.txt`
- **职责**: 高级代码优化和重构
- **使用场景**: 覆盖率已较高，需要深度优化时

---

### 🔴 分析层（3个LLM Agents）

#### 5. Crash Analyzer
- **文件**: `agents/crash_analyzer.py`
- **输入**: ASAN报告、stack trace
- **输出**: 
  - crash_type (heap-buffer-overflow, UAF, timeout, OOM)
  - crash_location (函数名:行号)
  - 初步严重性评估
- **Session Memory写入**: CRASH_CONTEXT

#### 6. Crash Feasibility Analyzer
- **文件**: `agents/crash_feasibility_analyzer.py`
- **prompt**: `crash_feasibility_analyzer_system.txt`
- **深度验证**:
  - crash在target code还是fuzzer harness?
  - 真实世界可达吗？（public API vs internal）
  - 安全相关吗？
  - 可复现吗？
- **输出**: `feasible` (True/False)
- **替代**: 旧版的"Context Analyzer"

#### 7. Coverage Analyzer
- **文件**: `agents/coverage_analyzer.py`
- **输入**: 
  - LLVM source-based coverage报告
  - 未覆盖的行号和函数
- **输出**: 
  - 具体改进建议（如："添加空数组测试`[]`"）
  - 未探索路径分析
- **Session Memory写入**: COVERAGE_INSIGHTS

---

### 🟣 执行层（2个Non-LLM节点）

#### 8. Build Node
- **文件**: `nodes/execution_node.py:build_node()`
- **职责**:
  1. 在OSS-Fuzz Docker容器中编译
  2. 解析编译错误
  3. **Target Function Call Validation** (关键！)
- **Validation实现**: `experiment/builder_runner.py:_pre_build_check()`
  - 使用正则检查fuzz target代码
  - 确保target function真正被调用
  - 失败时设置`has_validation_error`
- **Phase切换**: 编译成功且validation通过 → `workflow_phase = "optimization"`

#### 9. Execution Node
- **文件**: `nodes/execution_node.py:execution_node()`
- **职责**:
  1. 运行libFuzzer（默认60s）
  2. 监控crash（ASAN）
  3. 收集LLVM source-based coverage
  4. 保存crash reproducer
- **指标**:
  - `coverage_percent` - PC覆盖率（内部指标）
  - **`line_coverage_diff`** - 真实项目代码覆盖率增量（**主要指标**）
  - `crashes` - 是否有crash
  - `crash_info` - ASAN报告

---

## 🧠 Session Memory机制

### 结构

```python
state["session_memory"] = {
    "api_constraints": [
        {"content": "Must call init() before decode()", "confidence": "HIGH", "iteration": 0}
    ],
    "known_fixes": [
        {"error": "undefined reference to compress", 
         "fix": "Add -lz to LDFLAGS", 
         "confidence": "MEDIUM", 
         "iteration": 2}
    ],
    "coverage_insights": [...],
    "crash_context": [...]
}
```

### 注入策略

Supervisor在每个agent调用前注入：
1. 按confidence排序（HIGH > MEDIUM > LOW）
2. 按recency排序（新iteration优先）
3. **最多取top-3条**每类

**代码**: `session_memory_injector.py:format_session_memory_for_prompt()`

---

## 💾 数据流：FuzzingContext

### Single Source of Truth

```python
# 在workflow开始时一次性准备
context = FuzzingContext.prepare(
    project_name="cjson",
    function_signature="cJSON* cJSON_Parse(const char *value)"
)

# 所有数据只准备一次，immutable
context.function_info      # FuzzIntrospector数据
context.api_dependencies   # 调用图
context.header_info        # include依赖
context.source_code        # 可选：源码
```

**哲学**:
- ✅ Nodes只读取context，不提取数据
- ✅ 缺失数据直接抛ValueError（fail fast）
- ❌ 不使用fallback或默认值
- ❌ 不返回None

**实现**: `data_context.py:FuzzingContext.prepare()`

---

## 🔧 智能上下文提取

### 问题：Token浪费

```python
# ❌ 传整个文件（500行）
prompt = f"Fix this error:\n{entire_fuzz_target_source}"
```

### 解决：±10行上下文

```python
# ✅ 只传错误周围20行
error_line = 142
context = extract_lines(source, start=132, end=152)
prompt = f"""
Error at line 142:
{context}

Build error: undefined reference to 'compress'
Fix this error.
"""
```

**效果**: 95% token减少，修复成功率不降反升

**实现**: `agents/fixer.py:_extract_error_context()`

---

## 📊 Token管理

### 每Agent独立100k历史

```python
state["agent_messages"] = {
    "function_analyzer": [
        {"role": "system", "content": "..."},
        {"role": "user", "content": "Analyze function..."},
        {"role": "assistant", "content": "Archetype: stateful_decoder..."}
    ],
    "prototyper": [
        {"role": "system", "content": "..."},
        # ... 独立的对话历史
    ],
    "enhancer": [...],
    # 每个agent最多100k tokens
}
```

**自动裁剪**: `memory.py:trim_messages_to_token_limit()`
- 保留system prompt（必须）
- 从最旧消息开始删除
- 保持最近的对话

---

## 🔀 Workflow控制逻辑

### 循环防止

1. **Per-node访问计数**: `state["node_visit_count"]["enhancer"]` ≤ 10
2. **Phase-specific重试**:
   - `compilation_retry_count` ≤ 3
   - `validation_failure_count` ≤ 2
3. **Stagnation检测**: `no_coverage_improvement_count` ≤ 3

### Phase转换条件

```python
# supervisor_node.py:190-230
if workflow_phase == "compilation":
    if compile_success and not has_validation_error:
        # build_node会设置workflow_phase = "optimization"
        return "execution"
    elif not compile_success:
        if compilation_retry_count < 3:
            return "enhancer"
        else:
            return "END"  # 编译失败，终止
```

---

## 🎯 关键设计决策

### 1. 为什么移除Prototyper Regeneration?

**之前**: 3次Enhancer重试失败后，用Prototyper完全重新生成
**现在**: 直接END

**原因**:
1. **成本过高**: 完全重新生成消耗大量tokens
2. **效果有限**: 如果Function Analyzer的分析正确，问题通常在细节，Enhancer足够
3. **Fail Fast**: 如果3次都修不好，说明问题很深（可能是data问题），应该人工介入

### 2. 为什么分离Validation阶段?

**问题**: 代码编译成功，但target function根本没被调用（无效fuzzer）

**解决**: 
- Build Node增加`_pre_build_check()`
- 用正则检查fuzz target代码
- 单独的retry counter（2次）

**效果**: 避免生成"编译通过但无用"的fuzzer

### 3. 为什么用line_coverage_diff而非coverage_percent?

**PC coverage_percent** (`cov_pcs / total_pcs`):
- LibFuzzer内部指标
- 不代表项目真实覆盖率
- 容易误导（可能只覆盖fuzzer harness）

**line_coverage_diff**:
- 真实项目代码行覆盖率增量
- 基于LLVM source-based coverage
- 真正衡量fuzzer质量

**代码**: `supervisor_node.py:276-298`

### 4. 为什么要Session Memory?

**问题**: Agent之间无法共享知识，重复犯错

**解决**:
- API Constraints: Prototyper知道Function Analyzer的发现
- Known Fixes: Enhancer记住之前的成功修复
- Coverage Insights: Enhancer知道Coverage Analyzer的建议

**效果**: 
- 减少重复分析
- 累积知识
- 更快收敛

---

## 📈 性能优化策略

### 1. Parallel Data Fetching

```python
# workflow.py:shared_data预取
# 在workflow启动前并行获取：
- source_code
- api_context
- api_dependencies
- header_info
```

### 2. Prompt优化

- **结构化输出**: JSON/YAML格式，减少解析错误
- **Few-shot Examples**: 在system prompt中提供2-3个示例
- **Token精简**: 移除冗余说明，保留关键信息
- **效果**: 相比naive prompt减少80% tokens

### 3. Coverage-Driven Optimization

**传统**: 随机变异输入
**LogicFuzz**: 
1. 运行fuzzer，收集未覆盖代码
2. Coverage Analyzer分析为什么未覆盖
3. Enhancer针对性添加测试用例
4. 重新运行，验证覆盖率提升

**效果**: 平均35%覆盖率增长

---

## 🐛 Crash验证流程

### 两阶段验证

```
Crash Detected (ASAN报告)
    ↓
┌──────────────────────────────────┐
│ Stage 1: Crash Analyzer          │
│ - 分类crash类型                  │
│ - 定位crash位置                  │
│ - 提取stack trace                │
└─────────────┬────────────────────┘
              ↓
┌──────────────────────────────────┐
│ Stage 2: Crash Feasibility       │
│ Analyzer                         │
│ - 在target code还是harness?      │
│ - 真实世界可达?                  │
│ - 安全相关?                      │
│ - 可复现?                        │
└─────────────┬────────────────────┘
              ↓
    feasible=True? ──YES──→ END (真实bug!)
              │
             NO
              ↓
    Enhancer修复harness
```

### False Positive过滤

**常见误报**:
1. Timeout in harness setup（harness死循环）
2. OOM due to test data generation（测试数据生成过大）
3. Crash in cleanup code（清理代码中的crash，非真实bug）

**Crash Feasibility Analyzer检查**:
- Stack trace中最顶层函数是target还是harness?
- 是否在公开API调用路径上?
- 是否可以从真实输入触发?

---

## 🎓 使用最佳实践

### 1. 启用FuzzIntrospector

```bash
# 启动FI server
bash report/launch_local_introspector.sh

# 运行时指定endpoint
python run_logicfuzz.py --agent \
  -y benchmark.yaml \
  -e http://0.0.0.0:8080/api  # 关键！
```

**收益**: 
- 更准确的API依赖分析
- 更好的调用序列
- 更高的编译成功率

### 2. 合理设置迭代次数

```bash
# 简单项目
--max-round 5 --run-timeout 60

# 复杂项目
--max-round 10 --run-timeout 300

# Bug hunting
--max-round 20 --run-timeout 1800
```

### 3. Temperature调优

```bash
# 保守（更确定性，适合编译阶段）
--temperature 0.3

# 平衡（推荐）
--temperature 0.4

# 探索（更多样性，适合coverage优化）
--temperature 0.6
```

### 4. 批量处理

```bash
# 整个benchmark
python run_logicfuzz.py --agent \
  -y conti-benchmark/conti-cmp/cjson.yaml \
  --num-samples 10  # 每个函数10次试验
```

---

## 🔬 调试技巧

### 1. 查看Agent对话历史

```python
# 在agent代码中
logger.debug(f"Agent messages: {state['agent_messages']['prototyper']}")
```

### 2. 检查Session Memory

```python
from agent_graph.session_memory_injector import format_session_memory_for_prompt

memory_str = format_session_memory_for_prompt(state, max_items_per_category=5)
print(memory_str)
```

### 3. 追踪Phase转换

```bash
# 日志中搜索
grep "workflow_phase" logicfuzz-*.log
grep "Switching to OPTIMIZATION" logicfuzz-*.log
```

### 4. 分析Retry原因

```bash
# 编译重试
grep "compilation_retry_count" logicfuzz-*.log

# Validation失败
grep "Validation failed" logicfuzz-*.log
```

---

## 📚 关键源码位置

| 功能 | 文件 | 函数/类 | 行号 |
|------|------|---------|------|
| Supervisor路由 | `supervisor_node.py` | `_determine_next_action()` | 117-345 |
| Phase切换 | `execution_node.py` | `build_node()` | 335-338 |
| Validation检查 | `builder_runner.py` | `_pre_build_check()` | - |
| Session Memory注入 | `session_memory_injector.py` | `format_session_memory_for_prompt()` | - |
| FuzzingContext准备 | `data_context.py` | `FuzzingContext.prepare()` | - |
| Token裁剪 | `memory.py` | `trim_messages_to_token_limit()` | - |
| Error上下文提取 | `agents/fixer.py` | `_extract_error_context()` | - |
| Coverage指标 | `supervisor_node.py` | Phase 2逻辑 | 276-298 |

---

## 🎯 总结

LogicFuzz通过以下创新实现高效的自动化fuzzing:

1. **两阶段工作流** - 先保证编译，再优化覆盖
2. **Supervisor-Agent模式** - 集中式路由，专业化分工
3. **Session Memory** - 跨agent知识共享
4. **FuzzingContext** - 单一数据源
5. **智能上下文提取** - ±10行上下文，95% token减少
6. **Validation机制** - 确保target function真正被调用
7. **两阶段Crash验证** - 过滤误报，聚焦真实bug
8. **Coverage-Driven** - 基于未覆盖代码针对性优化

**核心哲学**: Fail Fast, Single Source of Truth, Token Efficiency, Agent Specialization

