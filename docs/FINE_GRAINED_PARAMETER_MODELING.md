# 细粒度参数建模系统升级

## 📋 概述

本文档记录了 LogicFuzz 参数建模策略的重大升级：**从粗粒度类型级别到细粒度字段级别的建模**。

### 问题背景

**之前的限制**：
- 对于复杂类型参数（struct/class），只能记录类型级别的策略
- 无法指定结构体内部各字段的独立 fuzzing 策略
- 导致覆盖率受限，因为字段组合空间未被充分探索

**示例问题**：
```c
// 目标函数
int process_config(struct Config *cfg);

// 之前的 SRS 只能记录：
{
  "parameter": "cfg",
  "type": "struct Config *",
  "strategy": "CONSTRAIN"  // ← 太粗粒度！无法指定各字段策略
}

// 生成的代码可能是：
struct Config cfg;
cfg.timeout = 30;        // 固定值！
cfg.flags = 0;           // 固定值！
cfg.buffer = (char*)data;
```

---

## 🎯 解决方案：CONSTRUCT 策略 + field_breakdown

### 新的 SRS Schema 扩展

```json
{
  "parameter_strategies": [
    {
      "parameter": "cfg",
      "type": "struct Config *",
      "strategy": "CONSTRUCT",  // ← 新策略
      "field_breakdown": {      // ← 新字段
        "is_complex_type": true,
        "primitive_fields": [
          {
            "field_path": "cfg->timeout",
            "field_type": "int",
            "strategy": "CONSTRAIN",
            "constraints": {"min": 0, "max": 3600},
            "construction": "fdp.ConsumeIntegralInRange<int>(0, 3600)",
            "rationale": "Timeout must be valid, vary to test different code paths"
          },
          {
            "field_path": "cfg->flags",
            "field_type": "uint32_t",
            "strategy": "DIRECT_FUZZ",
            "construction": "fdp.ConsumeIntegral<uint32_t>()",
            "rationale": "Bitfield flags - test all combinations"
          },
          {
            "field_path": "cfg->buffer",
            "field_type": "char*",
            "strategy": "CONSTRAIN",
            "constraints": {"max_length": 1024},
            "construction": "fdp.ConsumeRandomLengthString(1024)",
            "rationale": "Buffer content varies"
          }
        ],
        "nested_types": [
          {"type_name": "Config", "definition_source": "FuzzIntrospector"}
        ]
      }
    }
  ]
}
```

### 生成的代码（改进后）

```cpp
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  // 字段级别的细粒度控制
  struct Config cfg;
  memset(&cfg, 0, sizeof(cfg));
  
  cfg.timeout = fdp.ConsumeIntegralInRange<int>(0, 3600);  // 变化！
  cfg.flags = fdp.ConsumeIntegral<uint32_t>();             // 变化！
  std::string buffer_str = fdp.ConsumeRandomLengthString(1024);
  cfg.buffer = buffer_str.c_str();
  
  process_config(&cfg);  // 现在能探索更多代码路径
  return 0;
}
```

---

## 🔧 实施细节

### 1. Strategy 增强

新增第 5 种策略：**CONSTRUCT**

| 策略 | 适用场景 | 描述 |
|------|---------|------|
| DIRECT_FUZZ | 简单 buffer 函数 | 直接传递 fuzzer 数据 |
| CONSTRAIN | 需要约束的参数 | 使用 FuzzedDataProvider + 约束 |
| FIX | 最后手段 | 固定值（需强理由） |
| **CONSTRUCT** (新) | **复杂结构体参数** | **分解到字段级别** |

### 2. Function Analyzer 升级

**新增章节**：`COMPLEX TYPE RECOGNITION`

引导 LLM：
1. 识别 struct/class/union 参数
2. 使用 FuzzIntrospector API 获取类型定义
3. 提取 primitive fields
4. 为每个字段指定独立策略

**新增 API 调用**：
```python
# 在 agent_graph/agents/langgraph_agent.py 中已有的接口
introspector.query_introspector_type_definition(project_name)
```

返回示例：
```json
[
  {
    "name": "Config",
    "type": "struct",
    "fields": [
      {"name": "timeout", "type": "int"},
      {"name": "flags", "type": "uint32_t"},
      {"name": "buffer", "type": "char*"}
    ],
    "pos": {"source_file": "config.h", "line_start": 10, "line_end": 15}
  }
]
```

### 3. Prototyper 升级

**新增示例**：Example 4 - CONSTRUCT Strategy

详细展示：
- 如何从 SRS 的 `field_breakdown` 读取字段策略
- 如何使用 FuzzedDataProvider 初始化各字段
- ✅ GOOD vs ❌ BAD 对比

**新增步骤指导**：
- Step 5 扩展：参数构造（包含字段级别处理）
- 明确从 SRS 读取 `construction` 代码

### 4. Improver 升级

**新增优先级**：Priority 3 - Fine-Grained Struct Field Variation

当覆盖率低时：
1. 检查是否有固定的结构体字段
2. 识别哪些字段影响未覆盖的分支
3. 将固定字段改为 FuzzedDataProvider 生成
4. 记录覆盖率改进预期

---

## 📊 预期效果

### 覆盖率提升

**假设场景**：
```c
int validate_config(struct Config *cfg) {
  if (cfg->timeout > 0) {        // Branch 1
    if (cfg->flags & FLAG_ASYNC) // Branch 2
      async_mode();
    else
      sync_mode();
  }
  if (strlen(cfg->buffer) > 10)  // Branch 3
    process_large_buffer();
}
```

| 方法 | timeout 变化 | flags 变化 | buffer 变化 | 可达分支 | 覆盖率 |
|------|-------------|------------|------------|---------|-------|
| **旧方法**（固定字段） | ❌ (30) | ❌ (0) | ✅ | Branch 1 only | ~33% |
| **新方法**（字段级变化） | ✅ | ✅ | ✅ | All branches | ~100% |

### 参数空间探索

- **旧方法**：`timeout × flags × buffer = 1 × 1 × ∞ = ∞` （但实际只测试一种 timeout/flags 组合）
- **新方法**：`timeout × flags × buffer = ∞ × ∞ × ∞` （真正探索字段组合空间）

---

## 🔍 与现有系统集成

### FuzzIntrospector API 使用

代码位置：`data_prep/introspector.py`

```python
def query_introspector_type_definition(project: str) -> List[dict]:
  """
  查询项目的所有类型定义（struct/union/typedef/enum）
  
  Returns:
    List of type definitions with structure:
    {
      'name': 'TypeName',
      'type': 'struct | union | typedef | enum',
      'fields': [
        {'name': 'field1', 'type': 'int'},
        {'name': 'field2', 'type': 'char*'}
      ],
      'pos': {
        'source_file': 'header.h',
        'line_start': 10,
        'line_end': 20
      }
    }
  """
```

已经在以下位置使用：
- `data_prep/project_context/context_introspector.py::ContextRetriever.get_type_def()`
- `agent_graph/api_context_extractor.py::APIContextExtractor._extract_type_definitions()`

### 现有流程扩展

```
┌─────────────────────────────────────────────────────────┐
│  Function Analyzer                                      │
│  1. 分析函数签名                                         │
│  2. 识别复杂类型参数 (struct Config *)                   │
│  3. ✨ 调用 FuzzIntrospector 获取类型定义                │
│  4. ✨ 提取 primitive fields                            │
│  5. ✨ 为每个字段指定策略                                │
│  6. 生成 SRS (with field_breakdown)                     │
└─────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  Prototyper                                             │
│  1. 读取 SRS                                            │
│  2. ✨ 检查 strategy == "CONSTRUCT"                     │
│  3. ✨ 遍历 field_breakdown.primitive_fields            │
│  4. ✨ 为每个字段生成 FuzzedDataProvider 调用            │
│  5. 生成完整 fuzzer 代码                                 │
└─────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  Improver (if coverage low)                             │
│  1. 分析覆盖率报告                                       │
│  2. ✨ 识别固定的结构体字段                              │
│  3. ✨ 查找字段相关的未覆盖分支                          │
│  4. ✨ 重写：固定字段 → FuzzedDataProvider              │
│  5. 预期覆盖率提升                                       │
└─────────────────────────────────────────────────────────┘
```

---

## 📝 修改文件清单

### Prompts (已完成)

1. ✅ `prompts/agent_graph/function_analyzer_system.txt`
   - 新增 Strategy 4: CONSTRUCT
   - 新增 COMPLEX TYPE RECOGNITION 章节
   - 新增字段分解流程指导

2. ✅ `prompts/agent_graph/function_analyzer_final_summary_prompt.txt`
   - 扩展 `parameter_strategies` schema (添加 `field_breakdown`)
   - 更新 Field Guidelines (添加 CONSTRUCT 说明)
   - 新增 CONSTRUCT 策略示例

3. ✅ `prompts/agent_graph/prototyper_system.txt`
   - 新增 CONSTRUCT Strategy 代码模板
   - 添加字段级变化示例

4. ✅ `prompts/agent_graph/prototyper_prompt.txt`
   - 新增 Example 4: CONSTRUCT Strategy
   - 扩展 Step 5: 参数构造（字段级处理）
   - 修正步骤编号

5. ✅ `prompts/agent_graph/improver_system.txt`
   - 新增 Priority 3: Fine-Grained Struct Field Variation
   - 更新策略优先级说明

6. ✅ `prompts/agent_graph/improver_prompt.txt`
   - 新增 Template 2: 结构体字段变化模板

### 代码 (未来工作)

以下代码改动**不需要立即实施**（LLM 可以通过 prompt 学会）：

1. ⏳ `agent_graph/agents/langgraph_agent.py::LangGraphFunctionAnalyzer`
   - 可选：在 `_format_function_context()` 中自动查询类型定义
   - 可选：传递类型定义给 LLM（作为额外上下文）

2. ⏳ `agent_graph/agents/langgraph_agent.py::LangGraphPrototyper`
   - 可选：验证生成的代码是否正确使用了 field_breakdown
   - 可选：自动检测缺失的字段变化

3. ⏳ `agent_graph/agents/langgraph_agent.py::LangGraphImprover`
   - 可选：自动分析覆盖率报告识别字段相关分支
   - 可选：建议具体的字段变化策略

---

## 🧪 验证方法

### 手动测试

1. 选择一个有复杂 struct 参数的函数（如 `libpng` 的配置函数）
2. 运行 Function Analyzer，检查 SRS 是否包含 `field_breakdown`
3. 运行 Prototyper，检查生成的代码是否字段级初始化
4. 对比覆盖率：旧方法 vs 新方法

### 自动化测试

```bash
# 测试用例：struct 参数函数
python -m pytest tests/test_fine_grained_modeling.py

# 验证点：
# 1. SRS 包含 field_breakdown
# 2. 生成代码使用 FuzzedDataProvider 初始化各字段
# 3. 覆盖率提升 > 20%
```

---

## 🎓 相关论文与工具

### 学术参考

1. **CKGFuzzer** (ASE'24)
   - 使用 tree-sitter 提取类型信息
   - 构建 Code Knowledge Graph
   - 我们的优势：直接利用 FuzzIntrospector API（更简单）

2. **RUBICK** (CCS'24)
   - 使用 Clang LibTooling 分析参数类型
   - 生成类型感知的 fuzz harness
   - 我们的优势：无需编译环境

3. **libErator** (USENIX Sec'23)
   - 手动标注参数约束
   - 我们的优势：自动从代码推断

### 工具比较

| 工具 | 类型提取 | 字段级建模 | 无需编译 | LogicFuzz |
|------|---------|-----------|---------|-----------|
| CKGFuzzer | tree-sitter | ❌ | ✅ | ✅ |
| RUBICK | Clang LibTooling | ✅ | ❌ | ✅ |
| libErator | 手动标注 | ✅ | N/A | ✅ |
| **LogicFuzz** | **FuzzIntrospector** | **✅** | **✅** | **⭐** |

---

## 🚀 下一步

### 短期（已完成）
- ✅ 设计 schema 扩展
- ✅ 更新 Function Analyzer prompts
- ✅ 更新 Prototyper prompts
- ✅ 更新 Improver prompts

### 中期（可选）
- ⏳ 添加类型定义自动注入到 LLM 上下文
- ⏳ 实现字段策略推荐算法
- ⏳ 添加自动化测试

### 长期（研究方向）
- 🔬 嵌套结构体递归处理
- 🔬 Union 类型的分支探索
- 🔬 动态类型推断（通过运行时信息）
- 🔬 与符号执行结合（精确约束）

---

## 📚 参考资料

- [FuzzIntrospector API 文档](../fuzz-introspector/tools/web-fuzzing-introspection/app/webapp/routes.py)
- [API 依赖图系统](./API_DEPENDENCY_GRAPH.md)
- [参数建模策略升级文档](./parameter_modeling_strategy_upgrade.md)
- [OSS-Fuzz LibFuzzer 教程](https://github.com/google/oss-fuzz/tree/master/docs/advanced-topics)

---

## ✅ 实施状态

| 组件 | 状态 | 备注 |
|------|------|------|
| SRS Schema 扩展 | ✅ 完成 | 添加 `field_breakdown` 字段 |
| Function Analyzer Prompts | ✅ 完成 | 新增 CONSTRUCT 识别指导 |
| Prototyper Prompts | ✅ 完成 | 新增字段级代码生成示例 |
| Improver Prompts | ✅ 完成 | 新增字段级优化策略 |
| 代码实现 | ⏳ 可选 | LLM 可通过 prompt 学习 |
| 测试验证 | ⏳ 待完成 | 需要实际项目验证 |

**总结**：核心 prompt 改动已完成，系统已具备细粒度参数建模能力！🎉

