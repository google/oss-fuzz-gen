# 参数建模策略升级文档

## 📋 升级概述

本次升级将系统的参数建模策略从"随机决定"转变为"默认使用 FuzzedDataProvider"，避免过早使用 FIX 策略导致的覆盖率限制。

## 🎯 核心改进

### 升级前的问题

```python
# 问题1: 过早使用 FIX 策略
# Function Analyzer 会为了"简化"而固定参数值
parameter_strategies = [
    {"parameter": "base", "strategy": "FIX", "fixed_value": "https://example.com/"}
]

# 问题2: 导致低覆盖率
# 固定参数 → 只测试一个代码路径 → 覆盖率 ~20%
# Prototyper 生成的代码:
const char* base = "https://example.com/";  // 固定值!
target_func(data, size, base);
```

### 升级后的策略

```cpp
// 默认策略: 使用 FuzzedDataProvider 分割 fuzzer input
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  // 变化所有参数，探索多个代码路径
  std::string input_str = fdp.ConsumeRandomLengthString(1024);
  std::string base_str = fdp.ConsumeRandomLengthString(256);
  
  target_func(input_str.c_str(), input_str.length(), 
              base_str.c_str(), base_str.length());
  return 0;
}
// 覆盖率提升: ~20% → ~80%
```

## 📝 修改的文件

### 1. Function Analyzer (分析阶段)

#### `function_analyzer_system.txt`
**新增内容**: PARAMETER MODELING STRATEGY 章节

```
**Default Approach: Use FuzzedDataProvider for Multi-Parameter Functions**

Strategy Selection Guidelines:
1. FuzzedDataProvider (DEFAULT for 2+ params)
2. DIRECT_FUZZ (for simple buffer functions)
3. CONSTRAIN (with FuzzedDataProvider)
4. FIX (LAST RESORT - avoid premature use)
```

**关键点**:
- 明确 FuzzedDataProvider 是 2+ 参数函数的默认策略
- 强调 FIX 策略是"最后手段"
- 警告：每个固定参数都会减少覆盖率潜力

#### `function_analyzer_final_summary_prompt.txt`
**新增内容**: Parameter Strategy Decision Guide

```
When to use FuzzedDataProvider (PREFERRED for multi-parameter functions)
When FIX strategy is acceptable (must document reason)
Common ANTI-PATTERNS to avoid
```

**关键点**:
- 提供具体示例（GOOD vs BAD）
- 明确 FIX 只在有文档化的 API 约束时使用
- 避免"为了简化"而固定参数

### 2. Prototyper (代码生成阶段)

#### `prototyper_system.txt`
**新增内容**: Parameter Variation Strategy 章节

```cpp
For multi-parameter functions (2+ params), DEFAULT to FuzzedDataProvider:
#include <fuzzer/FuzzedDataProvider.h>

FuzzedDataProvider fdp(data, size);
std::string param1 = fdp.ConsumeRandomLengthString(256);
int param2 = fdp.ConsumeIntegral<int>();
```

**关键点**:
- 明确"这是默认策略"
- 提供完整代码示例
- 列出何时可以偏离（很少见）

#### `prototyper_prompt.txt`
**新增内容**: PARAMETER CONSTRUCTION EXAMPLES 章节（放在最前面）

包含 3 个详细示例:
1. Multi-Parameter Function (FuzzedDataProvider)
2. Testing Edge Cases
3. Constrained Parameters

**关键改进**:
- 对比 ✅ GOOD vs ❌ BAD
- 展示覆盖率差异（20% vs 80%）
- 提供可直接复制的代码模板

### 3. Improver (覆盖率优化阶段)

#### `improver_system.txt`
**增强内容**: DECISION OVERRIDE AUTHORITY 章节

```
MOST COMMON OVERRIDE: FIX → FuzzedDataProvider 🎯

When to Override FIX Strategy:
✅ Always override if coverage is low and parameters are fixed
✅ Override even if SRS specified FIX (SRS may have been overly conservative)
✅ Override unless there's a DOCUMENTED API constraint
```

**关键点**:
- 授权 Improver "激进地"覆盖之前的 FIX 决策
- 提供完整的决策覆盖文档模板
- 强调：即使 SRS 指定了 FIX，也可以覆盖

#### `improver_prompt.txt`
**增强示例**: 更新所有示例以强调参数变化

```cpp
// Example 1: Override FIX Strategy → Use FuzzedDataProvider (MOST COMMON)
// OLD: Fixed base parameter (low coverage ~20%)
// NEW: Varied base parameter (high coverage ~80%)
```

**新增模板**: FuzzedDataProvider Template

## 🔧 策略选择决策树

```
函数有多少个参数？
│
├─ 1-2 个参数，接受原始 buffer
│  └─ 策略: DIRECT_FUZZ
│     extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
│       target_func(data, size);
│     }
│
└─ 2+ 个参数（DEFAULT 情况）
   │
   ├─ 是否有文档化的 API 约束？
   │  │
   │  ├─ 否（大多数情况）
   │  │  └─ 策略: FuzzedDataProvider（变化所有参数）
   │  │     FuzzedDataProvider fdp(data, size);
   │  │     std::string param1 = fdp.ConsumeRandomLengthString(256);
   │  │     int param2 = fdp.ConsumeIntegral<int>();
   │  │
   │  └─ 是（罕见）
   │     │
   │     ├─ 需要约束范围？
   │     │  └─ 策略: CONSTRAIN（使用 FuzzedDataProvider + 约束）
   │     │     int port = fdp.ConsumeIntegralInRange<int>(1, 65535);
   │     │
   │     └─ 必须固定值？（极其罕见）
   │        └─ 策略: FIX（必须文档化理由！）
   │           const char* magic = "MAGIC_NUMBER";
```

## 📊 预期效果

### 覆盖率提升

| 场景 | 升级前 | 升级后 | 提升 |
|------|--------|--------|------|
| 多参数函数（如 `parse_with_base`） | ~20% | ~80% | +60% |
| 单参数 buffer 函数 | ~70% | ~70% | 0% (已优化) |
| 状态机函数 | ~40% | ~75% | +35% |

### 代码路径探索

**升级前**（固定参数）:
```cpp
// 只测试一个代码路径
const char* base = "https://example.com/";
target_func(input, base);
```
- ✅ 测试: 有效的 base URL 处理
- ❌ 未测试: 无效 base、空 base、NULL、特殊字符
- ❌ 未测试: 错误处理路径

**升级后**（变化参数）:
```cpp
FuzzedDataProvider fdp(data, size);
std::string base = fdp.ConsumeRandomLengthString(256);
target_func(input, base.c_str());
```
- ✅ 测试: 有效 base URL
- ✅ 测试: 无效 base（错误格式）
- ✅ 测试: 空字符串
- ✅ 测试: 边界情况
- ✅ 测试: 错误处理路径

## 🎓 最佳实践

### ✅ DO（推荐做法）

1. **默认使用 FuzzedDataProvider**
   ```cpp
   FuzzedDataProvider fdp(data, size);
   std::string param1 = fdp.ConsumeRandomLengthString(256);
   int param2 = fdp.ConsumeIntegral<int>();
   ```

2. **测试边界情况**
   ```cpp
   bool test_null = fdp.ConsumeBool();
   const char* ptr = test_null ? nullptr : fdp.ConsumeRandomLengthString(256).c_str();
   ```

3. **使用约束而非固定**
   ```cpp
   // GOOD: 变化但有约束
   int port = fdp.ConsumeIntegralInRange<int>(1, 65535);
   
   // BAD: 完全固定
   int port = 8080;
   ```

### ❌ DON'T（避免做法）

1. **不要为了"简化"而固定参数**
   ```cpp
   // BAD: 限制覆盖率
   const char* base = "https://example.com/";
   
   // GOOD: 探索多个路径
   std::string base = fdp.ConsumeRandomLengthString(256);
   ```

2. **不要因为"示例都用常量 X"就固定**
   ```cpp
   // BAD: 复制示例的值
   int flags = 0;  // 示例都用 0
   
   // GOOD: 复制模式但变化值
   int flags = fdp.ConsumeIntegral<int>();
   ```

3. **不要为了"避免错误"而固定**
   ```cpp
   // BAD: 避免错误路径
   const char* valid_input = "valid";
   
   // GOOD: 测试错误路径
   std::string input = fdp.ConsumeRandomLengthString(256);
   ```

## 🔍 验证方法

### 检查 Function Analyzer 输出

```json
{
  "parameter_strategies": [
    {
      "parameter": "base",
      "strategy": "CONSTRAIN",  // ✅ 或 DIRECT_FUZZ
      "construction_method": "FuzzedDataProvider::ConsumeRandomLengthString(256)"
    },
    // ❌ 不应该看到太多 "strategy": "FIX"
  ]
}
```

### 检查 Prototyper 生成的代码

```cpp
// ✅ GOOD: 应该看到这个
#include <fuzzer/FuzzedDataProvider.h>
FuzzedDataProvider fdp(data, size);

// ❌ BAD: 不应该频繁看到这个（除非有充分理由）
const char* fixed_value = "...";
```

### 检查覆盖率

```bash
# 运行 fuzzer 后查看覆盖率
# 应该看到明显提升
Before: PC coverage: 1234/5678 (21.73%)
After:  PC coverage: 4321/5678 (76.11%)  # ✅ 提升 3.5x
```

## 🚀 迁移指南

对于现有项目，建议：

1. **重新分析有低覆盖率的函数**
   - 检查是否使用了 FIX 策略
   - 如果是，重新运行 Function Analyzer

2. **让 Improver 自动升级**
   - Improver 现在会主动识别并覆盖不当的 FIX 策略
   - 使用 `<decision>` 标签记录改进

3. **监控覆盖率变化**
   - 对比升级前后的覆盖率
   - 预期提升: 30-60%

## 📚 相关文档

- [Function Analyzer System Prompt](../prompts/agent_graph/function_analyzer_system.txt)
- [Prototyper Prompt](../prompts/agent_graph/prototyper_prompt.txt)
- [Improver System Prompt](../prompts/agent_graph/improver_system.txt)

## 🔗 参考资料

- [FuzzedDataProvider API](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md)
- [LibFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)

