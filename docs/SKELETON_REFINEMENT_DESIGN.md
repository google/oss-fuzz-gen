# Skeleton Refinement 设计方案

## 问题分析

### 当前流程（已修复后）

```
Header Extraction
    ↓
Function Analyzer (概念描述)
    ↓
_retrieve_skeleton (组装skeleton + headers)
    ↓
Prototyper (填空实现)
```

**仍存在的问题**：
1. Function Analyzer输出的是**概念性描述**（自然语言），而不是**具体的skeleton**
2. Prototyper需要从概念描述→skeleton实现，跨度太大
3. 多源信息（call sites、existing fuzzers、FI数据）没有充分利用来**精炼skeleton**

### 你的优化思路

**核心理念**：Function Analyzer应该是**skeleton refinement**过程

```
初始skeleton (from long_term_memory)
    ↓
Function Analyzer: 迭代精炼skeleton
    ├─ 使用call sites信息 → 补全setup/cleanup序列
    ├─ 使用existing fuzzers → 补全input validation
    ├─ 使用header extraction → 补全includes
    └─ 使用函数签名分析 → 补全参数构造
    ↓
精炼后的完整skeleton + 详细spec
    ↓
Prototyper: 最小化修改（只填空变量名等细节）
```

---

## 新设计方案

### 核心原则

1. **Skeleton as Single Source of Truth**
   - Function Analyzer的主要输出是**精炼后的skeleton代码**
   - Specification是skeleton的**自然语言补充说明**，而不是主体

2. **Iterative Refinement**
   - 初始skeleton来自long_term_memory（archetype模板）
   - Function Analyzer通过多源信息**逐步填充**skeleton的各个部分
   - 每次迭代都是在**当前skeleton基础上**进行改进

3. **Minimal Prototyping**
   - Prototyper只做**最小化修改**（变量名、具体值、边界情况等）
   - 不需要重新设计driver结构

---

## 详细设计

### Phase 1: Function Analyzer的新输出格式

**文件**: `prompts/agent_graph/function_analyzer_final_summary_prompt.txt`

```markdown
## 6. Refined Driver Skeleton

Based on the initial skeleton and all gathered information, provide a **refined skeleton** with:
- All headers included (from header extraction)
- Input validation logic (from preconditions + existing fuzzers)
- Resource allocation (from function signature + dependencies)
- Setup sequence (from call sites + archetype pattern)
- Main API call (with parameter construction)
- Cleanup sequence (from postconditions + resource tracking)

**IMPORTANT**: This should be **compilable pseudo-code** with concrete structure, not abstract placeholders.

Use information from:
1. **Header Extraction**: Include all discovered headers
2. **Call Sites**: Identify common setup/cleanup patterns
3. **Existing Fuzzers**: Extract input validation and initialization patterns
4. **Function Signature**: Determine parameter construction strategy
5. **Archetype Pattern**: Follow the proven pattern structure

```c
// === REFINED SKELETON ===
// (All headers are included below)
#include <stddef.h>
#include <stdint.h>
#include "src/terminal/terminalframebuffer.h"  // From header extraction

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation (refined from preconditions + existing fuzzers)
  if (size < 8) return 0;  // Need at least width(4) + height(4)
  
  // Resource allocation (refined from function analysis)
  Terminal::Framebuffer *fb = new Terminal::Framebuffer(80, 24);
  if (!fb) return 0;
  
  // Extract parameters from fuzz input
  int width = *((int32_t*)data);
  int height = *((int32_t*)(data + 4));
  
  // Sanitize parameters (from preconditions)
  if (width <= 0) width = 1;
  if (height <= 0) height = 1;
  if (width > 1000) width = 1000;   // Prevent resource exhaustion
  if (height > 1000) height = 1000;
  
  // Main API call
  fb->resize(width, height);
  
  // Cleanup
  delete fb;
  return 0;
}
```

## 7. Specification Annotations

Provide **detailed annotations** for the refined skeleton:

### Input Validation Rationale
- Minimum size: 8 bytes (2 x int32_t for width and height)
- Parameter sanitization: Positive values enforced (precondition from assert)
- Upper bounds: 1000x1000 to prevent OOM (resource consideration)

### Resource Management
- Framebuffer object: Must be initialized before resize
- Initial size: 80x24 (common terminal size, from existing fuzzers)
- Cleanup: delete to prevent memory leak

### Edge Cases to Test
- Zero/negative dimensions (caught by sanitization)
- Same dimensions (width unchanged branch, line 14-15 in snippet)
- Expanding dimensions (new cells allocation, line 20)
- Shrinking dimensions (row truncation, line 11-13)

### Coverage Goals
- Both branches of width comparison (oldwidth == s_width vs !=)
- Both branches of height comparison (resize rows or not)
- Exception safety (allocation failures in make_shared, vector::resize)
```

---

### Phase 2: Function Analyzer的实现调整

**文件**: `agent_graph/agents/langgraph_agent.py`

**关键修改**：

1. **在Final Summary Prompt之前，预先组装skeleton**

```python
def _function_analyzer_final_summary(self, state: FuzzTargetState) -> dict:
    """Generate final summary with refined skeleton."""
    
    # 1. 获取archetype
    archetype = state.get('specification', {}).get('archetype', 'object_lifecycle')
    
    # 2. 获取初始skeleton模板
    skeleton_template = self._load_skeleton_template(archetype)
    
    # 3. 提取headers
    header_info = state.get('header_info', {})
    header_section = self._format_header_section(header_info, archetype)
    
    # 4. 组装initial skeleton（带headers）
    initial_skeleton = self._assemble_initial_skeleton(
        skeleton_template, 
        header_section
    )
    
    # 5. 提取多源信息
    call_sites = state.get('call_sites', [])
    existing_fuzzers = state.get('existing_fuzzers', [])
    function_info = state.get('function_info', {})
    
    # 6. 构建prompt（包含initial skeleton + 多源信息）
    prompt = self._build_refinement_prompt(
        initial_skeleton=initial_skeleton,
        call_sites=call_sites,
        existing_fuzzers=existing_fuzzers,
        function_info=function_info,
        archetype_knowledge=archetype_knowledge
    )
    
    # 7. LLM生成refined skeleton
    response = self.llm.invoke(prompt)
    
    # 8. 解析refined skeleton和annotations
    refined_skeleton = self._extract_skeleton_from_response(response)
    annotations = self._extract_annotations_from_response(response)
    
    # 9. 更新state
    return {
        'specification': {
            'refined_skeleton': refined_skeleton,
            'annotations': annotations,
            'archetype': archetype
        }
    }
```

2. **新增辅助方法**

```python
def _assemble_initial_skeleton(self, template: str, headers: str) -> str:
    """Assemble initial skeleton with headers."""
    return f"""// === INITIAL SKELETON (to be refined) ===
{headers}

{template}
"""

def _build_refinement_prompt(self, **kwargs) -> str:
    """Build prompt for skeleton refinement."""
    initial_skeleton = kwargs['initial_skeleton']
    call_sites = kwargs['call_sites']
    existing_fuzzers = kwargs['existing_fuzzers']
    
    return f"""
You are refining a driver skeleton for fuzzing.

## Initial Skeleton (provided)
```c
{initial_skeleton}
```

## Available Information to Refine Skeleton

### 1. Call Sites Analysis
{self._format_call_sites(call_sites)}

### 2. Existing Fuzzers Reference
{self._format_existing_fuzzers(existing_fuzzers)}

### 3. Function Signature
{kwargs['function_info']}

### 4. Archetype Pattern Knowledge
{kwargs['archetype_knowledge']}

## Task
Refine the initial skeleton by:
1. Filling in concrete input validation logic
2. Adding specific resource allocation code
3. Implementing parameter extraction from fuzz input
4. Defining cleanup sequence based on allocated resources

**Output Format**: See Section 6 & 7 in the template
"""
```

---

### Phase 3: Prototyper的简化

**文件**: `prompts/agent_graph/prototyper_prompt.txt`

**新指令**：

```markdown
# Task: Minimal Refinement of Driver Skeleton

You will receive a **refined driver skeleton** that already contains:
- ✅ Correct headers
- ✅ Driver structure (input validation, setup, cleanup)
- ✅ Main API call
- ✅ Resource management pattern

Your job is to make **minimal adjustments** only:

## What You SHOULD Do
1. **Variable naming**: Choose appropriate names (e.g., `fb` → `framebuffer`)
2. **Concrete values**: Replace placeholders with specific values (e.g., `{min}` → `8`)
3. **Edge case handling**: Add missing boundary checks if annotations suggest
4. **Error handling**: Add try-catch if C++ exceptions are mentioned

## What You MUST NOT Do
1. ❌ Change header includes
2. ❌ Restructure the driver flow
3. ❌ Add new API calls not mentioned in skeleton
4. ❌ Remove existing validation logic

## Example

**Input (Refined Skeleton)**:
```c
#include "api.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_SIZE) return 0;  // Placeholder
  obj_t *obj = create_obj();
  process(obj, data, size);
  destroy_obj(obj);
  return 0;
}
```

**Your Output (Minimal Changes)**:
```c
#include "api.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return 0;  // MIN_SIZE = 4 (from annotations)
  
  obj_t *obj = create_obj();
  if (!obj) return 0;  // Add null check
  
  process(obj, data, size);
  destroy_obj(obj);
  return 0;
}
```

**Explanation**:
- ✅ Replaced `MIN_SIZE` with concrete value `4`
- ✅ Added null check for `obj`
- ❌ Did NOT change headers
- ❌ Did NOT change driver structure
```

---

## 对比：旧设计 vs 新设计

| 方面 | 旧设计 (修复后) | 新设计 (Refinement) |
|------|----------------|---------------------|
| **Function Analyzer输出** | 概念描述 | 精炼后的skeleton代码 |
| **Specification内容** | 自然语言为主 | Skeleton为主 + 注释 |
| **多源信息利用** | 仅作参考 | 主动用于填充skeleton |
| **Prototyper任务** | 从概念→代码 | 最小化调整 |
| **Skeleton来源** | Long-term memory | Long-term memory + refinement |
| **Header处理** | 在_retrieve_skeleton | 在analyzer阶段预先组装 |

---

## 预期效果

### Function Analyzer输出示例

```markdown
## 6. Refined Driver Skeleton

```c
// === REFINED SKELETON ===
#include <stddef.h>
#include <stdint.h>
#include "src/terminal/terminalframebuffer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation
  if (size < 8) return 0;
  
  // Resource allocation
  Terminal::Framebuffer *fb = new Terminal::Framebuffer(80, 24);
  if (!fb) return 0;
  
  // Extract parameters
  int width = *((int32_t*)data);
  int height = *((int32_t*)(data + 4));
  
  // Sanitize
  if (width <= 0) width = 1;
  if (height <= 0) height = 1;
  if (width > 1000) width = 1000;
  if (height > 1000) height = 1000;
  
  // Main API call
  fb->resize(width, height);
  
  // Cleanup
  delete fb;
  return 0;
}
```

## 7. Specification Annotations
... (详细说明)
```

### Prototyper只需微调

```c
// Prototyper可能只会改：
// 1. 变量名：fb → framebuffer
// 2. 添加异常处理：try-catch
// 3. 更精确的边界值
```

---

## 实施步骤

1. ✅ 修改`function_analyzer_final_summary_prompt.txt`
   - 将"## 6. Driver Structure"改回"## 6. Refined Driver Skeleton"
   - 要求输出**完整的skeleton代码**（而不是概念描述）
   - 添加"## 7. Specification Annotations"部分

2. ✅ 修改`langgraph_agent.py`
   - 在调用final summary之前，预先组装initial skeleton
   - 将initial skeleton作为prompt的一部分传入
   - 提取refined skeleton并存入state

3. ✅ 修改`prototyper_prompt.txt`
   - 强调"minimal refinement"
   - 列出禁止修改的内容

4. ✅ 测试验证
   - 检查Function Analyzer是否输出完整skeleton
   - 检查Prototyper是否只做最小修改
   - 验证生成的fuzz target质量

---

## 优势分析

### 1. 更清晰的职责分离

- **Function Analyzer**: 代码架构师（从多源信息构建skeleton）
- **Prototyper**: 代码实现者（填充细节）

### 2. 更充分的信息利用

- Call sites → setup/cleanup序列
- Existing fuzzers → input validation模式
- Headers → 正确的includes
- Function signature → 参数构造策略

### 3. 更小的LLM跨度

- 旧设计：概念描述 → 完整代码（跨度大）
- 新设计：skeleton模板 → refined skeleton（迭代小步）

### 4. 更好的可调试性

- Function Analyzer输出是可编译的代码
- 可以直接看到refinement的效果
- 问题定位更容易（是analyzer还是prototyper的问题？）

---

## 潜在风险

### 1. Function Analyzer任务变重

**风险**: LLM需要生成更多代码，可能增加token消耗  
**缓解**: 通过明确的多源信息引导，减少试错

### 2. Skeleton quality依赖多源信息

**风险**: 如果call sites/existing fuzzers信息不足，skeleton可能不完整  
**缓解**: 提供fallback逻辑，使用archetype默认模式

### 3. Prototyper可能过度修改

**风险**: LLM可能忽略"minimal changes"指令  
**缓解**: 在prompt中明确列出禁止项，并加强约束

---

## 下一步

选择以下方案之一：

### Option A: 完全实施新设计
- 修改所有3个组件（analyzer prompt + langgraph_agent + prototyper prompt）
- 重新测试整个workflow

### Option B: 渐进式实施
- 先修改Function Analyzer输出格式（输出skeleton + annotations）
- 保持Prototyper不变，观察效果
- 如果效果好，再优化Prototyper为minimal refinement

### Option C: 混合模式
- Function Analyzer输出：refined skeleton + 概念描述
- Prototyper可以选择使用skeleton或从概念重新生成
- 给LLM更多灵活性

---

## 推荐方案

**推荐Option A (完全实施)**

原因：
1. 设计理念清晰：skeleton refinement
2. 职责分离明确：analyzer构建，prototyper微调
3. 信息利用充分：多源数据直接用于skeleton填充
4. 当前修复已经铺平道路：skeleton模板已清理，header extraction已就位

风险可控：
- 可以在测试集上先验证
- 如果效果不好，可以回退到当前修复版本

