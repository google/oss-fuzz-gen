# Hybrid Specification + Session Memory 协同设计

## Session Memory机制理解

### 当前架构

```
Session Memory (共享内存) = {
    api_constraints: []      // API使用约束
    archetype: {}            // 架构模式
    known_fixes: []          // 已知错误修复
    decisions: []            // 关键决策
    coverage_strategies: []  // 覆盖率策略
}
```

**流转方式**：
1. 每个agent通过`session_memory_header.txt`看到当前consensus
2. Agent在响应中使用XML tags标记新发现：
   - `<api_constraint>...</api_constraint>`
   - `<known_fix error="...">...</known_fix>`
   - `<decision reason="...">...</decision>`
   - `<coverage_strategy target="...">...</coverage_strategy>`
3. `extract_session_memory_updates_from_response()`提取这些tags
4. 更新合并到state中的session_memory
5. 下一个agent看到更新后的consensus

---

## 核心洞察：Session Memory是Knowledge，Skeleton是Artifact

### 两者的本质区别

| 维度 | Session Memory | Skeleton |
|------|----------------|----------|
| **本质** | Knowledge (知识) | Artifact (产物) |
| **形式** | 约束、策略、决策 | 代码结构 |
| **生命周期** | 跨iterations累积 | 每次迭代重建 |
| **用途** | 指导设计 | 具体实现 |
| **来源** | 多agent consensus | Function Analyzer生成 |

### 协同关系

```
Session Memory (知识层)
    ↓ 指导
Skeleton Refinement (实现层)
```

**关键点**：
- Session Memory记录"为什么"（why）
- Skeleton实现"是什么"（what）

---

## 优化设计：Session Memory驱动的Skeleton Refinement

### 核心理念

**Session Memory作为Skeleton Refinement的输入**

```
Long-term memory archetype template
    +
Session Memory (当前任务的constraints)
    +
Multi-source information (headers, call sites, etc.)
    ↓
Function Analyzer: 生成Refined Skeleton
    ↓
Skeleton + Session Memory Annotations
    ↓
Prototyper: 基于skeleton + annotations实现
    ↓
如果失败 → 更新Session Memory
```

---

## 详细设计

### Phase 1: 扩展Session Memory结构

**新增skeleton相关字段**：

```python
# agent_graph/state.py
session_memory: NotRequired[Dict[str, Any]] = {
    # 现有字段
    "api_constraints": [],
    "archetype": None,
    "known_fixes": [],
    "decisions": [],
    "coverage_strategies": [],
    
    # 新增skeleton refinement字段
    "skeleton_components": {
        "headers": [],           # 已确认的header includes
        "input_validation": [],  # 输入验证逻辑
        "setup_sequence": [],    # 初始化序列
        "cleanup_sequence": [],  # 清理序列
        "parameter_construction": []  # 参数构造方法
    }
}
```

**为什么需要这些字段？**

1. **headers**: Header Extraction agent发现的headers应该保存到session memory
   - 避免重复提取
   - 确保所有后续agent看到一致的headers

2. **input_validation**: 从preconditions和existing fuzzers提取的验证逻辑
   - 例如：`size >= 8`（需要两个int32_t参数）
   - 例如：`width > 0 && height > 0`（assert约束）

3. **setup_sequence**: 从call sites分析得到的初始化步骤
   - 例如：`new Terminal::Framebuffer(80, 24)`
   - 顺序很重要

4. **cleanup_sequence**: 资源清理步骤
   - 例如：`delete framebuffer`
   - 与setup_sequence对应

5. **parameter_construction**: 如何从fuzz input提取参数
   - 例如：`int width = *((int32_t*)data)`
   - 类型转换、边界检查

---

### Phase 2: Function Analyzer更新Session Memory

**在Function Analyzer的各个阶段更新session memory**：

#### 2.1 Initial Analysis阶段

```python
# agent_graph/agents/langgraph_agent.py - LangGraphFunctionAnalyzer

def _analyze_initial(self, state: FuzzingWorkflowState) -> dict:
    """Initial analysis - extract preconditions and determine archetype."""
    
    # ... existing code ...
    
    # 解析响应，提取skeleton components
    response_text = response.content
    
    # 提取API constraints (preconditions)
    if "preconditions" in response_text.lower():
        # 解析preconditions并标记为api_constraint
        # 例如：<api_constraint>Parameters must be positive (s_width > 0, s_height > 0)</api_constraint>
    
    # 提取archetype
    if archetype_match := re.search(r'archetype:\s*(\w+)', response_text, re.IGNORECASE):
        archetype_type = archetype_match.group(1)
        # 更新session_memory.archetype
    
    # 提取session memory updates
    session_memory_updates = extract_session_memory_updates_from_response(
        response_text,
        agent_name="function_analyzer",
        current_iteration=state.get("current_iteration", 0)
    )
    
    updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
    
    return {
        "specification": {...},
        "session_memory": updated_session_memory
    }
```

#### 2.2 Call Sites Analysis阶段

```markdown
# prompts/agent_graph/function_analyzer_iteration_prompt.txt

Based on the call site examples, identify:

1. **Setup Sequence**
   <setup_step order="1">Create Framebuffer with default size (80x24)</setup_step>
   <setup_step order="2">Initialize display surface</setup_step>

2. **Cleanup Sequence**
   <cleanup_step order="1">Delete framebuffer object</cleanup_step>

3. **Parameter Construction**
   <param_construction param="width">Extract from data[0:4] as int32_t</param_construction>
   <param_construction param="height">Extract from data[4:8] as int32_t</param_construction>
```

**提取逻辑**：

```python
def _extract_skeleton_components_from_response(response: str) -> dict:
    """Extract skeleton components from agent response."""
    
    components = {
        "setup_sequence": [],
        "cleanup_sequence": [],
        "parameter_construction": []
    }
    
    # Extract setup steps
    setup_pattern = r'<setup_step order="(\d+)">(.*?)</setup_step>'
    for match in re.finditer(setup_pattern, response, re.DOTALL):
        order = int(match.group(1))
        step = match.group(2).strip()
        components["setup_sequence"].append({"order": order, "step": step})
    
    # Extract cleanup steps
    cleanup_pattern = r'<cleanup_step order="(\d+)">(.*?)</cleanup_step>'
    for match in re.finditer(cleanup_pattern, response, re.DOTALL):
        order = int(match.group(1))
        step = match.group(2).strip()
        components["cleanup_sequence"].append({"order": order, "step": step})
    
    # Extract parameter construction
    param_pattern = r'<param_construction param="([^"]+)">(.*?)</param_construction>'
    for match in re.finditer(param_pattern, response, re.DOTALL):
        param = match.group(1).strip()
        method = match.group(2).strip()
        components["parameter_construction"].append({"param": param, "method": method})
    
    return components
```

#### 2.3 Final Summary阶段：使用Session Memory

**修改prompt**：

```markdown
# prompts/agent_graph/function_analyzer_final_summary_prompt.txt

# Current Consensus Constraints

{CONSENSUS_CONTEXT}  # 来自session memory

---

# Available Skeleton Components (from Session Memory)

## Confirmed Headers
{headers_from_session_memory}

## Input Validation Rules
{validation_rules_from_session_memory}

## Setup Sequence
{setup_sequence_from_session_memory}

## Cleanup Sequence
{cleanup_sequence_from_session_memory}

## Parameter Construction Methods
{param_construction_from_session_memory}

---

# Your Task

Using the **confirmed skeleton components above**, generate a **refined driver skeleton**:

## 6. Refined Driver Skeleton

```c
// === REFINED SKELETON ===
// Headers (from session memory)
{inject_headers_here}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Input validation (from session memory validation rules)
  {inject_validation_here}
  
  // Setup sequence (from session memory, in order)
  {inject_setup_sequence_here}
  
  // Parameter construction (from session memory)
  {inject_param_construction_here}
  
  // Main API call
  {target_function_call}
  
  // Cleanup sequence (from session memory, reverse order)
  {inject_cleanup_sequence_here}
  
  return 0;
}
```

## 7. Annotations

Provide rationale for any design choices NOT already documented in session memory.
```

---

### Phase 3: Header Extraction更新Session Memory

**当前问题**：Header Extraction结果只存在`state['header_info']`，Function Analyzer可能看不到

**优化方案**：Header Extraction也更新session memory

```python
# agent_graph/agents/langgraph_agent.py - LangGraphHeaderExtraction

def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
    """Execute header extraction and update session memory."""
    
    # ... existing extraction logic ...
    
    headers = self._extract_headers(...)
    
    # 更新session memory
    session_memory = state.get("session_memory", {})
    skeleton_components = session_memory.get("skeleton_components", {})
    
    # 添加headers到session memory
    for header in headers:
        if header not in skeleton_components.get("headers", []):
            skeleton_components.setdefault("headers", []).append({
                "path": header,
                "source": "header_extraction",
                "confidence": "high",  # Header extraction结果可信度高
                "iteration": state.get("current_iteration", 0)
            })
    
    session_memory["skeleton_components"] = skeleton_components
    
    return {
        "header_info": headers,  # 保留原有字段
        "session_memory": session_memory  # 新增session memory更新
    }
```

---

### Phase 4: Prototyper使用Session Memory

**优化Prototyper prompt**：

```markdown
# prompts/agent_graph/prototyper_prompt.txt

# Current Consensus Constraints

{CONSENSUS_CONTEXT}  # 包含所有skeleton components

---

# Your Task

You will receive a **refined skeleton** that was built using the consensus constraints above.

## What to Do

Make **minimal refinements** only:

1. ✅ Improve variable naming
2. ✅ Fine-tune boundary values (if annotations suggest)
3. ✅ Add error handling (if needed)

## What NOT to Do

1. ❌ Change headers (they are consensus from header_extraction)
2. ❌ Modify setup/cleanup sequence (they are consensus from call_sites)
3. ❌ Change parameter construction (it's consensus from function_analyzer)

## Example

**Session Memory shows**:
- Headers: `#include "terminal/framebuffer.h"` (high confidence)
- Setup: `new Terminal::Framebuffer(80, 24)` (from call sites)
- Validation: `size >= 8` (from preconditions)

**Refined Skeleton**:
```c
#include "terminal/framebuffer.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;
  auto *fb = new Terminal::Framebuffer(80, 24);
  int w = *((int32_t*)data);
  int h = *((int32_t*)(data + 4));
  fb->resize(w, h);
  delete fb;
  return 0;
}
```

**Your minimal changes**:
```c
#include "terminal/framebuffer.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;
  
  // Better variable naming
  Terminal::Framebuffer *framebuffer = new Terminal::Framebuffer(80, 24);
  if (!framebuffer) return 0;  // Null check
  
  // Extract and sanitize parameters
  int width = *((int32_t*)data);
  int height = *((int32_t*)(data + 4));
  
  // Clamp to prevent resource exhaustion (from session memory constraints)
  if (width <= 0) width = 1;
  if (height <= 0) height = 1;
  if (width > 1000) width = 1000;
  if (height > 1000) height = 1000;
  
  framebuffer->resize(width, height);
  
  delete framebuffer;
  return 0;
}
```

**Explanation**:
- ✅ Improved variable naming (`fb` → `framebuffer`)
- ✅ Added null check
- ✅ Added parameter sanitization (based on API constraints in session memory)
- ❌ Did NOT change header (it's consensus)
- ❌ Did NOT change setup sequence (it's consensus)
```

---

### Phase 5: Crash Analyzer/Enhancer反馈到Session Memory

**当编译/运行失败时，更新session memory**：

```markdown
# prompts/agent_graph/enhancer_prompt.txt

If you fix an error, document it for future iterations:

<known_fix error="missing header: terminal/framebuffer.h">
Add #include "src/terminal/terminalframebuffer.h" instead
</known_fix>

<api_constraint>
Framebuffer constructor requires positive dimensions, enforce width > 0 && height > 0
</api_constraint>
```

**效果**：下一次迭代时，所有agent都能看到这些fixes

---

## 信息流设计

### 完整的Hybrid Specification生成流程

```
[Initial State]
    ↓
Header Extraction
    ├─ 提取headers
    └─ 更新session_memory.skeleton_components.headers
    ↓
Function Analyzer (Initial)
    ├─ 分析preconditions
    ├─ 确定archetype
    └─ 更新session_memory.api_constraints
    ↓
Function Analyzer (Call Sites Iteration)
    ├─ 分析call sites
    ├─ 提取setup/cleanup序列
    └─ 更新session_memory.skeleton_components.{setup_sequence, cleanup_sequence}
    ↓
Function Analyzer (Final Summary)
    ├─ 读取session_memory中的所有skeleton components
    ├─ 组装refined skeleton
    └─ 生成annotations
    ↓
Prototyper
    ├─ 读取refined skeleton
    ├─ 读取session_memory (constraints, components)
    ├─ 做minimal refinement
    └─ 生成final fuzz target
    ↓
Compiler/Builder
    ├─ 尝试编译
    └─ 如果失败 → Crash Analyzer/Enhancer
    ↓
Crash Analyzer/Enhancer
    ├─ 分析错误
    ├─ 修复问题
    └─ 更新session_memory.known_fixes
    ↓
[Next Iteration]
    ├─ 所有agent看到updated session_memory
    └─ 避免重复相同错误
```

---

## Session Memory的演化示例

### Iteration 0 (初始状态)

```json
{
  "api_constraints": [],
  "archetype": null,
  "known_fixes": [],
  "decisions": [],
  "coverage_strategies": [],
  "skeleton_components": {
    "headers": [],
    "input_validation": [],
    "setup_sequence": [],
    "cleanup_sequence": [],
    "parameter_construction": []
  }
}
```

### Iteration 1 (Header Extraction + Function Analyzer)

```json
{
  "api_constraints": [
    {
      "constraint": "Parameters must be positive (width > 0, height > 0)",
      "source": "function_analyzer",
      "confidence": "high",
      "iteration": 1
    }
  ],
  "archetype": {
    "type": "object_lifecycle",
    "lifecycle_phases": ["create", "use", "destroy"],
    "source": "function_analyzer",
    "iteration": 1
  },
  "skeleton_components": {
    "headers": [
      {
        "path": "#include \"src/terminal/terminalframebuffer.h\"",
        "source": "header_extraction",
        "confidence": "high",
        "iteration": 1
      }
    ],
    "input_validation": [
      {
        "rule": "size >= 8",
        "reason": "Need 2 x int32_t for width and height",
        "source": "function_analyzer",
        "iteration": 1
      }
    ],
    "setup_sequence": [],  // 尚未提取
    "cleanup_sequence": [],
    "parameter_construction": []
  }
}
```

### Iteration 2 (Call Sites Analysis)

```json
{
  "skeleton_components": {
    "headers": [...],  // 保留之前的
    "input_validation": [...],
    "setup_sequence": [
      {
        "order": 1,
        "step": "Terminal::Framebuffer *fb = new Terminal::Framebuffer(80, 24)",
        "source": "function_analyzer",
        "iteration": 2
      }
    ],
    "cleanup_sequence": [
      {
        "order": 1,
        "step": "delete fb",
        "source": "function_analyzer",
        "iteration": 2
      }
    ],
    "parameter_construction": [
      {
        "param": "width",
        "method": "int width = *((int32_t*)data)",
        "source": "function_analyzer",
        "iteration": 2
      },
      {
        "param": "height",
        "method": "int height = *((int32_t*)(data + 4))",
        "source": "function_analyzer",
        "iteration": 2
      }
    ]
  }
}
```

### Iteration 3 (Compilation Error → Enhancer Fix)

```json
{
  "known_fixes": [
    {
      "error_pattern": "undefined reference to Terminal::Framebuffer::Framebuffer",
      "solution": "Add null check after new: if (!fb) return 0;",
      "source": "enhancer",
      "iteration": 3
    }
  ],
  "skeleton_components": {
    "setup_sequence": [
      {
        "order": 1,
        "step": "Terminal::Framebuffer *fb = new Terminal::Framebuffer(80, 24)",
        "source": "function_analyzer",
        "iteration": 2
      },
      {
        "order": 2,
        "step": "if (!fb) return 0",  // 新增
        "source": "enhancer",
        "iteration": 3
      }
    ]
  }
}
```

---

## 实施步骤

### Step 1: 扩展Session Memory结构 ✅

**文件**: `agent_graph/state.py`

```python
# 新增skeleton_components字段到session_memory默认结构
def consolidate_session_memory(state: FuzzingWorkflowState) -> Dict[str, Any]:
    """..."""
    if not session_memory:
        return {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": [],
            "skeleton_components": {  # 新增
                "headers": [],
                "input_validation": [],
                "setup_sequence": [],
                "cleanup_sequence": [],
                "parameter_construction": []
            }
        }
```

**文件**: `agent_graph/state.py` - 新增helper functions

```python
def add_skeleton_header(
    state: FuzzingWorkflowState,
    header_path: str,
    source: str,
    confidence: str = "medium",
    iteration: int = None
) -> None:
    """Add a header to skeleton_components."""
    # ...

def add_skeleton_validation_rule(
    state: FuzzingWorkflowState,
    rule: str,
    reason: str,
    source: str,
    iteration: int = None
) -> None:
    """Add input validation rule to skeleton_components."""
    # ...

def add_skeleton_setup_step(
    state: FuzzingWorkflowState,
    step: str,
    order: int,
    source: str,
    iteration: int = None
) -> None:
    """Add setup step to skeleton_components."""
    # ...

# 类似的: add_skeleton_cleanup_step, add_skeleton_param_construction
```

### Step 2: 修改Session Memory Injector ✅

**文件**: `agent_graph/session_memory_injector.py`

**新增提取逻辑**：

```python
def extract_session_memory_updates_from_response(
    response: str,
    agent_name: str,
    current_iteration: int
) -> Dict[str, Any]:
    """Extract session_memory updates from agent response."""
    
    updates = {
        # 现有字段
        "api_constraints": [],
        "known_fixes": [],
        "decisions": [],
        "coverage_strategies": [],
        
        # 新增skeleton components
        "skeleton_components": {
            "headers": [],
            "input_validation": [],
            "setup_sequence": [],
            "cleanup_sequence": [],
            "parameter_construction": []
        }
    }
    
    # ... 现有提取逻辑 ...
    
    # 新增：提取skeleton components
    
    # Extract headers
    header_pattern = r'<skeleton_header path="([^"]+)" confidence="([^"]+)">'
    for match in re.finditer(header_pattern, response):
        path = match.group(1).strip()
        confidence = match.group(2).strip()
        updates["skeleton_components"]["headers"].append({
            "path": path,
            "confidence": confidence,
            "source": agent_name,
            "iteration": current_iteration
        })
    
    # Extract validation rules
    validation_pattern = r'<validation_rule reason="([^"]+)">(.*?)</validation_rule>'
    for match in re.finditer(validation_pattern, response, re.DOTALL):
        reason = match.group(1).strip()
        rule = match.group(2).strip()
        updates["skeleton_components"]["input_validation"].append({
            "rule": rule,
            "reason": reason,
            "source": agent_name,
            "iteration": current_iteration
        })
    
    # Extract setup/cleanup/param construction
    # ... 类似逻辑 ...
    
    return updates
```

**更新format函数**：

```python
def format_session_memory_for_prompt(state: FuzzingWorkflowState) -> str:
    """Format session_memory as readable text for injection into agent prompts."""
    
    # ... 现有逻辑 ...
    
    # 新增：Format skeleton components
    if skeleton_components := session_memory.get("skeleton_components", {}):
        if headers := skeleton_components.get("headers", []):
            parts.append("\n## Confirmed Headers")
            for h in headers:
                parts.append(f"- {h['path']} (confidence: {h['confidence']}, source: {h['source']})")
        
        if validation := skeleton_components.get("input_validation", []):
            parts.append("\n## Input Validation Rules")
            for v in validation:
                parts.append(f"- `{v['rule']}` - {v['reason']}")
        
        if setup := skeleton_components.get("setup_sequence", []):
            parts.append("\n## Setup Sequence")
            for s in sorted(setup, key=lambda x: x.get('order', 0)):
                parts.append(f"{s['order']}. {s['step']}")
        
        if cleanup := skeleton_components.get("cleanup_sequence", []):
            parts.append("\n## Cleanup Sequence")
            for c in sorted(cleanup, key=lambda x: x.get('order', 0)):
                parts.append(f"{c['order']}. {c['step']}")
        
        if params := skeleton_components.get("parameter_construction", []):
            parts.append("\n## Parameter Construction")
            for p in params:
                parts.append(f"- **{p['param']}**: {p['method']}")
    
    return "\n".join(parts)
```

### Step 3: 修改Header Extraction更新Session Memory ✅

**文件**: `agent_graph/agents/langgraph_agent.py`

```python
class LangGraphHeaderExtraction(LangGraphAgent):
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Execute header extraction and update session memory."""
        
        # ... 现有提取逻辑 ...
        
        headers = [...]  # 提取到的headers
        
        # 更新session memory
        from agent_graph.state import add_skeleton_header
        
        for header in headers:
            add_skeleton_header(
                state,
                header_path=header,
                source="header_extraction",
                confidence="high",
                iteration=state.get("current_iteration", 0)
            )
        
        return {
            "header_info": headers,  # 保留原有字段
            "session_memory": state.get("session_memory")  # 返回更新后的session_memory
        }
```

### Step 4: 修改Function Analyzer Prompts ✅

**文件**: `prompts/agent_graph/function_analyzer_iteration_prompt.txt`

**新增指令**：

```markdown
# Extracting Skeleton Components

As you analyze the function, extract reusable skeleton components using these tags:

## Setup Sequence
<setup_step order="1">Initialization code</setup_step>
<setup_step order="2">Resource allocation</setup_step>

## Cleanup Sequence
<cleanup_step order="1">Resource deallocation (reverse order of setup)</cleanup_step>

## Parameter Construction
<param_construction param="parameter_name">Method to extract from fuzz input</param_construction>

## Input Validation
<validation_rule reason="rationale">if (condition) return 0;</validation_rule>

These will be extracted and added to session memory for use in final skeleton generation.
```

**文件**: `prompts/agent_graph/function_analyzer_final_summary_prompt.txt`

**修改skeleton生成部分**：

```markdown
# Available Skeleton Components (from Consensus)

The following components have been confirmed by analysis:

{SKELETON_COMPONENTS_FROM_SESSION_MEMORY}

---

# Your Task

## 6. Refined Driver Skeleton

Using the **confirmed skeleton components above**, generate a refined driver skeleton:

**IMPORTANT**:
- Use headers from session memory (don't invent new ones)
- Follow setup/cleanup sequences from session memory
- Apply input validation rules from session memory
- Use parameter construction methods from session memory

```c
// === REFINED SKELETON ===
{use_headers_from_session_memory}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  {use_validation_rules_from_session_memory}
  
  {use_setup_sequence_from_session_memory}
  
  {use_param_construction_from_session_memory}
  
  // Main API call
  {target_function}({parameters});
  
  {use_cleanup_sequence_from_session_memory}
  
  return 0;
}
```

## 7. Annotations

Only annotate design choices **NOT already documented** in session memory.
Refer to session memory components by citing their source/iteration.
```

### Step 5: 修改Prototyper Prompt ✅

**文件**: `prompts/agent_graph/prototyper_prompt.txt`

**强调session memory约束**：

```markdown
# Important: Respect Consensus Constraints

The skeleton you receive was built using consensus constraints from session memory.

**YOU MUST NOT**:
- ❌ Change headers (they are high-confidence from header_extraction)
- ❌ Modify setup/cleanup sequence (they are consensus from call_sites)
- ❌ Remove input validation (they are consensus from preconditions)
- ❌ Change parameter construction methods (they are consensus)

**YOU SHOULD ONLY**:
- ✅ Improve variable names
- ✅ Add comments
- ✅ Fine-tune boundary values (if annotations suggest)
- ✅ Add error handling (if not present)

If you believe a consensus constraint is incorrect, **explain why** in your response
using the <decision> tag, but do NOT change it in the code.
```

---

## 优势分析

### 1. 知识累积（Across Iterations）

**旧设计**：每次迭代重新分析，重复犯错

**新设计**：
- Iteration 1: 发现header路径错误 → 更新known_fixes
- Iteration 2: 自动使用正确路径
- Iteration 3: 发现需要null check → 更新setup_sequence
- Iteration 4: 自动包含null check

### 2. 多Agent协同

**旧设计**：Header Extraction的结果可能被Function Analyzer忽略

**新设计**：
- Header Extraction → session_memory.skeleton_components.headers
- Function Analyzer读取session_memory → 直接使用确认的headers
- Prototyper读取session_memory → 不会修改consensus headers

### 3. 可追溯性

每个skeleton component都有：
- `source`: 来自哪个agent
- `iteration`: 在哪次迭代添加
- `confidence`: 可信度

**例子**：
```json
{
  "path": "#include \"src/terminal/terminalframebuffer.h\"",
  "source": "header_extraction",
  "confidence": "high",
  "iteration": 1
}
```

### 4. 冲突解决

如果多个agent提供不同的skeleton components，可以根据：
- Confidence level (high > medium > low)
- Source priority (header_extraction > function_analyzer > prototyper)
- Iteration (later > earlier, if it's a fix)

---

## 潜在风险与缓解

### Risk 1: Session Memory过大

**风险**：skeleton_components累积太多，prompt过长

**缓解**：
- 在`consolidate_session_memory()`中限制每类component数量
- 只保留最高confidence的items
- 去重（相同内容只保留一个）

### Risk 2: 错误信息传播

**风险**：如果agent提取了错误的component，后续迭代都会使用

**缓解**：
- 允许agent通过`<decision>`标签质疑consensus
- Enhancer发现错误时，可以更新/覆盖之前的components
- 使用confidence level，低confidence的可以被高confidence覆盖

### Risk 3: Agent过度依赖Session Memory

**风险**：Agent不做分析，直接使用session memory

**缓解**：
- Prompt中强调"session memory是参考，不是强制"
- 要求agent解释为什么使用/不使用session memory中的component
- 如果session memory为空（首次迭代），agent仍需独立分析

---

## 实施计划

### Phase 1: 基础设施（2-3小时）
1. ✅ 扩展`state.py`中的session_memory结构
2. ✅ 添加skeleton component helper functions
3. ✅ 更新`session_memory_injector.py`提取和格式化逻辑
4. ✅ 测试session memory读写

### Phase 2: Agent集成（3-4小时）
1. ✅ 修改Header Extraction更新session memory
2. ✅ 修改Function Analyzer提取skeleton components
3. ✅ 修改Function Analyzer使用session memory组装skeleton
4. ✅ 测试单个agent的session memory更新

### Phase 3: Prompt优化（2-3小时）
1. ✅ 修改`function_analyzer_iteration_prompt.txt`（添加提取tags）
2. ✅ 修改`function_analyzer_final_summary_prompt.txt`（使用session memory）
3. ✅ 修改`prototyper_prompt.txt`（强调consensus约束）
4. ✅ 测试prompt效果

### Phase 4: 端到端测试（2-3小时）
1. ✅ 在测试集上运行完整workflow
2. ✅ 检查session memory是否正确累积
3. ✅ 检查skeleton quality是否提升
4. ✅ 对比新旧设计的效果

---

## 总结

### 核心创新

**Hybrid Specification = Skeleton Code + Session Memory Annotations**

- **Skeleton Code**: 具体实现（what）
- **Session Memory**: 知识层（why + how）
  - API constraints
  - Skeleton components (headers, validation, setup, cleanup, params)
  - Known fixes
  - Decisions

### 关键优势

1. **知识累积**：跨iterations避免重复错误
2. **Multi-agent协同**：Header Extraction ↔ Function Analyzer ↔ Prototyper
3. **可追溯性**：每个component都有source和iteration
4. **Refinement质量**：Skeleton基于consensus，而不是单一agent的猜测

### 下一步

你觉得这个设计方向OK吗？要不要我开始实施Phase 1？

