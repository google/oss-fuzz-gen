# Function Analyzer 重新设计方案

## 问题：当前架构的职责混乱

### 现状

```
Function Analyzer (浅层语法分析)
  ↓ 输出: function_analysis.txt (文本规格)
Prototyper (被迫做语义理解 + 代码生成)
  ↓ 输出: fuzz_driver.cpp
```

**核心问题**：
- Function Analyzer只做**what**（函数需要什么precondition），不做**why**（为什么需要？目的是什么？）
- Prototyper接收文本规格，需要重新理解语义，效率低且容易丢失信息
- **缺失层**：没有"如何有效测试这个API"的建模

---

## 解决方案：分层建模

### 新架构：三层分析

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Function Analyzer (API Behavioral Model)          │
│ 职责：深度理解API的行为语义和测试策略                        │
├─────────────────────────────────────────────────────────────┤
│ 输出：结构化JSON规格 (不是纯文本！)                          │
│                                                             │
│ {                                                           │
│   "api_semantics": {                                        │
│     "purpose": "Parse Canon CR3 image format",              │
│     "category": "format_parser",                            │
│     "input_format": {                                       │
│       "type": "binary_format",                              │
│       "format_name": "CR3/CRX",                             │
│       "magic_bytes": "66 74 79 70 63 72 78 20",            │
│       "min_valid_size": 64,                                 │
│       "structure": "MP4/ISOBMFF container"                  │
│     }                                                       │
│   },                                                        │
│   "reachability": {                                         │
│     "direct_call": false,                                   │
│     "entry_points": ["LibRaw::open_buffer", "unpack"],      │
│     "trigger_condition": "Input must be valid CR3 file"     │
│   },                                                        │
│   "test_strategy": {                                        │
│     "approach": "format_aware_fuzzing",                     │
│     "input_construction": {                                 │
│       "base": "seed_corpus",                                │
│       "mutations": [                                        │
│         {                                                   │
│           "target": "track_metadata",                       │
│           "method": "bit_flip",                             │
│           "preserve": ["magic_bytes", "box_structure"]      │
│         }                                                   │
│       ]                                                     │
│     },                                                      │
│     "coverage_goals": [                                     │
│       "error_handling (invalid_track_num)",                 │
│       "boundary_cases (track_count=0, MAX)",                │
│       "format_variations (different_codec_settings)"        │
│     ]                                                       │
│   },                                                        │
│   "lifecycle": {                                            │
│     "archetype": "object_lifecycle",                        │
│     "sequence": [                                           │
│       {"step": 1, "call": "LibRaw::LibRaw()", ...},         │
│       {"step": 2, "call": "open_buffer(data, size)", ...},  │
│       {"step": 3, "call": "unpack()", ...},                 │
│       {"step": 4, "call": "~LibRaw()", ...}                 │
│     ]                                                       │
│   },                                                        │
│   ...                                                       │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Test Strategy Planner (NEW!)                      │
│ 职责：基于API语义，设计具体的测试方案                        │
├─────────────────────────────────────────────────────────────┤
│ 输入：api_semantics (JSON)                                  │
│ 输出：test_plan (JSON)                                      │
│                                                             │
│ {                                                           │
│   "harness_type": "format_aware_harness",                   │
│   "input_strategy": {                                       │
│     "use_seed_corpus": true,                                │
│     "corpus_source": "gs://libraw-corpus/cr3_samples/",     │
│     "mutation_zones": [                                     │
│       {                                                     │
│         "name": "track_metadata",                           │
│         "offset_range": [64, 512],                          │
│         "preserve_constraints": ["box_size_consistency"]    │
│       }                                                     │
│     ]                                                       │
│   },                                                        │
│   "execution_paths": [                                      │
│     {                                                       │
│       "name": "valid_parse_path",                           │
│       "setup": "Provide minimally valid CR3",               │
│       "goal": "Exercise normal parsing logic"               │
│     },                                                      │
│     {                                                       │
│       "name": "error_handling_path",                        │
│       "setup": "Corrupt track_num field",                   │
│       "goal": "Trigger bounds check and error return"       │
│     }                                                       │
│   ],                                                        │
│   "parameter_matrix": [                                     │
│     {"data": "SEED", "size": "EXACT"},                      │
│     {"data": "SEED+MUTATE", "size": "EXACT"},               │
│     {"data": "SEED", "size": "FUZZ(0, 2*original)"}         │
│   ]                                                         │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Prototyper (Code Generator)                       │
│ 职责：纯粹的代码生成，不做语义理解                           │
├─────────────────────────────────────────────────────────────┤
│ 输入：test_plan (JSON) + skeleton_template                 │
│ 输出：fuzz_driver.cpp                                       │
│                                                             │
│ // 根据test_plan直接生成代码                                │
│ extern "C" int LLVMFuzzerTestOneInput(...) {                │
│   // 从test_plan.input_strategy获取                         │
│   if (size < 64) return 0;  // min_valid_size              │
│                                                             │
│   FuzzedDataProvider fdp(data, size);                       │
│                                                             │
│   // 从test_plan.execution_paths生成多路径逻辑              │
│   uint8_t path = fdp.ConsumeIntegral<uint8_t>() % 2;        │
│   switch (path) {                                           │
│     case 0: /* valid_parse_path */ ...                     │
│     case 1: /* error_handling_path */ ...                  │
│   }                                                         │
│                                                             │
│   // 从test_plan.lifecycle.sequence生成调用序列             │
│   LibRaw raw;                                               │
│   raw.open_buffer(data, size);                              │
│   raw.unpack();                                             │
│   return 0;                                                 │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 详细设计

### Layer 1: Function Analyzer 重新设计

#### 新职责

不仅仅提取preconditions，而是要回答：

1. **API Semantics（语义建模）**
   - 函数的业务目的是什么？（parse? validate? encode? transform?）
   - 输入数据的格式要求？（binary format? text? structured?）
   - 与其他API的关系？（standalone? part of pipeline?）

2. **Reachability Analysis（可达性分析）**
   - 这个函数可以直接调用吗？（public API?）
   - 如果不能，通过什么路径触达？（entry points?）
   - 需要什么条件才能执行到？（state requirements?）

3. **Test Strategy（测试策略）**
   - 如何构造有效的测试输入？（random? seed-based? format-aware?）
   - 哪些执行路径值得探索？（error paths? boundary cases?）
   - 期望的coverage goals是什么？

4. **Format Understanding（格式理解）** - 新增！
   - 如果是format parser，识别格式规范
   - 提取magic bytes, 最小size, 结构约束
   - 查询是否有seed corpus可用

#### 新的分析流程

```python
# 当前：迭代分析call sites
for call_site in call_sites:
    extract_preconditions()
    extract_postconditions()
    extract_sequence()

# 新增：语义理解
def _execute_iterative_analysis():
    # Phase 1: Static Analysis（保持）
    initial_analysis = analyze_function_source()
    
    # Phase 2: Usage Pattern Mining（保持）
    for call_site in call_sites:
        extract_patterns()
    
    # Phase 3: Semantic Understanding（新增！）
    api_semantics = _analyze_api_semantics(
        function_source, call_sites, initial_analysis
    )
    # 输出：
    # - purpose: 业务目的
    # - category: format_parser | validator | transformer | ...
    # - input_format: 如果是parser，详细格式信息
    
    # Phase 4: Reachability Analysis（新增！）
    reachability = _analyze_reachability(
        function_signature, call_sites, project_name
    )
    # 输出：
    # - direct_call: bool
    # - entry_points: [public APIs that lead to this function]
    # - trigger_conditions: 需要什么样的input才能触达
    
    # Phase 5: Test Strategy Design（新增！）
    test_strategy = _design_test_strategy(
        api_semantics, reachability, call_sites
    )
    # 输出：
    # - approach: random_fuzzing | format_aware | seed_based | ...
    # - input_construction: 如何构造测试输入
    # - coverage_goals: 期望覆盖的路径
    
    # Phase 6: Generate Structured Spec（改进！）
    return {
        "api_semantics": api_semantics,
        "reachability": reachability,
        "test_strategy": test_strategy,
        "lifecycle": lifecycle,  # 保持
        "preconditions": preconditions,  # 保持
        "postconditions": postconditions  # 保持
    }
```

#### 新增Prompts

**`function_analyzer_semantics_prompt.txt`** (新增)
```
Based on the function analysis, determine:

## API Semantics

1. **Purpose Classification**
   - Primary purpose: [Format Parser | Validator | Encoder | Decoder | Transformer | Calculator | State Manager | ...]
   - Specific task: [1-2 sentences]

2. **Input Format Requirements**
   - Data type: [raw_bytes | text | structured_object | ...]
   - Format specification (if format parser):
     * Format name: [CR3 | PNG | JPEG | JSON | XML | ...]
     * Magic bytes: [hex sequence]
     * Minimum valid size: [bytes]
     * Structure: [describe container/encoding]
   - Constraints: [what makes input valid?]

3. **Relationship to Other APIs**
   - Standalone: [can be called directly? yes/no]
   - Part of pipeline: [which sequence?]
   - Dependencies: [requires what state/setup?]

Evidence: [cite call sites and source code]
```

**`function_analyzer_reachability_prompt.txt`** (新增)
```
Based on the call sites, determine how to reach this function:

## Reachability Analysis

1. **Direct Callable**
   - Is this a public API? [yes/no]
   - Evidence: [header file? export list?]

2. **Indirect Reachability** (if not directly callable)
   - Entry points: [which public APIs call this?]
   - Call chain: [API1 → API2 → target_function]
   - Trigger condition: [what input/state causes entry point to call this?]

3. **Fuzzing Implications**
   - How to construct harness: [direct call | via entry point]
   - Required setup: [state/context needed]
   - Input requirements: [what format drives execution to this function?]

Evidence: [cite specific call sites]
```

**`function_analyzer_test_strategy_prompt.txt`** (新增)
```
Design an effective test strategy for this function:

## Test Strategy

1. **Input Construction Approach**
   Given the API semantics and reachability:
   
   Choose ONE primary strategy:
   - [ ] Random Fuzzing: Fully random bytes
   - [ ] Format-Aware Fuzzing: Preserve structure, mutate payload
   - [ ] Seed-Based Fuzzing: Start from valid samples, apply mutations
   - [ ] Grammar-Based Fuzzing: Generate from format specification
   
   Justification: [why this approach?]

2. **Input Construction Details**
   - Minimum input size: [bytes]
   - Required structure: [magic bytes? headers? sections?]
   - Mutation zones: [which parts can fuzz? which must preserve?]
   - Seed corpus: [available? where? gs://...?]

3. **Execution Path Exploration**
   Identify key paths to explore:
   
   - Path 1: [normal/happy path]
     * Setup: [what input?]
     * Goal: [exercise which logic?]
   
   - Path 2: [error handling]
     * Setup: [what invalid input?]
     * Goal: [trigger which error check?]
   
   - Path 3: [boundary case]
     * Setup: [edge case input?]
     * Goal: [test which limit?]

4. **Coverage Goals**
   What should the fuzzer aim to cover?
   - [ ] Error handling paths
   - [ ] Boundary conditions
   - [ ] Format variations
   - [ ] State transitions
   - [ ] Resource limits

Evidence: [based on call site patterns and source code]
```

---

### Layer 2: Test Strategy Planner（新组件！）

**为什么需要这一层？**

Function Analyzer 输出的是**知识**（what/why），但Prototyper需要的是**指令**（how）。

Test Strategy Planner的职责：
- 输入：`api_semantics` (JSON from Function Analyzer)
- 输出：`test_plan` (JSON for Prototyper)
- 职责：将高层语义转换为具体的代码生成指令

#### 实现方式

**选项A：LLM-based Agent**（推荐）
```python
class LangGraphTestStrategyPlanner(LangGraphAgent):
    def execute(self, state):
        api_semantics = state["function_analysis"]["api_semantics"]
        
        # 根据semantics生成具体plan
        if api_semantics["category"] == "format_parser":
            plan = self._plan_format_aware_harness(api_semantics)
        elif api_semantics["category"] == "stateless_function":
            plan = self._plan_simple_harness(api_semantics)
        # ...
        
        return {"test_plan": plan}
```

**选项B：Rule-based Planner**（更简单，可先实现）
```python
def generate_test_plan(api_semantics):
    """根据API语义，使用规则生成测试计划"""
    
    # Rule 1: Format parser → format-aware harness
    if api_semantics["category"] == "format_parser":
        return {
            "harness_type": "format_aware",
            "input_strategy": {
                "use_seed_corpus": True,
                "mutation_zones": extract_mutation_zones(api_semantics),
                ...
            }
        }
    
    # Rule 2: Simple stateless → random fuzzing
    elif api_semantics["category"] == "stateless_function":
        return {
            "harness_type": "simple_random",
            "input_strategy": {
                "use_seed_corpus": False,
                "param_extraction": generate_param_extraction(api_semantics),
                ...
            }
        }
    
    # ...
```

---

### Layer 3: Prototyper 简化

**新职责：纯粹的代码生成器**

不再需要理解API语义，只需：
1. 读取 `test_plan` (JSON)
2. 选择对应的模板
3. 填充参数
4. 生成代码

**新的Prototyper Prompt**（极简化）：
```
Generate a fuzz driver based on the following test plan:

**Test Plan**:
{TEST_PLAN_JSON}

**Skeleton Template**:
{SKELETON_CODE}

**Task**: Fill in the skeleton following the test plan exactly:
1. Use input_strategy to generate input handling code
2. Use execution_paths to generate path exploration logic
3. Use lifecycle.sequence to generate API call sequence
4. Use preconditions/postconditions for error checks

**Rules**:
- Follow the test plan EXACTLY
- Use provided headers EXACTLY
- Ensure code compiles
```

---

## 实现路线图

### Phase 1: 增强Function Analyzer（1-2周）

**优先级：High**

1. **新增语义分析prompts**
   - `function_analyzer_semantics_prompt.txt`
   - `function_analyzer_reachability_prompt.txt`
   - `function_analyzer_test_strategy_prompt.txt`

2. **修改Function Analyzer逻辑**
   ```python
   def _execute_iterative_analysis():
       # 现有逻辑...
       initial_analysis = ...
       for call_site in call_sites:
           ...
       
       # 新增：语义理解
       semantics_prompt = build_prompt("function_analyzer_semantics", ...)
       api_semantics = self.chat_llm(state, semantics_prompt)
       api_semantics_json = parse_json(api_semantics)
       
       # 新增：可达性分析
       reachability_prompt = build_prompt("function_analyzer_reachability", ...)
       reachability = self.chat_llm(state, reachability_prompt)
       reachability_json = parse_json(reachability)
       
       # 新增：测试策略
       strategy_prompt = build_prompt("function_analyzer_test_strategy", ...)
       test_strategy = self.chat_llm(state, strategy_prompt)
       test_strategy_json = parse_json(test_strategy)
       
       # 返回结构化JSON，而非纯文本
       return {
           "api_semantics": api_semantics_json,
           "reachability": reachability_json,
           "test_strategy": test_strategy_json,
           "lifecycle": ...,  # 保持现有
           "preconditions": ...,  # 保持现有
           "postconditions": ...  # 保持现有
       }
   ```

3. **输出格式改进**
   - 当前：`function_analysis.txt` (纯文本)
   - 新增：`function_analysis.json` (结构化)
   - 保持：`function_analysis.txt` (兼容性，从JSON渲染)

### Phase 2: 实现Test Strategy Planner（1周）

**优先级：Medium**（可先用规则实现）

1. **创建新节点**
   ```python
   # agent_graph/nodes/test_strategy_planner_node.py
   def test_strategy_planner_node(state, config):
       api_semantics = state["function_analysis"]["api_semantics"]
       test_plan = generate_test_plan(api_semantics)  # 规则生成
       return {"test_plan": test_plan}
   ```

2. **更新workflow graph**
   ```python
   graph.add_node("test_strategy_planner", test_strategy_planner_node)
   graph.add_edge("function_analyzer", "test_strategy_planner")
   graph.add_edge("test_strategy_planner", "prototyper")
   ```

3. **规则库实现**
   ```python
   # agent_graph/test_strategy_rules.py
   STRATEGY_RULES = {
       "format_parser": {...},
       "stateless_function": {...},
       "object_lifecycle": {...},
       ...
   }
   ```

### Phase 3: 简化Prototyper（3天）

**优先级：Medium**

1. **修改Prototyper Prompt**
   - 移除"effective fuzzing"指导（已在test_plan中）
   - 改为"follow test_plan exactly"

2. **Prototyper接收test_plan**
   ```python
   def prototyper_node(state, config):
       test_plan = state["test_plan"]
       skeleton = select_template(test_plan["harness_type"])
       
       prompt = f"""
       Generate code following this test plan:
       {json.dumps(test_plan, indent=2)}
       
       Use this skeleton:
       {skeleton}
       """
       
       code = llm.generate(prompt)
       return {"fuzz_target_source": code}
   ```

### Phase 4: 集成FuzzIntrospector增强（2周）

**优先级：Medium**（提升质量）

1. **查询seed corpus**
   ```python
   # 在Function Analyzer中
   def _query_seed_corpus(project_name, function_name):
       # 查询OSS-Fuzz corpus bucket
       corpus_path = f"gs://{project_name}-corpus/{function_name}/"
       samples = list_corpus_files(corpus_path)
       
       if samples:
           # 下载一个sample分析
           sample = download_sample(samples[0])
           magic_bytes = extract_magic_bytes(sample)
           min_size = len(sample)
           return {
               "corpus_available": True,
               "corpus_path": corpus_path,
               "magic_bytes": magic_bytes,
               "min_size": min_size
           }
       return {"corpus_available": False}
   ```

2. **格式识别**
   ```python
   def _identify_format(function_name, source_code):
       # 基于函数名和源码推断格式
       if "CR3" in function_name or "crx" in source_code.lower():
           return {
               "format": "CR3/CRX",
               "container": "MP4/ISOBMFF",
               "magic_bytes": "66 74 79 70 63 72 78 20"
           }
       # ... 其他格式
   ```

---

## 预期效果

### Before（当前）

```
Function Analyzer:
  输出: "Function needs non-null buffer, size > 0"
  
Prototyper（困惑）:
  "好吧，我就传随机data吧... 但怎么测试才有效？不知道..."
  
Result:
  - Coverage diff: 0.03%
  - 因为random bytes无法触达format-specific code
```

### After（优化后）

```
Function Analyzer:
  输出: {
    "api_semantics": {
      "purpose": "Parse CR3 format",
      "category": "format_parser",
      "input_format": {
        "format": "CR3/CRX",
        "magic_bytes": "66 74 79 70 63 72 78 20",
        "min_valid_size": 64
      }
    },
    "test_strategy": {
      "approach": "format_aware_fuzzing",
      "use_seed_corpus": true,
      "corpus_path": "gs://libraw-corpus/cr3/"
    }
  }

Test Strategy Planner:
  输出: {
    "harness_type": "format_aware_harness",
    "input_strategy": {
      "base": "seed_from_corpus",
      "mutations": [
        {"zone": "track_metadata", "method": "bit_flip"},
        {"zone": "codec_params", "method": "value_mutation"}
      ]
    }
  }

Prototyper（清晰）:
  "明白了！我要生成一个从corpus加载seed，然后mutate特定区域的harness"
  
Result:
  - Coverage diff: 5-10%
  - 因为有效的CR3 input能触达实际解析逻辑
```

---

## 关键洞察

### 为什么这个重新设计重要？

1. **职责清晰化**
   - Function Analyzer → **语义建模专家**（what/why）
   - Test Strategy Planner → **测试设计专家**（how - high level）
   - Prototyper → **代码生成专家**（how - implementation）

2. **信息不丢失**
   - 当前：语义 → 文本 → 重新解读（信息丢失！）
   - 新架构：语义 → JSON → 直接使用（精确传递）

3. **可扩展性**
   - 新增格式支持：只需扩展规则库
   - 新增策略：只需添加新的test plan模板
   - 不影响其他层

4. **可测试性**
   - 每层输出都是结构化JSON，可以单元测试
   - 可以mock中间结果，独立测试每一层

---

## 立即可做的Quick Win

**不需要完整重构，可以先做这些：**

### Quick Win 1: 增强Function Analyzer输出格式（1天）

```python
# 在current function_analyzer_final_summary_prompt.txt最后加一段：

## 9. Format-Specific Analysis (if applicable)

If this function is a format parser/decoder:

**Format Identification**:
- Format name: [CR3 | PNG | JPEG | JSON | XML | custom]
- Evidence: [function name? source code patterns?]

**Format Requirements**:
- Magic bytes: [hex sequence if identifiable]
- Minimum valid size: [bytes]
- Structure: [flat | hierarchical | container-based]

**Fuzzing Recommendation**:
- [ ] Random fuzzing suitable (simple format)
- [ ] Format-aware fuzzing needed (complex structure)
- [ ] Seed corpus recommended (format-specific)

If format-aware fuzzing needed:
- Corpus availability: [check gs://{project}-corpus/]
- Mutation strategy: [preserve structure | mutate payload | both]
```

### Quick Win 2: Prototyper使用格式信息（2天）

```python
# 修改prototyper_prompt.txt，在开头加：

{FORMAT_GUIDANCE}  # 从function_analysis提取

# 如果有格式信息：
**Format-Specific Guidance**:
This function parses {FORMAT_NAME} format.
- Magic bytes: {MAGIC_BYTES}
- Minimum size: {MIN_SIZE}
- Recommendation: {FUZZING_RECOMMENDATION}

**Implication for your harness**:
- Add minimum size check: if (size < {MIN_SIZE}) return 0;
- Consider preserving magic bytes if using mutations
- If seed corpus available, use custom mutator (see FUZZING_BEST_PRACTICES.md)
```

### Quick Win 3: 添加格式检测helper（半天）

```python
# agent_graph/utils/format_detector.py

KNOWN_FORMATS = {
    "CR3": {
        "patterns": ["CR3", "crx", "canon"],
        "magic_bytes": "66 74 79 70 63 72 78 20",
        "min_size": 64,
        "recommendation": "format_aware_fuzzing"
    },
    "PNG": {
        "patterns": ["PNG", "png"],
        "magic_bytes": "89 50 4E 47",
        "min_size": 33,
        "recommendation": "format_aware_fuzzing"
    },
    # ...
}

def detect_format(function_name, source_code):
    """检测函数处理的格式"""
    for format_name, info in KNOWN_FORMATS.items():
        for pattern in info["patterns"]:
            if pattern in function_name or pattern in source_code:
                return {
                    "format": format_name,
                    **info
                }
    return None
```

这些Quick Wins可以立即提升libraw类型项目的coverage！

---

## 总结

**核心思想**：
- **分离关注点**：语义理解 vs 测试设计 vs 代码生成
- **结构化传递**：JSON而非文本，精确传递信息
- **深度建模**：不仅是"what"，还要"why"和"how"

**预期收益**：
- Coverage diff: 0.03% → 5-10%（对format parsers）
- 代码质量：更清晰的分层，更易维护
- 可扩展性：新增格式/策略只需扩展规则库

**实施建议**：
1. 先实现Quick Wins（3天），立即看到效果
2. 再逐步实现完整重构（4-6周）

