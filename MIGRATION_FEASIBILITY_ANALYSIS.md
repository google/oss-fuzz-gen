# Automata 方法迁移可行性分析

本文档分析将 `source/` 文件夹下的 automata 建立方法迁移到当前 logicfuzz 系统的可行性。

## 一、当前系统 vs Automata 方法对比

### 1.1 当前 LogicFuzz 架构

**核心特点：**
- **基于 LLM 的多智能体系统**：使用 LangGraph 协调多个专门化的 agent
- **启发式 + FuzzIntrospector**：通过命名规则和 FuzzIntrospector API 分析依赖
- **线性调用序列**：生成简单的 prerequisites → target → cleanup 序列
- **动态生成**：每次运行时由 LLM 生成代码

**API 依赖分析方式：**
```python
# agent_graph/api_dependency_analyzer.py
- 启发式规则识别 init/create/new 函数
- 基于类型匹配查找生产者函数
- 拓扑排序生成调用序列
- 生成初始化代码模板
```

**输出格式：**
```python
{
    'prerequisites': ['ctx_init', 'ctx_create'],
    'data_dependencies': [('ctx_create', 'target')],
    'call_sequence': ['ctx_create', 'ctx_init', 'target'],
    'initialization_code': ['MyCtx* ctx;', 'ctx_create(&ctx);']
}
```

### 1.2 Source 文件夹的 Automata 方法

**核心特点：**
- **静态分析提取**：使用 Soot 从 Java 代码中提取 Usage Graph
- **Automata 表示**：转换为 NFA（包含条件分支、循环、epsilon 转换）
- **被动学习**：使用 RPNI 算法从正负样本学习
- **结构化表示**：生成 JSON/DOT 格式的 automata

**提取流程：**
```
Java 代码 → Soot 分析 → Usage Graph → NFA Automata → 学习优化 → 生成 Driver
```

**输出格式：**
```json
{
  "name": "automata_name",
  "initial": ["0"],
  "states": ["0", "1", "2"],
  "alphabets": [
    {"type": "call", "func": "ctx_create"},
    {"type": "cond", "cond": "ctx != NULL"},
    {"type": "call", "func": "target"}
  ],
  "map": {
    "0": {"1": {"type": "call", "func": "ctx_create"}},
    "1": {"2": {"type": "cond", "cond": "ctx != NULL"}}
  }
}
```

## 二、迁移可行性评估

### 2.1 ✅ 高度可行的部分

#### 1. **Automata 数据结构**
- **可行性**：✅ 高
- **原因**：Python 已有成熟的 automata 库（如 `automata-lib`、`AALpy`）
- **迁移难度**：低
- **实现方式**：
  ```python
  # 可以创建 Python 版本的 iAutomata
  class Automata:
      def __init__(self, name: str):
          self.name = name
          self.states: Set[str] = set()
          self.initial_states: Set[str] = set()
          self.transitions: Dict[str, Dict[str, Event]] = {}
          self.alphabet: Set[Event] = set()
  ```

#### 2. **事件类型系统**
- **可行性**：✅ 高
- **原因**：事件类型（API 调用、条件、epsilon）可以轻松映射到 Python
- **迁移难度**：低
- **实现方式**：
  ```python
  class Event(ABC):
      pass
      
  class CallAPIEvent(Event):
      def __init__(self, func_sig: str):
          self.func_sig = func_sig
          
  class ConstraintEvent(Event):
      def __init__(self, condition: str):
          self.condition = condition
          
  class EpsilonEvent(Event):
      pass
  ```

#### 3. **被动学习（RPNI）**
- **可行性**：✅ 高
- **原因**：已有 Python 实现（AALpy、LearnLib Python 绑定）
- **迁移难度**：中
- **实现方式**：
  ```python
  from aalpy.learning_algorithms import run_RPNI
  # 或使用 learnlib 的 Python 接口
  ```

#### 4. **Automata 合并和统一**
- **可行性**：✅ 高
- **原因**：Python 的 `libautomata.py` 已经实现了大部分逻辑
- **迁移难度**：低
- **实现方式**：直接复用 `source/automata/libautomata.py`

### 2.2 ⚠️ 需要适配的部分

#### 1. **静态分析工具替换**
- **当前**：Soot（Java 静态分析）
- **目标**：C/C++ 代码分析
- **可行性**：⚠️ 中
- **挑战**：
  - Soot 是 Java 专用，不能直接用于 C/C++
  - 需要找到 C/C++ 的等价工具
- **解决方案**：
  - **选项 A**：使用 Clang AST + 自定义分析器
    - 优点：精确，支持复杂分析
    - 缺点：实现复杂，需要处理 C/C++ 的各种特性
  - **选项 B**：使用现有工具（tree-sitter + FuzzIntrospector）
    - 优点：已有基础设施
    - 缺点：可能不如 Soot 精确
  - **选项 C**：从现有 fuzzer 中提取（推荐）
    - 优点：利用真实使用示例，质量高
    - 缺点：需要解析 C 代码

#### 2. **Usage Graph 提取**
- **当前**：从 Java 代码的 interprocedural CFG 提取
- **目标**：从 C/C++ 代码或现有 fuzzer 提取
- **可行性**：⚠️ 中
- **实现策略**：
  ```python
  # 策略 1: 从现有 fuzzer 提取
  def extract_from_fuzzer(fuzzer_code: str) -> Automata:
      # 解析 C 代码（使用 tree-sitter 或 Clang）
      # 识别 API 调用序列
      # 识别条件分支
      # 构建 automata
      pass
      
  # 策略 2: 从 FuzzIntrospector 的调用图提取
  def extract_from_call_graph(project: str, func: str) -> Automata:
      # 使用 FuzzIntrospector 的 call graph
      # 转换为 automata
      pass
  ```

#### 3. **条件约束处理**
- **当前**：使用 Z3 简化 Java 条件表达式
- **目标**：处理 C/C++ 条件表达式
- **可行性**：✅ 高
- **原因**：Z3 支持 C/C++ 表达式
- **迁移难度**：低
- **注意**：需要适配 C/C++ 的类型系统（指针、结构体等）

### 2.3 ❌ 困难或不可行的部分

#### 1. **直接复用 Java 代码**
- **可行性**：❌ 低
- **原因**：Soot 是 Java 专用，不能分析 C/C++
- **解决方案**：需要重写提取逻辑，但可以复用概念和算法

#### 2. **完全相同的提取精度**
- **可行性**：⚠️ 中
- **原因**：C/C++ 的复杂性（指针、宏、模板等）可能影响分析精度
- **解决方案**：采用混合方法（静态分析 + 动态学习）

## 三、迁移方案设计

### 3.1 方案 A：渐进式迁移（推荐）

**阶段 1：数据结构迁移**
- 在 Python 中实现 automata 数据结构
- 实现事件类型系统
- 实现基本的 automata 操作（合并、统一字母表等）

**阶段 2：提取逻辑适配**
- 从现有 fuzzer 中提取 API 调用序列
- 使用 tree-sitter 或 Clang 解析 C 代码
- 构建简单的 usage graph

**阶段 3：学习算法集成**
- 集成 RPNI 或其他被动学习算法
- 从正负样本学习 automata

**阶段 4：与现有系统集成**
- 将 automata 作为额外的上下文注入到 LLM
- 或作为验证工具检查 LLM 生成的代码

### 3.2 方案 B：混合方法

**核心思想**：结合两种方法的优势

```
当前 LLM 方法（生成代码）
    ↓
Automata 验证（检查调用序列是否正确）
    ↓
如果不符合 automata → 反馈给 LLM 修正
```

**实现方式：**
1. 使用当前方法生成初始代码
2. 从生成的代码中提取 automata
3. 使用被动学习优化 automata
4. 用优化后的 automata 验证后续生成

### 3.3 方案 C：完全替换

**核心思想**：用 automata 方法完全替换当前的启发式方法

**优点**：
- 更结构化的 API 依赖表示
- 支持条件分支和循环
- 可以通过学习不断改进

**缺点**：
- 需要大量重写
- 失去 LLM 的灵活性
- 可能影响当前系统的稳定性

## 四、具体迁移步骤（推荐方案 A）

### 步骤 1：创建 Python Automata 库

```python
# agent_graph/automata/automata.py
class Automata:
    """Python 版本的 iAutomata"""
    def __init__(self, name: str):
        self.name = name
        self.states: Set[str] = set()
        self.initial_states: Set[str] = set()
        self.final_states: Set[str] = set()  # 所有状态默认都是 final
        self.transitions: Dict[str, Dict[str, Event]] = {}
        self.alphabet: Set[Event] = set()
    
    def add_state(self, state: str):
        self.states.add(state)
        self.final_states.add(state)  # NFA 特性
    
    def add_initial_state(self, state: str):
        self.add_state(state)
        self.initial_states.add(state)
    
    def add_transition(self, from_state: str, to_state: str, event: Event):
        if from_state not in self.transitions:
            self.transitions[from_state] = {}
        self.transitions[from_state][to_state] = event
        self.alphabet.add(event)
```

### 步骤 2：从现有 Fuzzer 提取 Automata

```python
# agent_graph/automata/extractor.py
class AutomataExtractor:
    """从 C 代码或现有 fuzzer 提取 automata"""
    
    def extract_from_fuzzer(self, fuzzer_code: str) -> Automata:
        """从 fuzzer 代码中提取 API 调用序列"""
        # 使用 tree-sitter 解析 C 代码
        # 识别函数调用
        # 识别条件分支
        # 构建 automata
        pass
    
    def extract_from_call_graph(self, project: str, func: str) -> Automata:
        """从 FuzzIntrospector 的调用图提取"""
        # 查询 FuzzIntrospector
        # 构建调用图
        # 转换为 automata
        pass
```

### 步骤 3：集成到现有工作流

```python
# agent_graph/data_context.py (修改)
class FuzzingContext:
    @classmethod
    def prepare(cls, project_name: str, function_signature: str):
        context = cls()
        # ... 现有代码 ...
        
        # 新增：提取 automata
        from agent_graph.automata.extractor import AutomataExtractor
        extractor = AutomataExtractor(project_name)
        context.api_automata = extractor.extract_from_call_graph(
            project_name, function_signature
        )
        
        return context
```

### 步骤 4：在 Prototyper 中使用 Automata

```python
# agent_graph/agents/prototyper.py (修改)
class LangGraphPrototyper(LangGraphAgent):
    def _format_automata_context(self, state: FuzzingWorkflowState) -> str:
        """将 automata 格式化为 prompt 上下文"""
        automata = state.context.api_automata
        if not automata:
            return ""
        
        # 转换为文本描述
        lines = ["## API Usage Automata\n"]
        lines.append(f"Automata: {automata.name}")
        lines.append(f"States: {len(automata.states)}")
        lines.append(f"Alphabet: {len(automata.alphabet)} events")
        
        # 生成调用序列示例
        sequences = self._generate_sequences_from_automata(automata)
        lines.append("\n### Valid Call Sequences:")
        for seq in sequences[:5]:  # 只显示前 5 个
            lines.append(f"- {' → '.join(seq)}")
        
        return "\n".join(lines)
```

### 步骤 5：添加被动学习支持

```python
# agent_graph/automata/learning.py
class AutomataLearner:
    """使用被动学习优化 automata"""
    
    def learn_from_samples(
        self,
        positive_samples: List[List[str]],  # 正样本：有效的调用序列
        negative_samples: List[List[str]]   # 负样本：无效的调用序列
    ) -> Automata:
        """使用 RPNI 算法学习"""
        from aalpy.learning_algorithms import run_RPNI
        
        # 转换为 AALpy 格式
        # 运行 RPNI
        # 转换回我们的 Automata 格式
        pass
```

## 五、迁移的收益和风险

### 5.1 收益

1. **更结构化的 API 依赖表示**
   - 支持条件分支和循环
   - 可以表示复杂的调用模式

2. **可学习性**
   - 从正负样本中学习
   - 不断改进 automata 质量

3. **可验证性**
   - 可以验证生成的代码是否符合 automata
   - 发现不正确的调用序列

4. **可复用性**
   - Automata 可以在不同项目间复用
   - 建立 API 使用模式库

### 5.2 风险

1. **实现复杂度**
   - 需要重写提取逻辑
   - 需要处理 C/C++ 的复杂性

2. **性能影响**
   - 静态分析可能较慢
   - 学习算法需要额外时间

3. **维护成本**
   - 需要维护两套系统（当前方法 + automata）
   - 需要处理兼容性问题

4. **精度问题**
   - C/C++ 的复杂性可能影响分析精度
   - 可能需要人工验证

## 六、推荐策略

### 6.1 短期（1-2 个月）

1. **实现基础数据结构**
   - 创建 Python 版本的 Automata 类
   - 实现基本操作（合并、统一等）

2. **从现有 fuzzer 提取**
   - 解析 OSS-Fuzz 中的现有 fuzzer
   - 提取 API 调用序列
   - 构建简单的 automata

3. **作为辅助工具**
   - 将 automata 作为额外的上下文注入 LLM
   - 不替换现有方法，而是增强

### 6.2 中期（3-6 个月）

1. **完善提取逻辑**
   - 支持条件分支提取
   - 支持循环识别
   - 使用 Clang 进行更精确的分析

2. **集成学习算法**
   - 实现 RPNI 或其他被动学习
   - 从正负样本中学习

3. **建立 Automata 库**
   - 为常见 API 建立 automata 库
   - 支持跨项目复用

### 6.3 长期（6-12 个月）

1. **完全集成**
   - 将 automata 作为主要依赖分析方法
   - LLM 作为补充和优化

2. **主动学习**
   - 实现 L* 算法
   - 支持交互式学习

3. **自动化优化**
   - 自动从 fuzzing 结果中提取正负样本
   - 持续改进 automata

## 七、结论

### 7.1 迁移可行性：✅ **可行，但需要渐进式迁移**

**关键点：**
1. ✅ 数据结构和算法可以迁移
2. ⚠️ 静态分析工具需要替换（Soot → Clang/tree-sitter）
3. ✅ 学习算法有 Python 实现可用
4. ⚠️ 需要适配 C/C++ 的特性

### 7.2 推荐方案

**采用方案 A（渐进式迁移）+ 方案 B（混合方法）**

1. **第一阶段**：实现基础数据结构，从现有 fuzzer 提取简单 automata
2. **第二阶段**：将 automata 作为 LLM 的辅助上下文
3. **第三阶段**：完善提取逻辑，集成学习算法
4. **第四阶段**：逐步将 automata 作为主要方法，LLM 作为优化

### 7.3 成功关键因素

1. **保持向后兼容**：不破坏现有功能
2. **渐进式迁移**：分阶段实施，每阶段都有价值
3. **充分利用现有基础设施**：FuzzIntrospector、tree-sitter 等
4. **验证和测试**：确保 automata 质量

### 7.4 预期效果

- **短期**：提高 API 依赖分析的准确性
- **中期**：建立可复用的 API 使用模式库
- **长期**：实现完全自动化的 API 依赖学习和优化

---

**建议下一步行动：**
1. 创建 `agent_graph/automata/` 目录结构
2. 实现基础的 `Automata` 类
3. 实现从现有 fuzzer 提取的简单版本
4. 在 Prototyper 中作为辅助上下文集成
5. 评估效果，决定是否继续深入

