# Memory Architecture

LogicFuzz 使用三层记忆系统：

| 类型 | 生命周期 | 作用域 | 用途 |
|------|---------|--------|------|
| **Long-term** | 永久 | 全局 | API模式、代码模板、常见错误 |
| **Session** | 单次运行 | 任务级 | API约束、修复记录、决策日志 |
| **Messages** | 单次运行 | Agent级 | LLM对话历史 |

---

## 1. Long-term Memory

**存储位置**: `long_term_memory/`

### 内容结构

```
archetypes/         # 10种API模式
├── stateless_parser.md
├── object_lifecycle.md
├── state_machine.md
├── stream_processor.md
├── round_trip.md
└── file_based.md

skeletons/          # 对应代码模板
pitfalls/           # 4类常见错误
```

### API使用

```python
from long_term_memory.retrieval import KnowledgeRetriever

retriever = KnowledgeRetriever()

# 获取bundle (archetype + skeleton + pitfalls)
bundle = retriever.get_archetype_bundle("stateless_parser")

# 单独获取
archetype = retriever.get_archetype("stateless_parser")
skeleton = retriever.get_skeleton("stateless_parser")
pitfalls = retriever.get_pitfalls_for_archetype("stateless_parser")
```

**调用者**: Function Analyzer (读archetype), Prototyper (读skeleton)

---

## 2. Session Memory

**存储**: `AgentGraphState.session_memory` (字典)

### 数据结构

```python
{
    "api_constraints": [
        {
            "type": "api_constraint",
            "content": "必须先调用 init() 再调用 decode()",
            "confidence": "HIGH",
            "source": "function_analyzer",
            "timestamp": "2024-01-01T12:00:00"
        }
    ],
    "archetype": {
        "identified_archetype": "stateful_decoder",
        "confidence": "HIGH",
        "reasoning": "API需要初始化状态"
    },
    "known_fixes": [...],
    "decisions": [...],
    "coverage_strategies": [...]
}
```

### 五大类别

| 类别 | 写入者 | 内容 | 示例 |
|------|--------|------|------|
| `api_constraints` | Function Analyzer | API调用约束 | "必须初始化才能调用" |
| `archetype` | Function Analyzer | 识别的API模式 | "stateful_decoder" |
| `known_fixes` | Enhancer | 错误修复方案 | "添加NULL检查" |
| `decisions` | Supervisor | 路由决策原因 | "检测到编译错误→Enhancer" |
| `coverage_strategies` | Coverage Analyzer | 覆盖率优化建议 | "添加边界测试" |

### 核心API

```python
# agent_graph/state.py
def add_api_constraint(state, constraint, confidence, source)
def set_archetype(state, archetype, confidence, reasoning)
def add_known_fix(state, fix_description, success, confidence)
def add_decision(state, decision_type, reasoning)
def add_coverage_strategy(state, strategy)
def format_session_memory(state)  # 转为文本注入prompt
def consolidate_session_memory(state)  # 去重清理
```

### 注入机制

每个Agent执行前，`format_session_memory()` 将相关记忆注入prompt：

```python
# agents/base_agent.py
def build_full_prompt(self, state):
    base_prompt = self.load_prompt()
    session_context = format_session_memory(state)
    return f"{base_prompt}\n\n{session_context}"
```

**Token优化**: 只注入与当前Agent相关的类别（如Enhancer注入`known_fixes`）

---

## 3. Agent Message History

**存储**: `AgentGraphState.agent_messages` (字典)

```python
{
    "function_analyzer": [
        {"role": "system", "content": "..."},
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "..."}
    ],
    "enhancer": [...]
}
```

### Token管理

```python
# agent_graph/memory.py
def trim_messages_to_limit(messages, model, max_tokens=100000):
    """保留最近的消息，丢弃过早的对话"""
    while count_tokens(messages, model) > max_tokens:
        messages.pop(1)  # 保留system message (index 0)
    return messages
```

### Reducer机制 (LangGraph)

```python
# agent_graph/state.py
class AgentGraphState(TypedDict):
    agent_messages: Annotated[dict, merge_agent_messages]

def merge_agent_messages(old, new):
    """每次Agent返回新消息时自动合并"""
    merged = old.copy()
    for agent_name, new_msgs in new.items():
        merged.setdefault(agent_name, []).extend(new_msgs)
    return merged
```

---

## 4. Memory工作流

### Phase 1 (Compilation)

```
Function Analyzer
  ↓ 写入 api_constraints, archetype
Prototyper (读取 archetype)
  ↓
Build → Execution → Enhancer (读取 known_fixes)
  ↓ 写入 known_fixes
Supervisor (consolidate session_memory)
```

### Phase 2 (Optimization)

```
Crash Analyzer
  ↓ 分析crash类型
Crash Feasibility Analyzer
  ↓ 写入 decisions (真实bug/误报)
Coverage Analyzer
  ↓ 写入 coverage_strategies
Enhancer (读取 coverage_strategies + known_fixes)
```

---

## 5. 关键实现

### State定义

```python
# agent_graph/state.py
class AgentGraphState(TypedDict):
    session_memory: dict                                    # Session Memory
    agent_messages: Annotated[dict, merge_agent_messages]   # Message History
    long_term_retriever: KnowledgeRetriever                 # Long-term Memory接口
```

### Session Memory注入器

```python
# agent_graph/session_memory_injector.py
def inject_session_memory_for_agent(agent_name, state):
    relevant_memory = filter_memory_by_agent(agent_name, state.session_memory)
    return format_as_prompt_section(relevant_memory)
```

### Supervisor清理

```python
# nodes/supervisor_node.py
def supervisor_node(state):
    # 每3次迭代清理一次
    if state["iteration_count"] % 3 == 0:
        state = consolidate_session_memory(state)
    return state
```

---

## 6. 设计优势

1. **职责分离**: Long-term(静态知识) vs Session(动态共识) vs Messages(对话)
2. **跨Agent共享**: Session Memory让所有Agent访问共同约束
3. **Token高效**: 智能过滤 + 自动trim，避免上下文爆炸
4. **类型安全**: TypedDict + Annotated确保数据一致性

---

## 7. 关键指标

- **Long-term Memory大小**: ~10 archetypes × 200行 = 2000行代码模板
- **Session Memory平均大小**: 5-15条约束/修复 (< 2K tokens)
- **Message History上限**: 100K tokens (自动trim)
- **Consolidate频率**: 每3次迭代清理一次重复
