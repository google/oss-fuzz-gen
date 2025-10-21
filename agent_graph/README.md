# Agent Graph - LangGraph Implementation

## 概述

这是fuzzing工作流的LangGraph实现，使用**agent-specific messages**架构。

## 核心设计

### Agent-Specific Messages

每个agent维护独立的对话历史：

```python
state["agent_messages"] = {
    "function_analyzer": [消息列表],
    "prototyper": [消息列表],
    "enhancer": [消息列表],
    "crash_analyzer": [消息列表]
}
```

### 结构化数据共享

Agents通过state字段传递信息：

```python
state["function_analysis"] = {...}  # FunctionAnalyzer → Prototyper
state["fuzz_target_source"] = "..."  # Prototyper → Build
state["build_errors"] = [...]        # Build → Enhancer
state["crash_info"] = {...}          # Execution → CrashAnalyzer
```

## 目录结构

```
agent_graph/
├── README.md                    # 本文件
├── state.py                     # State定义
├── memory.py                    # 消息管理和token控制
├── workflow.py                  # Workflow构建
├── agents/
│   ├── langgraph_agent.py      # LangGraph agent基类（推荐使用）
│   ├── base_agent.py           # ADK agent基类（兼容性）
│   └── ...                     # 其他agent实现
└── nodes/
    ├── function_analyzer_node.py  # 函数分析（使用agent-specific messages）
    ├── prototyper_node.py         # 代码生成（使用agent-specific messages）
    ├── enhancer_node.py           # 代码增强（使用agent-specific messages）
    ├── crash_analyzer_node.py    # crash分析（使用agent-specific messages）
    ├── execution_node.py          # 编译和执行（不需要LLM）
    └── supervisor_node.py         # 路由器（不需要LLM）
```

## 快速开始

### 1. 运行测试

```bash
python3 test_agent_messages.py
```

### 2. 创建workflow

```python
from agent_graph import FuzzingWorkflow
from llm_toolkit.models import LLM

# 创建workflow
llm = LLM.setup(...)
workflow = FuzzingWorkflow(llm, args)

# 运行
result = workflow.run(benchmark, trial=0)
```

### 3. 添加新Agent

```python
# 1. 在agents/langgraph_agent.py中定义
class LangGraphNewAgent(LangGraphAgent):
    def __init__(self, llm, trial, args):
        super().__init__(
            name="new_agent",
            llm=llm,
            trial=trial,
            args=args,
            system_message="You are..."
        )
    
    def execute(self, state):
        # 从state获取数据
        data = state.get("field", {})
        
        # 构建prompt（不要从其他agent的messages获取！）
        prompt = f"Do something with {data}"
        
        # Chat（自动使用new_agent的messages）
        response = self.chat_llm(state, prompt)
        
        # 返回结构化数据
        return {"new_field": response}

# 2. 创建node
def new_agent_node(state, config):
    agent = LangGraphNewAgent(
        llm=config["configurable"]["llm"],
        trial=state["trial"],
        args=config["configurable"]["args"]
    )
    return agent.execute(state)

# 3. 在workflow.py中添加
workflow.add_node("new_agent", new_agent_node)
```

## 优势

✅ **节省Token**: 每个agent只看自己的对话，节省50%+ tokens
✅ **自动Trim**: 每个agent自动trim到50k tokens
✅ **清晰架构**: 对话隔离，数据共享
✅ **易维护**: 添加新agent很简单
✅ **兼容性**: 完美配合Supervisor架构

## 注意事项

### ✅ 正确做法

```python
# 从结构化数据构建prompt
function_analysis = state.get("function_analysis", {})
prompt = f"Summary: {function_analysis.get('summary', '')}"
```

### ❌ 错误做法

```python
# 不要从其他agent的messages获取信息！
fa_messages = state["agent_messages"]["function_analyzer"]
prompt = f"Previous: {fa_messages[-1]['content']}"
```

## 相关文档

- `REFACTORING_SUMMARY.md` - 详细的重构总结
- `test_agent_messages.py` - 功能测试
- `LANGGRAPH_DESIGN.md` - Supervisor架构设计

