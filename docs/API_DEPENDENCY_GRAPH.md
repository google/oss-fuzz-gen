# API 依赖图系统

基于 **tree-sitter** 和 **FuzzIntrospector** 分析 API 调用依赖，生成正确的函数调用序列。

---

## 核心功能

1. **前置依赖识别**: 识别初始化函数 (`*_init`, `*_create`, `*_new`, `*_alloc`, `*_open`)
2. **数据流依赖**: 追踪参数的生产者-消费者关系
3. **调用序列生成**: 拓扑排序生成正确的调用顺序
4. **初始化模板**: 自动生成变量声明和初始化代码

---

## 架构

```
Function Analyzer
    ↓
APIDependencyAnalyzer
    ├─ tree-sitter (解析头文件)
    └─ FuzzIntrospector (验证函数/类型)
    ↓
NetworkX DiGraph (依赖图)
    ↓
拓扑排序 → 调用序列
    ↓
Prototyper (注入SRS规范)
```

---

## 核心类

### APIDependencyAnalyzer

```python
class APIDependencyAnalyzer:
    def analyze(self, target_function_name, header_file_content):
        """返回依赖图和调用序列"""
        return {
            "target_function": "decode",
            "prerequisite_functions": ["ctx_init", "ctx_create"],
            "calling_sequence": ["ctx_create", "ctx_init", "decode"],
            "dependency_graph_edges": [
                {"from": "decode", "to": "ctx_init", "reason": "data_flow"}
            ],
            "initialization_code": "MyCtx* ctx = ctx_create(); ctx_init(ctx);"
        }
```

### 关键方法

| 方法 | 职责 |
|------|------|
| `_find_prerequisite_functions` | 启发式识别初始化函数 |
| `_analyze_data_dependencies` | 分析参数类型依赖 |
| `_build_dependency_graph` | 构建NetworkX图 |
| `_generate_calling_sequence` | 拓扑排序生成序列 |
| `_generate_initialization_code` | 生成初始化模板 |

---

## 识别规则

### 前置依赖启发式

```python
INIT_FUNCTION_PATTERNS = [
    r'.*_init$', r'.*_create$', r'.*_new$',
    r'.*_alloc$', r'.*_open$', r'.*_setup$'
]
```

**条件**:
1. 函数名匹配模式
2. 返回值/参数类型与目标函数相关
3. FuzzIntrospector验证存在性

### 数据流依赖

```python
# 例子: decode(MyCtx* ctx)
#      ctx_create() -> MyCtx*
# 结论: decode 依赖 ctx_create (数据流)
```

---

## 输出格式

### 注入到SRS规范

```python
# agents/prototyper.py
def _format_srs_specification(self, state):
    srs = base_srs
    
    if has_api_dependency:
        srs += f"""
## API调用依赖

**调用序列**: {sequence}
**初始化代码**:
```c
{init_code}
```
"""
    return srs
```

### 示例输出

```yaml
calling_sequence:
  - ctx_create
  - ctx_init  
  - decode

initialization_code: |
  MyCtx* ctx = ctx_create();
  if (ctx) {
      ctx_init(ctx);
  }
```

---

## 集成点

### Function Analyzer → Prototyper

```python
# nodes/function_analyzer_node.py
analyzer = APIDependencyAnalyzer(...)
result = analyzer.analyze(target_func, header_content)
state["api_dependency"] = result  # 存入state

# agents/prototyper.py
def generate(..., state):
    srs = self._format_srs_specification(state)
    # api_dependency注入到SRS
```

---

## 使用的FuzzIntrospector API

| API | 用途 |
|-----|------|
| `query_introspector_all_functions` | 验证函数存在 |
| `query_introspector_function_source` | 获取函数源码 |
| `query_introspector_type_definition` | 查询类型定义 |
| `query_introspector_call_sites_metadata` | 分析调用关系 |

---

## 实际例子

### libxml2 xmlParseFile

```c
// 目标函数
xmlDoc* xmlParseFile(const char* filename);

// 前置依赖识别
xmlInitParser();  // 全局初始化

// 数据依赖
xmlCleanupParser();  // 清理函数 (后置)
```

**生成的调用序列**:
```c
xmlInitParser();
xmlDoc* doc = xmlParseFile("/tmp/input.xml");
if (doc) xmlFreeDoc(doc);
xmlCleanupParser();
```

---

## 关键配置

```python
# api_dependency_analyzer.py
MAX_SEARCH_DEPTH = 2          # 依赖搜索深度
MAX_PREREQUISITE_COUNT = 5    # 最多识别5个前置函数
FUZZER_FRIENDLY_KEYWORDS = [  # 优先选择这些函数
    "init", "create", "new", "setup"
]
```

---

## 限制

1. **启发式规则**: 依赖命名约定，可能漏识别
2. **循环依赖**: 检测到环时fallback到简单顺序
3. **全局状态**: 难以追踪跨函数的全局变量依赖
4. **Token限制**: 只包含最关键的依赖信息

---

## 关键文件

```
utils/
├── api_dependency_analyzer.py    # 核心分析器
└── header_extractor.py           # tree-sitter解析

nodes/
└── function_analyzer_node.py     # 集成点

agents/
└── prototyper.py                 # 消费依赖图

tools/
└── fuzz_introspector_tools.py    # FI API包装
```
