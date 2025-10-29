# Function Analyzer Prompt优化指南

本文档说明Function Analyzer的prompt结构以及如何优化每个prompt文件来实现精准的function analysis引导。

## 📁 Prompt文件结构

Function Analyzer使用以下prompt文件（按执行顺序）：

### 1. **function_analyzer_system.txt** 
- **作用**: 定义agent的整体角色和任务目标
- **当前内容**: 定义了以下分析框架：
  - Preconditions → State Transitions → Postconditions
  - 关注对象生命周期和状态转换
  - 要求cite source code evidence
  
### 2. **function_analyzer_initial_prompt.txt** ⭐ 
- **作用**: 第一阶段 - 分析目标函数源码本身
- **输入变量**:
  - `{FUNCTION_SIGNATURE}`: 函数签名
  - `{FUNCTION_SOURCE}`: 函数源代码
- **优化重点**:
  - 引导LLM关注哪些函数特征（参数、返回值、约束）
  - 决定初始分析的深度和广度
  - 为后续迭代分析奠定基础

### 3. **function_analyzer_iteration_prompt.txt** ⭐⭐⭐ 
- **作用**: 第二阶段 - 迭代分析真实使用案例
- **输入变量**:
  - `{EXAMPLE_NUMBER}`: 当前案例编号
  - `{EXAMPLES_ANALYZED}`: 已分析的案例数
  - `{CALLER_NAME}`: 调用者函数名
  - `{CALL_LINE_NUMBER}`: 调用位置
  - `{CONTEXT_BEFORE}`: 调用前的代码上下文
  - `{CALL_STATEMENT}`: API调用语句
  - `{CONTEXT_AFTER}`: 调用后的代码上下文
  - `{PARAMETER_SETUP}`: 参数准备代码
  - `{RETURN_USAGE}`: 返回值使用代码
- **优化重点** (最关键):
  - **引导LLM从usage example中提取什么信息**
  - 如何识别usage pattern
  - 如何发现参数约束和preconditions
  - 如何识别error handling模式
  - 如何判断何时"已无新见解"（收敛判断）

### 4. **function_analyzer_final_summary_prompt.txt**
- **作用**: 第三阶段 - 生成最终综合分析报告
- **输入变量**:
  - `{PROJECT_NAME}`: 项目名称
  - `{FUNCTION_SIGNATURE}`: 函数签名
  - `{EXAMPLES_COUNT}`: 分析的案例总数
- **优化重点**:
  - 如何综合所有对话历史形成最终分析
  - 输出格式应该包含哪些关键信息
  - 如何为prototyper提供可操作的指导

## 🎯 核心优化目标

### 当前设计理念
- **完全LLM驱动**: 不hardcode数据结构，所有模式识别由LLM完成
- **对话式累积知识**: 通过agent的对话历史自动累积见解
- **自由格式输出**: 不强制JSON格式，让LLM自由表达

### 你需要引导LLM关注的要点

#### A. 参数分析 (Parameter Analysis)
```
- 参数如何构造？(malloc? static? from other functions?)
- 参数有哪些约束？(>0? aligned? non-null?)
- 哪些参数可以直接fuzz？哪些需要满足前置条件？
- 参数之间有关联吗？(size vs buffer length)
```

#### B. 生命周期分析 (Lifecycle Analysis)
```
- 是否需要init/setup函数？
- 是否需要cleanup/free函数？
- 对象有哪些状态？状态如何转换？
- 多个API调用的典型顺序是什么？
```

#### C. 返回值与错误处理 (Return & Error Handling)
```
- 如何判断成功/失败？
- 常见的错误返回值是什么？
- caller如何检查错误？
- 失败时需要怎样的cleanup？
```

#### D. 覆盖率线索 (Coverage Hints)
```
- 不同usage pattern导致不同的代码路径
- 哪些参数组合可以触发边界条件？
- 哪些输入可能触发深层逻辑？
```

#### E. 崩溃风险 (Crash Risks)
```
- 违反哪些preconditions会导致崩溃？
- null pointer解引用的风险在哪？
- buffer overflow的可能性？
- use-after-free的风险？
```

## 🔧 优化建议

### 优先级1: function_analyzer_iteration_prompt.txt
这是最关键的文件，决定了每个usage example能提取多少信息。

**当前问题**:
- 太泛化，让LLM"note any insights"可能遗漏关键信息
- 没有明确要求LLM对比新旧pattern
- 缺少具体的分析checklist

**建议改进**:
1. 添加具体的分析维度checklist
2. 明确要求对比之前的pattern
3. 引导LLM识别"哪些pattern是新的"
4. 要求LLM总结"累积的共识"

### 优先级2: function_analyzer_system.txt
定义整体分析框架。

**当前问题**:
- 偏向理论化（Preconditions → Postconditions）
- 缺少对fuzzing实用性的强调

**建议改进**:
1. 强调"为fuzzer生成做准备"
2. 明确要求"可操作的setup sequences"
3. 要求区分"可fuzz的参数" vs "需约束的参数"

### 优先级3: function_analyzer_final_summary_prompt.txt
综合所有见解生成最终报告。

**建议改进**:
1. 明确输出格式（给prototyper用）
2. 要求总结最critical的constraints
3. 提供setup sequence示例
4. 标注high-risk areas

## 📊 衡量优化效果

优化prompt后，可以观察：
1. **迭代收敛速度**: 是否能在更少examples内收敛
2. **信息提取质量**: 是否捕获了关键constraints
3. **fuzz target成功率**: 生成的代码是否能编译+运行
4. **覆盖率**: 是否指导生成了high-coverage的fuzz target

## 💡 实验建议

1. 从一个具体案例开始（如libpng的png_read_info）
2. 手动review LLM的分析过程
3. 识别LLM遗漏的关键信息
4. 在prompt中添加针对性引导
5. 迭代优化直到LLM能自主发现这些信息

---

**关键原则**: Prompt应该像一个资深工程师在引导junior engineer做code review，
明确告诉他们"看什么"、"怎么看"、"记录什么"。

