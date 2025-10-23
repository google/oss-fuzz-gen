# LangGraph Agent 状态机图

## 完整工作流程图

```mermaid
flowchart TD
    Start([开始]) --> Supervisor{Supervisor<br/>监督节点}
    
    Supervisor -->|无函数分析| FunctionAnalyzer[Function Analyzer<br/>函数分析器]
    Supervisor -->|无Fuzz Target| Prototyper[Prototyper<br/>原型生成器]
    Supervisor -->|未构建| Build[Build<br/>构建节点]
    Supervisor -->|构建失败<br/>且未超重试次数| Enhancer[Enhancer<br/>增强器]
    Supervisor -->|构建成功<br/>但未运行| Execution[Execution<br/>执行节点]
    Supervisor -->|发现崩溃<br/>未分析| CrashAnalyzer[Crash Analyzer<br/>崩溃分析器]
    Supervisor -->|崩溃已分析<br/>未做上下文分析| ContextAnalyzer[Context Analyzer<br/>上下文分析器]
    Supervisor -->|低覆盖率<br/>无显著改进| CoverageAnalyzer[Coverage Analyzer<br/>覆盖率分析器]
    Supervisor -->|达到终止条件| End([结束])
    
    FunctionAnalyzer --> Supervisor
    Prototyper --> Supervisor
    Build --> Supervisor
    Enhancer --> Supervisor
    Execution --> Supervisor
    CrashAnalyzer --> Supervisor
    ContextAnalyzer --> Supervisor
    CoverageAnalyzer --> Supervisor
    
    style Start fill:#90EE90
    style End fill:#FFB6C1
    style Supervisor fill:#87CEEB
    style FunctionAnalyzer fill:#FFD700
    style Prototyper fill:#FFD700
    style Enhancer fill:#FFD700
    style Build fill:#DDA0DD
    style Execution fill:#DDA0DD
    style CrashAnalyzer fill:#FF6347
    style ContextAnalyzer fill:#FF6347
    style CoverageAnalyzer fill:#FF6347
```

## 状态机详细说明

### 1. 节点类型

#### 监督节点 (Supervisor)
- **功能**: 根据当前状态决定下一步操作
- **输入**: 当前工作流状态
- **输出**: next_action (下一个要执行的节点)

#### LLM驱动节点 (使用大语言模型)
- **Function Analyzer**: 分析目标函数，生成函数签名和需求
- **Prototyper**: 生成初始的fuzz target和构建脚本
- **Enhancer**: 基于错误反馈改进fuzz target
- **Crash Analyzer**: 分析崩溃信息，判断是否为真bug
- **Coverage Analyzer**: 分析覆盖率报告，提供改进建议
- **Context Analyzer**: 分析崩溃的上下文，判断可行性

#### 非LLM节点
- **Build**: 编译fuzz target
- **Execution**: 运行fuzzer并收集结果

### 2. 路由决策树

```mermaid
flowchart TD
    Start{开始路由决策} --> HasFuncAnalysis{是否有<br/>函数分析?}
    
    HasFuncAnalysis -->|否| FuncAnalyzer[→ function_analyzer]
    HasFuncAnalysis -->|是| HasFuzzTarget{是否有<br/>Fuzz Target?}
    
    HasFuzzTarget -->|否| Proto[→ prototyper]
    HasFuzzTarget -->|是| HasBuilt{是否已构建?}
    
    HasBuilt -->|未构建| BuildNode[→ build]
    HasBuilt -->|构建失败| BuildFailed{重试次数<br/>< 最大值?}
    HasBuilt -->|构建成功| HasRun{是否已运行?}
    
    BuildFailed -->|是| Enhance1[→ enhancer]
    BuildFailed -->|否| EndNode1[→ END]
    
    HasRun -->|未运行| ExecNode[→ execution]
    HasRun -->|运行失败| RunFailed{是否崩溃?}
    HasRun -->|运行成功| CheckCov{检查覆盖率}
    
    RunFailed -->|是崩溃| HasCrashAnalysis{是否有<br/>崩溃分析?}
    RunFailed -->|否| Enhance2[→ enhancer]
    
    HasCrashAnalysis -->|否| CrashAna[→ crash_analyzer]
    HasCrashAnalysis -->|是| HasContext{是否有<br/>上下文分析?}
    
    HasContext -->|否| ContextAna[→ context_analyzer]
    HasContext -->|是| IsFeasible{崩溃可行<br/>真bug?}
    
    IsFeasible -->|是| EndNode2[→ END<br/>发现真bug!]
    IsFeasible -->|否| Enhance3[→ enhancer<br/>假阳性]
    
    CheckCov --> CovPercent{覆盖率 < 50%<br/>且无显著改进?}
    
    CovPercent -->|是| HasCovAnalysis{是否有<br/>覆盖率分析?}
    CovPercent -->|否| CheckStagnant{连续<br/>无改进次数<br/>>= 3?}
    
    HasCovAnalysis -->|否| CovAna[→ coverage_analyzer]
    HasCovAnalysis -->|是| NeedImprove{建议改进?}
    
    NeedImprove -->|是| CheckIter{迭代次数<br/>< 最大值?}
    NeedImprove -->|否| EndNode3[→ END]
    
    CheckIter -->|是| Enhance4[→ enhancer]
    CheckIter -->|否| EndNode4[→ END]
    
    CheckStagnant -->|是| EndNode5[→ END<br/>覆盖率稳定]
    CheckStagnant -->|否| EndNode6[→ END<br/>达标或迭代完成]
    
    style Start fill:#87CEEB
    style FuncAnalyzer fill:#FFD700
    style Proto fill:#FFD700
    style BuildNode fill:#DDA0DD
    style Enhance1 fill:#FFD700
    style Enhance2 fill:#FFD700
    style Enhance3 fill:#FFD700
    style Enhance4 fill:#FFD700
    style ExecNode fill:#DDA0DD
    style CrashAna fill:#FF6347
    style ContextAna fill:#FF6347
    style CovAna fill:#FF6347
    style EndNode1 fill:#FFB6C1
    style EndNode2 fill:#90EE90
    style EndNode3 fill:#FFB6C1
    style EndNode4 fill:#FFB6C1
    style EndNode5 fill:#90EE90
    style EndNode6 fill:#90EE90
```

### 3. 循环控制机制

```mermaid
flowchart TD
    Check{循环检查} --> GlobalCount{supervisor_call_count<br/>> 50?}
    GlobalCount -->|是| Term1[终止: global_loop_limit]
    GlobalCount -->|否| ErrorCount{错误数量<br/>> max_errors?}
    
    ErrorCount -->|是| Term2[终止: too_many_errors]
    ErrorCount -->|否| RetryCount{retry_count<br/>> max_retries?}
    
    RetryCount -->|是| Term3[终止: max_retries_reached]
    RetryCount -->|否| NodeVisit{单节点访问次数<br/>> 10?}
    
    NodeVisit -->|是| Term4[终止: node_loop_detected]
    NodeVisit -->|否| NoImprov{无覆盖率改进<br/>次数 >= 3?}
    
    NoImprov -->|是| Term5[正常结束: 覆盖率稳定]
    NoImprov -->|否| Continue[继续执行]
    
    style Check fill:#87CEEB
    style Term1 fill:#FFB6C1
    style Term2 fill:#FFB6C1
    style Term3 fill:#FFB6C1
    style Term4 fill:#FFB6C1
    style Term5 fill:#90EE90
    style Continue fill:#90EE90
```

### 4. 状态数据流

```mermaid
flowchart LR
    State[(FuzzingWorkflowState)]
    
    State -->|基础信息| Basic[benchmark<br/>trial<br/>work_dirs]
    State -->|分析结果| Analysis[function_analysis<br/>context_analysis<br/>crash_analysis<br/>coverage_analysis]
    State -->|构建结果| Build[compile_success<br/>build_errors<br/>binary_exists]
    State -->|执行结果| Exec[run_success<br/>coverage_percent<br/>crashes<br/>crash_info]
    State -->|工作流控制| Control[next_action<br/>retry_count<br/>supervisor_call_count<br/>node_visit_counts]
    State -->|消息历史| Messages[agent_messages<br/>每个agent独立]
    
    style State fill:#87CEEB
    style Basic fill:#FFD700
    style Analysis fill:#FF6347
    style Build fill:#DDA0DD
    style Exec fill:#DDA0DD
    style Control fill:#90EE90
    style Messages fill:#FFA500
```

### 5. 典型执行路径

#### 路径1: 成功发现真bug
```
Start → Supervisor → FunctionAnalyzer → Supervisor → Prototyper → 
Supervisor → Build → Supervisor → Execution → Supervisor → 
CrashAnalyzer → Supervisor → ContextAnalyzer → Supervisor → END (真bug!)
```

#### 路径2: 达到良好覆盖率
```
Start → Supervisor → FunctionAnalyzer → Supervisor → Prototyper → 
Supervisor → Build → Supervisor → Execution → Supervisor → 
CoverageAnalyzer → Supervisor → Enhancer → Supervisor → Build → 
Supervisor → Execution → Supervisor → END (覆盖率达标)
```

#### 路径3: 构建失败后修复
```
Start → Supervisor → FunctionAnalyzer → Supervisor → Prototyper → 
Supervisor → Build (失败) → Supervisor → Enhancer → Supervisor → 
Build → Supervisor → Execution → Supervisor → END
```

### 6. 关键配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| MAX_SUPERVISOR_CALLS | 50 | 全局supervisor调用次数上限 |
| MAX_NODE_VISITS | 10 | 单个节点最大访问次数 |
| max_retries | 3 | 最大重试次数 |
| max_errors | 5 | 最大错误数量 |
| NO_IMPROVEMENT_THRESHOLD | 3 | 连续无覆盖率改进次数阈值 |
| COVERAGE_THRESHOLD | 0.5 | 低覆盖率阈值 (50%) |
| IMPROVEMENT_THRESHOLD | 0.01 | 最小改进阈值 (1%) |
| SIGNIFICANT_IMPROVEMENT | 0.05 | 显著改进阈值 (5%) |
| max_iterations | 5 | 最大迭代次数 |

## 图例说明

- 🟢 **绿色**: 开始/成功结束
- 🔵 **蓝色**: Supervisor监督节点
- 🟡 **黄色**: LLM驱动的分析/生成节点
- 🟣 **紫色**: 构建/执行节点（非LLM）
- 🔴 **红色**: 分析节点（崩溃/覆盖率）
- 🔴 **粉色**: 异常终止

