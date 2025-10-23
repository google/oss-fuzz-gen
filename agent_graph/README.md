# LangGraph Agent State Machine

## Complete Workflow Diagram

```mermaid
flowchart TD
    Start([Start]) --> Supervisor{Supervisor<br/>Node}
    
    Supervisor -->|1. No function analysis| FunctionAnalyzer[Function Analyzer]
    Supervisor -->|2. No Fuzz Target| Prototyper[Prototyper]
    Supervisor -->|3. Has Target but not built| Build[Build<br/>Node]
    Supervisor -->|4. Build failed<br/>retry < max| Enhancer[Enhancer]
    Supervisor -->|5. Build success<br/>but not run| Execution[Execution<br/>Node]
    Supervisor -->|6. Crash not analyzed| CrashAnalyzer[Crash Analyzer]
    Supervisor -->|7. Crash analyzed<br/>no context analysis| ContextAnalyzer[Context Analyzer]
    Supervisor -->|8. Low coverage<br/>no significant improvement| CoverageAnalyzer[Coverage Analyzer]
    Supervisor -->|9. Termination condition met| End([End])
    
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

### Core Loop Structure

The workflow follows a **centralized star topology** where all nodes return to Supervisor for next-step decision making:

1. **FunctionAnalyzer** → Supervisor → **Prototyper** → Supervisor → **Build** → Supervisor
2. Build success → **Execution** → Supervisor
3. Build failure → **Enhancer** → Supervisor → Build (retry loop)
4. Crash detected → **CrashAnalyzer** → Supervisor → **ContextAnalyzer** → Supervisor
5. Low coverage → **CoverageAnalyzer** → Supervisor → **Enhancer** → Supervisor (improvement loop)

## State Machine Details

### 1. Node Types

#### Supervisor Node
- **Function**: Decides next action based on current state
- **Input**: Current workflow state
- **Output**: next_action (next node to execute)

#### LLM-Driven Nodes (Using Large Language Models)
- **Function Analyzer**: Analyzes target function, generates function signature and requirements
- **Prototyper**: Generates initial fuzz target and build scripts
- **Enhancer**: Improves fuzz target based on error feedback
- **Crash Analyzer**: Analyzes crash information, determines if it's a real bug
- **Coverage Analyzer**: Analyzes coverage reports, provides improvement suggestions
- **Context Analyzer**: Analyzes crash context, determines feasibility

#### Non-LLM Nodes
- **Build**: Compiles fuzz target
- **Execution**: Runs fuzzer and collects results

### 2. Routing Decision Tree

```mermaid
flowchart TD
    Start{Start Routing Decision} --> HasFuncAnalysis{Has<br/>Function Analysis?}
    
    HasFuncAnalysis -->|No| FuncAnalyzer[→ function_analyzer]
    HasFuncAnalysis -->|Yes| HasFuzzTarget{Has<br/>Fuzz Target?}
    
    HasFuzzTarget -->|No| Proto[→ prototyper]
    HasFuzzTarget -->|Yes| HasBuilt{Built?}
    
    HasBuilt -->|Not Built| BuildNode[→ build]
    HasBuilt -->|Build Failed| BuildFailed{Retry Count<br/>< Max?}
    HasBuilt -->|Build Success| HasRun{Run?}
    
    BuildFailed -->|Yes| Enhance1[→ enhancer]
    BuildFailed -->|No| EndNode1[→ END]
    
    HasRun -->|Not Run| ExecNode[→ execution]
    HasRun -->|Run Failed| RunFailed{Crashed?}
    HasRun -->|Run Success| CheckCov{Check Coverage}
    
    RunFailed -->|Crashed| HasCrashAnalysis{Has<br/>Crash Analysis?}
    RunFailed -->|No| Enhance2[→ enhancer]
    
    HasCrashAnalysis -->|No| CrashAna[→ crash_analyzer]
    HasCrashAnalysis -->|Yes| HasContext{Has<br/>Context Analysis?}
    
    HasContext -->|No| ContextAna[→ context_analyzer]
    HasContext -->|Yes| IsFeasible{Crash Feasible<br/>Real Bug?}
    
    IsFeasible -->|Yes| EndNode2[→ END<br/>Real Bug Found!]
    IsFeasible -->|No| Enhance3[→ enhancer<br/>False Positive]
    
    CheckCov --> CovPercent{Coverage < 50%<br/>No Significant Improvement?}
    
    CovPercent -->|Yes| HasCovAnalysis{Has<br/>Coverage Analysis?}
    CovPercent -->|No| CheckStagnant{Consecutive<br/>No Improvement<br/>>= 3?}
    
    HasCovAnalysis -->|No| CovAna[→ coverage_analyzer]
    HasCovAnalysis -->|Yes| NeedImprove{Needs Improvement?}
    
    NeedImprove -->|Yes| CheckIter{Iteration Count<br/>< Max?}
    NeedImprove -->|No| EndNode3[→ END]
    
    CheckIter -->|Yes| Enhance4[→ enhancer]
    CheckIter -->|No| EndNode4[→ END]
    
    CheckStagnant -->|Yes| EndNode5[→ END<br/>Coverage Stable]
    CheckStagnant -->|No| EndNode6[→ END<br/>Target Met or Iterations Complete]
    
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

