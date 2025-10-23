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

### 3. Loop Control Mechanism

```mermaid
flowchart TD
    Check{Loop Check} --> GlobalCount{supervisor_call_count<br/>> 50?}
    GlobalCount -->|Yes| Term1[Terminate: global_loop_limit]
    GlobalCount -->|No| ErrorCount{Error Count<br/>> max_errors?}
    
    ErrorCount -->|Yes| Term2[Terminate: too_many_errors]
    ErrorCount -->|No| RetryCount{retry_count<br/>> max_retries?}
    
    RetryCount -->|Yes| Term3[Terminate: max_retries_reached]
    RetryCount -->|No| NodeVisit{Single Node Visit Count<br/>> 10?}
    
    NodeVisit -->|Yes| Term4[Terminate: node_loop_detected]
    NodeVisit -->|No| NoImprov{No Coverage Improvement<br/>Count >= 3?}
    
    NoImprov -->|Yes| Term5[Normal End: Coverage Stable]
    NoImprov -->|No| Continue[Continue Execution]
    
    style Check fill:#87CEEB
    style Term1 fill:#FFB6C1
    style Term2 fill:#FFB6C1
    style Term3 fill:#FFB6C1
    style Term4 fill:#FFB6C1
    style Term5 fill:#90EE90
    style Continue fill:#90EE90
```

### 4. State Data Flow

```mermaid
flowchart LR
    State[(FuzzingWorkflowState)]
    
    State -->|Basic Info| Basic[benchmark<br/>trial<br/>work_dirs]
    State -->|Analysis Results| Analysis[function_analysis<br/>context_analysis<br/>crash_analysis<br/>coverage_analysis]
    State -->|Build Results| Build[compile_success<br/>build_errors<br/>binary_exists]
    State -->|Execution Results| Exec[run_success<br/>coverage_percent<br/>crashes<br/>crash_info]
    State -->|Workflow Control| Control[next_action<br/>retry_count<br/>supervisor_call_count<br/>node_visit_counts]
    State -->|Message History| Messages[agent_messages<br/>per agent]
    
    style State fill:#87CEEB
    style Basic fill:#FFD700
    style Analysis fill:#FF6347
    style Build fill:#DDA0DD
    style Exec fill:#DDA0DD
    style Control fill:#90EE90
    style Messages fill:#FFA500
```

### 5. Typical Execution Paths

#### Path 1: Real Bug Successfully Found
```
Start → Supervisor → FunctionAnalyzer → Supervisor → Prototyper → 
Supervisor → Build → Supervisor → Execution → Supervisor → 
CrashAnalyzer → Supervisor → ContextAnalyzer → Supervisor → END (Real Bug!)
```

#### Path 2: Good Coverage Achieved
```
Start → Supervisor → FunctionAnalyzer → Supervisor → Prototyper → 
Supervisor → Build → Supervisor → Execution → Supervisor → 
CoverageAnalyzer → Supervisor → Enhancer → Supervisor → Build → 
Supervisor → Execution → Supervisor → END (Coverage Target Met)
```

#### Path 3: Build Failure then Fixed
```
Start → Supervisor → FunctionAnalyzer → Supervisor → Prototyper → 
Supervisor → Build (Failed) → Supervisor → Enhancer → Supervisor → 
Build → Supervisor → Execution → Supervisor → END
```

### 6. Key Configuration Parameters

| Parameter | Default | Description |
|------|--------|------|
| MAX_SUPERVISOR_CALLS | 50 | Global supervisor call count limit |
| MAX_NODE_VISITS | 10 | Maximum visits per node |
| max_retries | 3 | Maximum retry count |
| max_errors | 5 | Maximum error count |
| NO_IMPROVEMENT_THRESHOLD | 3 | Threshold for consecutive no-improvement iterations |
| COVERAGE_THRESHOLD | 0.5 | Low coverage threshold (50%) |
| IMPROVEMENT_THRESHOLD | 0.01 | Minimum improvement threshold (1%) |
| SIGNIFICANT_IMPROVEMENT | 0.05 | Significant improvement threshold (5%) |
| max_iterations | 5 | Maximum iteration count |

## Legend

- 🟢 **Green**: Start/Successful End
- 🔵 **Blue**: Supervisor Node
- 🟡 **Yellow**: LLM-Driven Analysis/Generation Nodes
- 🟣 **Purple**: Build/Execution Nodes (Non-LLM)
- 🔴 **Red**: Analysis Nodes (Crash/Coverage)
- 🔴 **Pink**: Abnormal Termination

