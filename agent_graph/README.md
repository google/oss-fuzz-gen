# LangGraph Agent State Machine

## Two-Phase Workflow Architecture

LogicFuzz implements a **two-phase workflow** to separate compilation concerns from optimization goals:

### **Phase 1: COMPILATION** 
Focus: Get the fuzz target to compile successfully
- Function Analysis → Code Generation → Compilation Fixing
- Dedicated retry counters and strategies
- Prototyper regeneration with error context

### **Phase 2: OPTIMIZATION**
Focus: Maximize coverage and discover bugs
- Execution → Analysis → Iterative Improvement
- Coverage-driven enhancement
- Crash analysis and feasibility checking

---

## Complete Workflow Diagram

```mermaid
flowchart TD
    Start([Start]) --> Phase1{PHASE 1:<br/>COMPILATION}
    
    Phase1 -->|Step 1| FunctionAnalyzer[Function Analyzer<br/>API Semantics]
    FunctionAnalyzer --> Phase1Check1{Has Analysis?}
    Phase1Check1 -->|Yes| Prototyper[Prototyper<br/>Generate Code]
    
    Prototyper --> Phase1Check2{Has Code?}
    Phase1Check2 -->|Yes| Build[Build<br/>Compile Target]
    
    Build --> BuildResult{Build<br/>Success?}
    BuildResult -->|Failed| CompileRetry{compilation_retry_count<br/>< 3?}
    
    CompileRetry -->|Yes| Enhancer1[Enhancer<br/>Fix w/ Error Context]
    Enhancer1 --> Build
    
    CompileRetry -->|No| ProtoRegen{prototyper_regenerate_count<br/>< 1?}
    ProtoRegen -->|Yes| PrototyperRegen[Prototyper<br/>Regenerate New Approach]
    ProtoRegen -->|No| EndFail([END<br/>Compilation Failed])
    
    PrototyperRegen --> Build
    
    BuildResult -->|Success| PhaseSwitch[Switch to<br/>PHASE 2: OPTIMIZATION]
    
    PhaseSwitch --> Execution[Execution<br/>Run Fuzzer]
    
    Execution --> ExecResult{Result?}
    
    ExecResult -->|Crash| CrashAnalyzer[Crash Analyzer<br/>Analyze Crash Type]
    CrashAnalyzer --> ContextAnalyzer[Context Analyzer<br/>Feasibility Check]
    ContextAnalyzer --> IsFeasible{Real Bug?}
    IsFeasible -->|Yes| EndBug([END<br/>Bug Found! ✓])
    IsFeasible -->|No| Enhancer2[Enhancer<br/>Fix False Positive]
    Enhancer2 --> Build
    
    ExecResult -->|Success| CheckCoverage{Coverage<br/>Good?}
    
    CheckCoverage -->|< 50% & diff < 5%| CoverageAnalyzer[Coverage Analyzer<br/>Suggest Improvements]
    CoverageAnalyzer --> CheckIter{Iterations<br/>< Max?}
    CheckIter -->|Yes| Enhancer3[Enhancer<br/>Improve Coverage]
    CheckIter -->|No| EndMaxIter([END<br/>Max Iterations])
    Enhancer3 --> Build
    
    CheckCoverage -->|>= 50% OR diff >= 5%| CheckStagnant{No Improvement<br/>Count >= 3?}
    CheckStagnant -->|Yes| EndStable([END<br/>Coverage Stable ✓])
    CheckStagnant -->|No| Execution
    
    style Start fill:#90EE90
    style Phase1 fill:#87CEEB
    style PhaseSwitch fill:#FFA500
    style FunctionAnalyzer fill:#FFD700
    style Prototyper fill:#FFD700
    style PrototyperRegen fill:#FFD700
    style Enhancer1 fill:#FFD700
    style Enhancer2 fill:#FFD700
    style Enhancer3 fill:#FFD700
    style Build fill:#DDA0DD
    style Execution fill:#DDA0DD
    style CrashAnalyzer fill:#FF6347
    style ContextAnalyzer fill:#FF6347
    style CoverageAnalyzer fill:#FF6347
    style EndFail fill:#FFB6C1
    style EndBug fill:#90EE90
    style EndMaxIter fill:#FFB6C1
    style EndStable fill:#90EE90
```

### Core Workflow Principles

The workflow follows a **two-phase centralized routing** where:

**Phase 1 (Compilation):**
1. **FunctionAnalyzer** analyzes API semantics (preconditions, setup sequence, constraints)
2. **Prototyper** generates initial fuzz target
3. **Build** attempts compilation
4. **Enhancer** fixes errors (max 3 retries with intelligent code context)
5. **Prototyper Regeneration** if enhancer fails (completely new approach)

**Phase 2 (Optimization):**
1. **Execution** runs the fuzz target and collects metrics
2. **CrashAnalyzer** + **ContextAnalyzer** validate crashes (feasibility checking)
3. **CoverageAnalyzer** suggests improvements for low coverage
4. **Enhancer** iteratively improves the target
5. Loops until good coverage, bug found, or max iterations

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

### 2. Two-Phase Routing Logic

The Supervisor implements **phase-aware routing** with different strategies for compilation vs optimization:

```mermaid
flowchart TD
    Start{Supervisor<br/>Routing} --> CheckPhase{workflow_phase?}
    
    CheckPhase -->|"compilation"| Phase1[PHASE 1:<br/>COMPILATION]
    CheckPhase -->|"optimization"| Phase2[PHASE 2:<br/>OPTIMIZATION]
    
    Phase1 --> P1_HasAnalysis{Has<br/>Function Analysis?}
    P1_HasAnalysis -->|No| P1_Analyzer[→ function_analyzer]
    P1_HasAnalysis -->|Yes| P1_HasTarget{Has<br/>Fuzz Target?}
    
    P1_HasTarget -->|No| P1_Proto[→ prototyper]
    P1_HasTarget -->|Yes| P1_Built{Build Status?}
    
    P1_Built -->|Not Built| P1_Build[→ build]
    P1_Built -->|Failed| P1_Retry{compilation_retry_count<br/>< 3?}
    P1_Built -->|Success| P1_Switch[Switch to Phase 2]
    
    P1_Retry -->|Yes| P1_Enhancer[→ enhancer<br/>code context extraction]
    P1_Retry -->|No| P1_Regen{prototyper_regenerate_count<br/>< 1?}
    
    P1_Regen -->|Yes| P1_ProtoRegen[→ prototyper<br/>add error context<br/>reset compilation_retry_count]
    P1_Regen -->|No| P1_End[→ END<br/>Compilation Failed]
    
    P1_Switch --> P2_Exec
    
    Phase2 --> P2_HasRun{Has Run?}
    P2_HasRun -->|No| P2_Exec[→ execution]
    P2_HasRun -->|Yes| P2_Result{Run Result?}
    
    P2_Result -->|Crashed| P2_CrashCheck{Has<br/>Crash Analysis?}
    P2_Result -->|Success| P2_Coverage{Coverage Check}
    
    P2_CrashCheck -->|No| P2_CrashAna[→ crash_analyzer]
    P2_CrashCheck -->|Yes| P2_ContextCheck{Has<br/>Context Analysis?}
    
    P2_ContextCheck -->|No| P2_ContextAna[→ context_analyzer]
    P2_ContextCheck -->|Yes| P2_Feasible{Feasible<br/>Real Bug?}
    
    P2_Feasible -->|Yes| P2_EndBug[→ END<br/>Bug Found!]
    P2_Feasible -->|No| P2_EnhancerFP[→ enhancer<br/>False Positive]
    
    P2_Coverage --> P2_CovLow{Coverage < 50%<br/>OR<br/>diff < 5%?}
    P2_CovLow -->|Yes| P2_CovCheck{Has<br/>Coverage Analysis?}
    P2_CovLow -->|No| P2_Stagnant{no_improvement<br/>count >= 3?}
    
    P2_CovCheck -->|No| P2_CovAna[→ coverage_analyzer]
    P2_CovCheck -->|Yes| P2_Iter{current_iteration<br/>< max_iterations?}
    
    P2_Iter -->|Yes| P2_EnhancerCov[→ enhancer<br/>retry_count++]
    P2_Iter -->|No| P2_EndMaxIter[→ END<br/>Max Iterations]
    
    P2_Stagnant -->|Yes| P2_EndStable[→ END<br/>Coverage Stable]
    P2_Stagnant -->|No| P2_Continue[Continue Loop]
    
    style Start fill:#87CEEB
    style Phase1 fill:#B0E0E6
    style Phase2 fill:#FFE4B5
    style P1_Analyzer fill:#FFD700
    style P1_Proto fill:#FFD700
    style P1_ProtoRegen fill:#FFD700
    style P1_Enhancer fill:#FFD700
    style P1_Build fill:#DDA0DD
    style P1_Switch fill:#FFA500
    style P2_Exec fill:#DDA0DD
    style P2_CrashAna fill:#FF6347
    style P2_ContextAna fill:#FF6347
    style P2_CovAna fill:#FF6347
    style P2_EnhancerFP fill:#FFD700
    style P2_EnhancerCov fill:#FFD700
    style P1_End fill:#FFB6C1
    style P2_EndBug fill:#90EE90
    style P2_EndMaxIter fill:#FFB6C1
    style P2_EndStable fill:#90EE90
```

#### Key Routing Differences Between Phases:

**COMPILATION Phase:**
- Uses `compilation_retry_count` (max 3)
- Enables Prototyper regeneration after retry exhaustion
- Enhancer receives intelligent code context (error lines ±10)
- Automatically switches to OPTIMIZATION on build success

**OPTIMIZATION Phase:**
- Uses `retry_count` for enhancement iterations
- Tracks `no_coverage_improvement_count` for stagnation detection
- Coverage-driven decision making (50% threshold, 5% diff)
- Crash feasibility validation before termination

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

