"""State management for LangGraph-based fuzzing workflow."""

from typing_extensions import TypedDict, NotRequired, Annotated
from typing import List, Dict, Any, Optional


def add_agent_messages(
    left: Dict[str, List[Dict[str, Any]]], 
    right: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Message reducer for agent-specific messages.
    
    This reducer:
    1. Merges agent-specific message dictionaries
    2. Trims each agent's messages independently to 50k tokens
    3. Preserves system messages for each agent
    
    Args:
        left: Existing agent messages {agent_name: [messages]}
        right: New agent messages to merge
    
    Returns:
        Merged and trimmed agent messages
    """
    from agent_graph.memory import trim_messages_by_tokens
    
    # Start with a copy of left
    result = left.copy()
    
    # Merge each agent's messages from right
    for agent_name, messages in right.items():
        if agent_name in result:
            # Combine existing and new messages for this agent
            combined = result[agent_name] + messages
        else:
            # New agent, just use the messages from right
            combined = messages
        
        # Trim this agent's messages to 100k tokens
        result[agent_name] = trim_messages_by_tokens(
            combined,
            max_tokens=100000,  # Increase to 100k tokens per agent
            keep_system=True,
            system_max_tokens=10000  # Limit system message to 10k
        )
    
    return result

class FuzzingWorkflowState(TypedDict):
    """
    LangGraph state schema for the fuzzing workflow.
    
    This state schema is designed to be compatible with the original
    Result object hierarchy while providing structure for LangGraph.
    """
    
    # === Core Information (Required) ===
    benchmark: Dict[str, Any]  # Benchmark dict (serialized from experiment.benchmark.Benchmark)
    trial: int  # Trial number
    work_dirs: Dict[str, Any]  # WorkDirs dict (serialized from experiment.workdir.WorkDirs)
    
    # === Agent-Specific Messages ===
    # Each agent maintains its own conversation history independently
    # Format: {agent_name: [messages]}
    # Example: {"function_analyzer": [...], "prototyper": [...]}
    agent_messages: NotRequired[Annotated[Dict[str, List[Dict[str, Any]]], add_agent_messages]]
    
    # === Function Analysis (from FunctionAnalyzer) ===
    function_analysis: NotRequired[Dict[str, Any]]
    
    # === Context Analysis (from ContextAnalyzer) ===
    context_analysis: NotRequired[Dict[str, Any]]
    
    # === Build Results (from Prototyper/Enhancer) ===
    fuzz_target_source: NotRequired[str]
    build_script_source: NotRequired[str]
    compile_success: NotRequired[bool]
    build_errors: NotRequired[List[str]]  # Keep simple for compatibility
    compile_log: NotRequired[str]
    binary_exists: NotRequired[bool]
    is_function_referenced: NotRequired[bool]
    
    # === Execution Results (from ExecutionStage) ===
    run_success: NotRequired[bool]
    run_error: NotRequired[str]
    run_log: NotRequired[str]
    artifact_path: NotRequired[str]
    crash_func: NotRequired[str]
    crashes: NotRequired[bool]
    crash_info: NotRequired[Dict[str, Any]]  # Detailed crash information including artifact_path, stack_trace, etc.
    reproducer_path: NotRequired[str]
    
    # === Coverage Results ===
    coverage_summary: NotRequired[str]
    coverage_percent: NotRequired[float]
    line_coverage_diff: NotRequired[float]
    coverage_report_path: NotRequired[str]
    cov_pcs: NotRequired[int]
    total_pcs: NotRequired[int]
    no_coverage_improvement_count: NotRequired[int]  # Track consecutive iterations without coverage improvement
    
    # === Analysis Results (from Analyzers) ===
    analysis_complete: NotRequired[bool]
    crash_analysis: NotRequired[Dict[str, Any]]
    coverage_analysis: NotRequired[Dict[str, Any]]
    
    # === Workflow Control ===
    next_action: NotRequired[str]  # For supervisor routing
    retry_count: NotRequired[int]
    max_retries: NotRequired[int]
    supervisor_call_count: NotRequired[int]  # Global counter for supervisor invocations (loop prevention)
    node_visit_counts: NotRequired[Dict[str, int]]  # Per-node visit counter (loop prevention)
    workflow_phase: NotRequired[str]  # Current workflow phase: "compilation" or "optimization"
    compilation_retry_count: NotRequired[int]  # Separate counter for compilation retries
    prototyper_regenerate_count: NotRequired[int]  # Counter for prototyper regenerations
    previous_fuzz_target_source: NotRequired[str]  # Store previous version for diff generation
    
    # === Error Handling ===
    errors: NotRequired[List[Dict[str, Any]]]
    warnings: NotRequired[List[str]]
    
    # === Configuration (from agent_test.py compatibility) ===
    pipeline: NotRequired[List[str]]  # Agent pipeline
    use_context: NotRequired[bool]  # Whether to use context
    prompt_file: NotRequired[str]  # Path to prompt file
    additional_files_path: NotRequired[str]  # Path to additional files
    run_timeout: NotRequired[int]  # Execution timeout
    current_iteration: NotRequired[int]  # Current workflow iteration
    max_iterations: NotRequired[int]  # Maximum workflow iterations
    workflow_status: NotRequired[str]  # Workflow status
    active_containers: NotRequired[List[str]]  # Active container list
    crash_results: NotRequired[List[Dict[str, Any]]]  # Crash results list
    
    # === Token Usage Statistics ===
    token_usage: NotRequired[Dict[str, Any]]  # Token consumption statistics
    
    # === Session Memory (Consensus Constraints) ===
    # Current consensus constraints established by agents during this task
    # Supervisor should always inject this consensus to downstream agents instead of full message history
    session_memory: NotRequired[Dict[str, Any]]

class WorkerState(TypedDict):
    """State for worker nodes in parallel execution."""
    
    task_id: str  # Unique task identifier
    task_type: str  # Type of task (compile, analyze, etc.)
    input_data: Dict[str, Any]  # Input data for the task
    output_data: NotRequired[Dict[str, Any]]  # Task output
    status: NotRequired[str]  # Task status
    error: NotRequired[str]  # Error message if task failed
    start_time: NotRequired[float]  # Task start timestamp
    end_time: NotRequired[float]  # Task completion timestamp

def create_initial_state(
    benchmark,  # experiment.benchmark.Benchmark object
    work_dirs,  # experiment.workdir.WorkDirs object
    trial: int = 0,
    max_round: int = 100,
    run_timeout: int = 300,
    pipeline: Optional[List[str]] = None,
    use_context: bool = False,
    prompt_file: str = "",
    additional_files_path: str = "",
    initial_prompt: str = "",
    model = None,
    **kwargs
) -> FuzzingWorkflowState:
    """Create an initial state for the fuzzing workflow with full parameter support."""
    
    # Serialize objects to dicts for msgpack compatibility
    benchmark_dict = benchmark.to_dict()
    work_dirs_dict = work_dirs.to_dict()
    
    # Initialize agent_messages dict (empty, agents will add their own system messages)
    agent_messages = {}
    
    return FuzzingWorkflowState(
        benchmark=benchmark_dict,
        trial=trial,
        work_dirs=work_dirs_dict,
        agent_messages=agent_messages,
        current_iteration=0,
        max_iterations=max_round,
        workflow_status="initialized",
        errors=[],
        warnings=[],
        # Loop prevention counters (similar to no_coverage_improvement_count)
        supervisor_call_count=0,
        node_visit_counts={},
        # Workflow phase control
        workflow_phase="compilation",  # Start with compilation phase
        compilation_retry_count=0,  # Track compilation retries separately
        prototyper_regenerate_count=0,  # Track prototyper regenerations
        previous_fuzz_target_source="",  # For diff generation
        # Store additional configuration
        pipeline=pipeline or [],
        use_context=use_context,
        prompt_file=prompt_file,
        additional_files_path=additional_files_path,
        run_timeout=run_timeout,
        build_errors=[],
        crash_results=[],
        active_containers=[],
        # Initialize token usage statistics
        token_usage={
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_tokens": 0,
            "by_agent": {}
        },
        # Initialize session memory (consensus constraints storage)
        session_memory={
            "api_constraints": [],      # API usage constraints list
            "archetype": None,           # Identified architecture pattern
            "known_fixes": [],           # Known error fixes
            "decisions": [],             # Key decision records
            "coverage_strategies": []    # Coverage optimization strategies
        }
    )

def is_terminal_state(state: FuzzingWorkflowState) -> bool:
    """Check if the workflow has reached a terminal state."""
    
    # Check termination conditions
    if state.get("termination_reason"):
        return True
    
    # Check maximum iterations
    current_iter = state.get("current_iteration", 0)
    max_iter = state.get("max_iterations", 5)
    if current_iter >= max_iter:
        return True
    
    # Check if we have a successful result
    if (state.get("compile_success") and 
        state.get("coverage_results") and 
        state.get("coverage_results", {}).get("coverage", 0) > 0.8):
        return True
    
    return False

def update_token_usage(state: FuzzingWorkflowState, agent_name: str, 
                       prompt_tokens: int, completion_tokens: int, total_tokens: int) -> None:
    """
    Update token usage statistics in state.
    
    Args:
        state: The workflow state
        agent_name: Name of the agent making the call
        prompt_tokens: Number of prompt tokens used
        completion_tokens: Number of completion tokens used
        total_tokens: Total tokens used
    """
    if "token_usage" not in state:
        state["token_usage"] = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_tokens": 0,
            "by_agent": {}
        }
    
    # Update totals
    state["token_usage"]["total_prompt_tokens"] += prompt_tokens
    state["token_usage"]["total_completion_tokens"] += completion_tokens
    state["token_usage"]["total_tokens"] += total_tokens
    
    # Update per-agent statistics
    if agent_name not in state["token_usage"]["by_agent"]:
        state["token_usage"]["by_agent"][agent_name] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "call_count": 0
        }
    
    agent_stats = state["token_usage"]["by_agent"][agent_name]
    agent_stats["prompt_tokens"] += prompt_tokens
    agent_stats["completion_tokens"] += completion_tokens
    agent_stats["total_tokens"] += total_tokens
    agent_stats["call_count"] += 1


def get_token_usage_summary(state: FuzzingWorkflowState) -> str:
    """Get a formatted summary of token usage."""
    token_usage = state.get("token_usage", {})
    if not token_usage:
        return "No token usage data available"
    
    summary = f"\n{'='*60}\n"
    summary += "Token Usage Summary\n"
    summary += f"{'='*60}\n"
    summary += f"Total Prompt Tokens:     {token_usage.get('total_prompt_tokens', 0):,}\n"
    summary += f"Total Completion Tokens: {token_usage.get('total_completion_tokens', 0):,}\n"
    summary += f"Total Tokens:            {token_usage.get('total_tokens', 0):,}\n"
    
    by_agent = token_usage.get("by_agent", {})
    if by_agent:
        summary += f"\n{'-'*60}\n"
        summary += "By Agent:\n"
        summary += f"{'-'*60}\n"
        for agent_name, stats in sorted(by_agent.items()):
            summary += f"\n{agent_name}:\n"
            summary += f"  Calls:             {stats.get('call_count', 0)}\n"
            summary += f"  Prompt Tokens:     {stats.get('prompt_tokens', 0):,}\n"
            summary += f"  Completion Tokens: {stats.get('completion_tokens', 0):,}\n"
            summary += f"  Total Tokens:      {stats.get('total_tokens', 0):,}\n"
    
    summary += f"{'='*60}\n"
    return summary


def get_state_summary(state: FuzzingWorkflowState) -> str:
    """Get a human-readable summary of the current state."""
    
    benchmark = state.get("benchmark", {})
    project = benchmark.get("project", "unknown")
    function = benchmark.get("function_name", "unknown")
    iteration = state.get("current_iteration", 0)
    status = state.get("workflow_status", "unknown")
    
    summary = f"Fuzzing workflow for {project}::{function} (iteration {iteration}, status: {status})"
    
    # Add build status
    if state.get("compile_success") is not None:
        build_status = "successful" if state["compile_success"] else "failed"
        summary += f"\n  Build: {build_status}"
    
    # Add coverage info
    coverage = state.get("coverage_results", {}).get("coverage")
    if coverage is not None:
        summary += f"\n  Coverage: {coverage:.2%}"
    
    # Add crash info
    crashes = len(state.get("crash_results", []))
    if crashes > 0:
        summary += f"\n  Crashes: {crashes} found"
    
    # Add error info
    errors = len(state.get("errors", []))
    if errors > 0:
        summary += f"\n  Errors: {errors} recorded"
    
    return summary


# ==================== Session Memory Management ====================

def add_api_constraint(
    state: FuzzingWorkflowState,
    constraint: str,
    source: str,
    confidence: str = "medium",
    iteration: int = None
) -> None:
    """
    Add API constraint to session_memory.
    
    Args:
        state: Workflow state
        constraint: Constraint description
        source: Source agent name
        confidence: Confidence level (high/medium/low)
        iteration: Iteration where this constraint was found
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": []
        }
    
    api_constraints = state["session_memory"].get("api_constraints", [])
    
    # Deduplication: Check if the same constraint already exists
    for existing in api_constraints:
        if existing["constraint"] == constraint:
            # Update if new constraint has higher confidence
            if confidence == "high" and existing["confidence"] != "high":
                existing["confidence"] = "high"
                existing["source"] = source
            return
    
    # Add new constraint
    api_constraints.append({
        "constraint": constraint,
        "source": source,
        "confidence": confidence,
        "iteration": iteration if iteration is not None else state.get("current_iteration", 0)
    })
    
    state["session_memory"]["api_constraints"] = api_constraints


def add_known_fix(
    state: FuzzingWorkflowState,
    error_pattern: str,
    solution: str,
    source: str,
    iteration: int = None
) -> None:
    """
    Add known error fix to session_memory.
    
    Args:
        state: Workflow state
        error_pattern: Error pattern description
        solution: Solution description
        source: Source agent name
        iteration: Iteration where this fix was discovered
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": []
        }
    
    known_fixes = state["session_memory"].get("known_fixes", [])
    
    # Deduplication
    for existing in known_fixes:
        if existing["error_pattern"] == error_pattern:
            # Update solution if different
            if existing["solution"] != solution:
                existing["solution"] = solution
                existing["source"] = source
            return
    
    # Add new fix
    known_fixes.append({
        "error_pattern": error_pattern,
        "solution": solution,
        "source": source,
        "iteration": iteration if iteration is not None else state.get("current_iteration", 0)
    })
    
    state["session_memory"]["known_fixes"] = known_fixes


def add_decision(
    state: FuzzingWorkflowState,
    decision: str,
    reason: str,
    source: str,
    iteration: int = None
) -> None:
    """
    Add key decision to session_memory.
    
    Args:
        state: Workflow state
        decision: Decision content
        reason: Decision reason
        source: Source agent name
        iteration: Iteration where this decision was made
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": []
        }
    
    decisions = state["session_memory"].get("decisions", [])
    
    decisions.append({
        "decision": decision,
        "reason": reason,
        "source": source,
        "iteration": iteration if iteration is not None else state.get("current_iteration", 0)
    })
    
    # Limit decisions to keep only the most recent 10
    state["session_memory"]["decisions"] = decisions[-10:]


def set_archetype(
    state: FuzzingWorkflowState,
    archetype_type: str,
    lifecycle_phases: List[str],
    source: str,
    iteration: int = None
) -> None:
    """
    Set the identified API archetype pattern.
    
    Args:
        state: Workflow state
        archetype_type: Archetype type (e.g., "stateful_decoder", "simple_parser")
        lifecycle_phases: List of lifecycle phases
        source: Source agent name
        iteration: Iteration where this archetype was identified
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": []
        }
    
    state["session_memory"]["archetype"] = {
        "type": archetype_type,
        "lifecycle_phases": lifecycle_phases,
        "source": source,
        "iteration": iteration if iteration is not None else state.get("current_iteration", 0)
    }


def add_coverage_strategy(
    state: FuzzingWorkflowState,
    strategy: str,
    target: str,
    source: str,
    iteration: int = None
) -> None:
    """
    Add coverage optimization strategy to session_memory.
    
    Args:
        state: Workflow state
        strategy: Strategy description
        target: Target/expected effect
        source: Source agent name
        iteration: Iteration where this strategy was proposed
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": []
        }
    
    strategies = state["session_memory"].get("coverage_strategies", [])
    
    # Deduplication
    for existing in strategies:
        if existing["strategy"] == strategy:
            return
    
    strategies.append({
        "strategy": strategy,
        "target": target,
        "source": source,
        "iteration": iteration if iteration is not None else state.get("current_iteration", 0)
    })
    
    # Limit strategies to keep only the most recent 10
    state["session_memory"]["coverage_strategies"] = strategies[-10:]


def format_session_memory_for_prompt(state: FuzzingWorkflowState) -> str:
    """
    Format session_memory as readable text for injection into agent prompts.
    
    Args:
        state: Workflow state
    
    Returns:
        Formatted session_memory text
    """
    session_memory = state.get("session_memory", {})
    
    if not session_memory:
        return "*No consensus constraints for this task yet*"
    
    parts = []
    
    # 1. Format API constraints
    if api_constraints := session_memory.get("api_constraints", []):
        parts.append("## API Usage Constraints")
        for c in api_constraints:
            confidence_level = c.get("confidence", "medium").upper()
            parts.append(f"- [{confidence_level}] {c['constraint']}")
            parts.append(f"  *source: {c['source']}, iteration: {c.get('iteration', 0)}*")
    
    # 2. Format archetype pattern
    if archetype := session_memory.get("archetype"):
        parts.append("\n## Identified Architecture Pattern")
        parts.append(f"- **Type**: {archetype['type']}")
        parts.append(f"- **Lifecycle**: {' → '.join(archetype['lifecycle_phases'])}")
        parts.append(f"- *source: {archetype['source']}, iteration: {archetype.get('iteration', 0)}*")
    
    # 3. Format known fixes
    if known_fixes := session_memory.get("known_fixes", []):
        parts.append("\n## Known Error Fixes")
        for fix in known_fixes[-5:]:  # Show only the most recent 5
            parts.append(f"- **Error**: {fix['error_pattern']}")
            parts.append(f"  **Solution**: {fix['solution']}")
            parts.append(f"  *source: {fix['source']}, iteration: {fix.get('iteration', 0)}*")
    
    # 4. Format decision records
    if decisions := session_memory.get("decisions", []):
        parts.append("\n## Key Decisions")
        for d in decisions[-3:]:  # Show only the most recent 3
            parts.append(f"- **Decision**: {d['decision']}")
            parts.append(f"  **Reason**: {d['reason']}")
            parts.append(f"  *source: {d['source']}, iteration: {d.get('iteration', 0)}*")
    
    # 5. Format coverage strategies
    if strategies := session_memory.get("coverage_strategies", []):
        parts.append("\n## Coverage Optimization Strategies")
        for s in strategies[-5:]:  # Show only the most recent 5
            parts.append(f"- {s['strategy']}")
            parts.append(f"  *target: {s['target']}, source: {s['source']}*")
    
    if not parts:
        return "*No consensus constraints for this task yet*"
    
    return "\n".join(parts)


def consolidate_session_memory(state: FuzzingWorkflowState) -> Dict[str, Any]:
    """
    Consolidate and clean session_memory with deduplication and length limits.
    
    This function should be called in the Supervisor node to keep session_memory tidy.
    
    Args:
        state: Workflow state
    
    Returns:
        Cleaned session_memory
    """
    session_memory = state.get("session_memory", {}).copy()
    
    if not session_memory:
        return {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": []
        }
    
    # 1. Deduplicate API constraints
    if api_constraints := session_memory.get("api_constraints", []):
        # Deduplicate by constraint content, keep the one with highest confidence
        unique_constraints = {}
        for c in api_constraints:
            key = c["constraint"]
            if key not in unique_constraints:
                unique_constraints[key] = c
            elif c["confidence"] == "high" and unique_constraints[key]["confidence"] != "high":
                unique_constraints[key] = c
        session_memory["api_constraints"] = list(unique_constraints.values())
    
    # 2. Deduplicate known_fixes
    if known_fixes := session_memory.get("known_fixes", []):
        unique_fixes = {}
        for fix in known_fixes:
            key = fix["error_pattern"]
            unique_fixes[key] = fix  # Later ones override earlier ones
        session_memory["known_fixes"] = list(unique_fixes.values())[-10:]  # Keep only the most recent 10
    
    # 3. Limit decisions length
    if decisions := session_memory.get("decisions", []):
        session_memory["decisions"] = decisions[-10:]
    
    # 4. Deduplicate coverage_strategies
    if strategies := session_memory.get("coverage_strategies", []):
        unique_strategies = {}
        for s in strategies:
            key = s["strategy"]
            unique_strategies[key] = s
        session_memory["coverage_strategies"] = list(unique_strategies.values())[-10:]
    
    return session_memory
