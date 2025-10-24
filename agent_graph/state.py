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
        
        # Trim this agent's messages to 50k tokens
        result[agent_name] = trim_messages_by_tokens(
            combined,
            max_tokens=50000,  # Each agent gets 50k tokens
            keep_system=True
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
    workflow_status: NotRequired[str]  # Workflow status
    build_errors: NotRequired[List[str]]  # Build error list
    active_containers: NotRequired[List[str]]  # Active container list
    
    # === Token Usage Statistics ===
    token_usage: NotRequired[Dict[str, Any]]  # Token consumption statistics

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
