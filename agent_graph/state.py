"""State management for LangGraph-based fuzzing workflow."""

from typing_extensions import TypedDict, NotRequired, Annotated
from typing import List, Dict, Any, Optional
import operator

def add_messages(left: List[Dict[str, Any]], right: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Message reducer for combining message lists."""
    return left + right

class FuzzingWorkflowState(TypedDict):
    """
    LangGraph state schema for the fuzzing workflow.
    
    This state schema is designed to be compatible with the original
    Result object hierarchy while providing structure for LangGraph.
    """
    
    # === Core Information (Required) ===
    benchmark: Dict[str, Any]  # Serialized Benchmark object
    trial: int  # Trial number
    work_dirs: Dict[str, str]  # Serialized WorkDirs object
    
    # === Messages for LangGraph ===
    messages: Annotated[List[Dict[str, Any]], add_messages]
    
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
    
    # === Analysis Results (from Analyzers) ===
    analysis_complete: NotRequired[bool]
    crash_analysis: NotRequired[Dict[str, Any]]
    coverage_analysis: NotRequired[Dict[str, Any]]
    
    # === Workflow Control ===
    next_action: NotRequired[str]  # For supervisor routing
    retry_count: NotRequired[int]
    max_retries: NotRequired[int]
    
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
    benchmark,  # benchmarklib.Benchmark or Dict[str, Any]
    work_dirs,  # workdir.WorkDirs or Dict[str, str] 
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
    
    # Handle benchmark conversion
    if hasattr(benchmark, 'to_dict'):
        benchmark_dict = benchmark.to_dict()
    elif isinstance(benchmark, dict):
        benchmark_dict = benchmark
    else:
        # Convert benchmark object to dict manually
        benchmark_dict = {
            'id': getattr(benchmark, 'id', 'unknown'),
            'project': getattr(benchmark, 'project', 'unknown'),
            'function_name': getattr(benchmark, 'function_name', 'unknown'),
            'language': getattr(benchmark, 'language', 'c++'),
            'function_signature': getattr(benchmark, 'function_signature', ''),
            'target_path': getattr(benchmark, 'target_path', ''),
            'target_name': getattr(benchmark, 'target_name', ''),
            'use_context': use_context
        }
    
    # Handle work_dirs conversion
    if hasattr(work_dirs, 'to_dict'):
        work_dirs_dict = work_dirs.to_dict()
    elif isinstance(work_dirs, dict):
        work_dirs_dict = work_dirs
    else:
        # Convert work_dirs object to dict manually
        work_dirs_dict = {
            'base': getattr(work_dirs, 'base', ''),
            'fuzz_targets': getattr(work_dirs, 'fuzz_targets', ''),
            'status': getattr(work_dirs, 'status', '')
        }
    
    # Create initial message
    initial_message = {
        "role": "system",
        "content": f"Starting fuzzing workflow for {benchmark_dict.get('project', 'unknown project')} "
                  f"function {benchmark_dict.get('function_name', 'unknown function')} (trial {trial})"
    }
    
    # Add initial prompt if provided
    messages = [initial_message]
    if initial_prompt:
        messages.append({
            "role": "user",
            "content": initial_prompt
        })
    
    return FuzzingWorkflowState(
        benchmark=benchmark_dict,
        trial=trial,
        work_dirs=work_dirs_dict,
        messages=messages,
        current_iteration=0,
        max_iterations=max_round,
        workflow_status="initialized",
        errors=[],
        warnings=[],
        # Store additional configuration
        pipeline=pipeline or [],
        use_context=use_context,
        prompt_file=prompt_file,
        additional_files_path=additional_files_path,
        run_timeout=run_timeout,
        build_errors=[],
        crash_results=[],
        active_containers=[]
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
