"""Main LangGraph workflow implementation for fuzzing."""

import argparse
from typing import Dict, Any

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from agent_graph.state import FuzzingWorkflowState, create_initial_state
from agent_graph.adapters import ConfigAdapter
from agent_graph.nodes import (
    function_analyzer_node,
    prototyper_node,
    enhancer_node,
    crash_analyzer_node,
    execution_node,
    build_node,
    supervisor_node,
    route_condition
)
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from llm_toolkit.models import LLM
from agent_graph.memory import create_memory_checkpointer

class FuzzingWorkflow:
    """
    Main fuzzing workflow class that manages the LangGraph execution.
    
    This class provides a high-level interface for running the fuzzing workflow
    with proper configuration and state management.
    """
    
    def __init__(self, llm: LLM, args: argparse.Namespace, 
                 use_checkpointer: bool = True, shared_data: dict = None):
        """
        Initialize the fuzzing workflow.
        
        Args:
            llm: LLM instance for agents
            args: Command line arguments
            use_checkpointer: Whether to use memory checkpointer for persistence
            shared_data: Pre-fetched shared data (optional, for optimization)
                        Contains: source_code, api_context, api_dependencies, 
                                 header_info, existing_fuzzer_headers
        """
        self.llm = llm
        self.args = args
        self.workflow_graph = None
        self.config = ConfigAdapter.create_config(llm, args)
        self.shared_data = shared_data  # Store for agents to access
        
        # Create memory checkpointer for conversation persistence
        self.checkpointer = create_memory_checkpointer() if use_checkpointer else None
    
    def create_workflow(self, workflow_type: str = "full") -> StateGraph:
        """
        Create the workflow graph.
        
        Args:
            workflow_type: Type of workflow ("full", "simple", "test")
            
        Returns:
            Configured LangGraph StateGraph
        """
        if workflow_type == "simple":
            self.workflow_graph = self._create_simple_workflow()
        elif workflow_type == "test":
            self.workflow_graph = self._create_test_workflow()
        else:
            self.workflow_graph = self._create_full_workflow()
        
        return self.workflow_graph
    
    def run(self, benchmark: Benchmark, trial: int, 
            workflow_type: str = "full") -> Dict[str, Any]:
        """
        Run the fuzzing workflow for a benchmark.
        
        Args:
            benchmark: Benchmark to process
            trial: Trial number
            workflow_type: Type of workflow to run
            
        Returns:
            Final workflow state
        """
        import logger
        import time
        
        logger.info('📍 [workflow.run] Entry point', trial=trial)
        
        # Create workflow if not already created
        if not self.workflow_graph:
            logger.info('📍 [workflow.run] Creating workflow graph...', trial=trial)
            self.create_workflow(workflow_type)
            logger.info('📍 [workflow.run] Workflow graph created', trial=trial)
        
        # Create initial state (objects will be converted internally)
        logger.info('📍 [workflow.run] Creating initial state...', trial=trial)
        initial_state = create_initial_state(
            benchmark=benchmark,
            trial=trial,
            work_dirs=self.args.work_dirs
        )
        
        # Inject shared_data into state if available
        if self.shared_data:
            initial_state['shared_data'] = self.shared_data
            logger.info('📍 [workflow.run] Shared data injected into state', trial=trial)
        else:
            logger.info('📍 [workflow.run] No shared data to inject', trial=trial)
        
        logger.info('📍 [workflow.run] Initial state created', trial=trial)
        
        # Compile and run the workflow with checkpointer
        compile_kwargs = {}
        if self.checkpointer:
            compile_kwargs['checkpointer'] = self.checkpointer
            logger.info('📍 [workflow.run] Using memory checkpointer', trial=trial)
        
        logger.info('📍 [workflow.run] Compiling workflow...', trial=trial)
        compile_start = time.time()
        compiled_workflow = self.workflow_graph.compile(**compile_kwargs)
        compile_duration = time.time() - compile_start
        logger.info(f'📍 [workflow.run] Workflow compiled in {compile_duration:.2f}s', trial=trial)
        
        # Execute the workflow with configurable parameters
        # Use thread_id for conversation persistence
        config = {
            "configurable": {
                "llm": self.llm,
                "args": self.args,
                "thread_id": f"{benchmark.id}_trial_{trial}",
                "shared_data": self.shared_data  # Pass shared data to agents
            },
            "recursion_limit": getattr(self.args, 'max_iterations', 5) * 10  # Allow enough cycles
        }
        
        logger.info('📍 [workflow.run] Starting workflow.invoke()...', trial=trial)
        logger.info(f'📍 [workflow.run]   Recursion limit: {config["recursion_limit"]}', trial=trial)
        
        try:
            invoke_start = time.time()
            final_state = compiled_workflow.invoke(initial_state, config=config)
            invoke_duration = time.time() - invoke_start
            logger.info(f'📍 [workflow.run] Workflow.invoke() completed in {invoke_duration:.2f}s', trial=trial)
        except Exception as e:
            import logger
            logger.error(f"Workflow execution failed: {e}", trial=trial)
            logger.error("Returning partial state with error information", trial=trial)
            
            # Try to get the last state from checkpointer if available
            if self.checkpointer:
                try:
                    # Get the last checkpoint
                    from langgraph.checkpoint.base import CheckpointTuple
                    config_for_checkpoint = {
                        "configurable": {"thread_id": f"{benchmark.id}_trial_{trial}"}
                    }
                    checkpoint_tuple = self.checkpointer.get_tuple(config_for_checkpoint)
                    if checkpoint_tuple and checkpoint_tuple.checkpoint:
                        final_state = checkpoint_tuple.checkpoint.get('channel_values', initial_state)
                        logger.info("Retrieved partial state from checkpointer", trial=trial)
                    else:
                        final_state = initial_state.copy()
                except Exception as checkpoint_err:
                    logger.warning(f"Failed to retrieve checkpoint: {checkpoint_err}", trial=trial)
                    final_state = initial_state.copy()
            else:
                final_state = initial_state.copy()
            
            # Add error information to the state
            if 'errors' not in final_state:
                final_state['errors'] = []
            final_state['errors'].append({
                'node': 'workflow',
                'message': str(e),
                'type': type(e).__name__,
                'fatal': True
            })
            final_state['termination_reason'] = 'fatal_error'
            
            # Re-raise if it's a keyboard interrupt
            if isinstance(e, KeyboardInterrupt):
                raise
        
        # Print token usage summary at the end
        logger.info('📍 [workflow.run] Getting token usage summary...', trial=trial)
        from agent_graph.state import get_token_usage_summary
        token_summary = get_token_usage_summary(final_state)
        logger.info(f"\n{token_summary}", trial=trial)
        logger.info('📍 [workflow.run] Token usage summary printed', trial=trial)
        
        # Finalize all agent logs before returning
        logger.info('📍 [workflow.run] Starting logger finalization...', trial=trial)
        from agent_graph.logger import LangGraphLogger
        workflow_logger = LangGraphLogger.get_logger(
            workflow_id="fuzzing_workflow", 
            trial=trial, 
            base_dir=str(self.args.work_dirs.base) if hasattr(self.args, 'work_dirs') and self.args.work_dirs else None
        )
        logger.info('📍 [workflow.run] Got workflow logger instance', trial=trial)
        
        finalize_start = time.time()
        logger.info('📍 [workflow.run] Calling workflow_logger.finalize()...', trial=trial)
        workflow_logger.finalize()
        finalize_duration = time.time() - finalize_start
        logger.info(f'📍 [workflow.run] Logger finalized in {finalize_duration:.2f}s', trial=trial)
        
        logger.info('📍 [workflow.run] Returning final_state', trial=trial)
        return final_state
    
    def _create_full_workflow(self) -> StateGraph:
        """Create the full supervisor-based workflow."""
        from agent_graph.nodes.coverage_analyzer_node import coverage_analyzer_node
        from agent_graph.nodes.context_analyzer_node import context_analyzer_node
        from agent_graph.nodes.improver_node import improver_node
        
        workflow = StateGraph(FuzzingWorkflowState)
        
        # Add all nodes
        workflow.add_node("supervisor", supervisor_node)
        workflow.add_node("function_analyzer", function_analyzer_node)
        workflow.add_node("prototyper", prototyper_node)
        workflow.add_node("enhancer", enhancer_node)
        workflow.add_node("improver", improver_node)
        workflow.add_node("build", build_node)
        workflow.add_node("execution", execution_node)
        workflow.add_node("crash_analyzer", crash_analyzer_node)
        workflow.add_node("coverage_analyzer", coverage_analyzer_node)
        workflow.add_node("context_analyzer", context_analyzer_node)
        
        # Set entry point
        workflow.set_entry_point("supervisor")
        
        # Add conditional edges from supervisor
        workflow.add_conditional_edges(
            "supervisor",
            route_condition,
            {
                "function_analyzer": "function_analyzer",
                "prototyper": "prototyper",
                "enhancer": "enhancer",
                "improver": "improver",
                "build": "build",
                "execution": "execution",
                "crash_analyzer": "crash_analyzer",
                "coverage_analyzer": "coverage_analyzer",
                "context_analyzer": "context_analyzer",
                "__end__": END
            }
        )
        
        # Add edges back to supervisor from all nodes
        workflow.add_edge("function_analyzer", "supervisor")
        workflow.add_edge("prototyper", "supervisor")
        workflow.add_edge("enhancer", "supervisor")
        workflow.add_edge("improver", "supervisor")
        workflow.add_edge("build", "supervisor")
        workflow.add_edge("execution", "supervisor")
        workflow.add_edge("crash_analyzer", "supervisor")
        workflow.add_edge("coverage_analyzer", "supervisor")
        workflow.add_edge("context_analyzer", "supervisor")
        
        return workflow
    
    def _create_simple_workflow(self) -> StateGraph:
        """Create a simple linear workflow for basic testing."""
        workflow = StateGraph(FuzzingWorkflowState)
        
        # Add nodes
        workflow.add_node("function_analyzer", function_analyzer_node)
        workflow.add_node("prototyper", prototyper_node)
        workflow.add_node("build", build_node)
        
        # Set entry point
        workflow.set_entry_point("function_analyzer")
        
        # Add linear edges
        workflow.add_edge("function_analyzer", "prototyper")
        workflow.add_edge("prototyper", "build")
        workflow.add_edge("build", END)
        
        return workflow
    
    def _create_test_workflow(self) -> StateGraph:
        """Create a minimal workflow for unit testing."""
        workflow = StateGraph(FuzzingWorkflowState)
        
        # Add only function analyzer for testing
        workflow.add_node("function_analyzer", function_analyzer_node)
        
        # Set entry and exit
        workflow.set_entry_point("function_analyzer")
        workflow.add_edge("function_analyzer", END)
        
        return workflow

def create_fuzzing_workflow() -> StateGraph:
    """
    Create the main fuzzing workflow graph.
    
    This is a convenience function for backward compatibility.
    
    Returns:
        Configured LangGraph StateGraph for fuzzing workflow
    """
    workflow = StateGraph(FuzzingWorkflowState)
    
    # Add nodes
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("function_analyzer", function_analyzer_node)
    workflow.add_node("prototyper", prototyper_node)
    workflow.add_node("enhancer", enhancer_node)
    workflow.add_node("build", build_node)
    workflow.add_node("execution", execution_node)
    workflow.add_node("crash_analyzer", crash_analyzer_node)
    
    # Set entry point
    workflow.set_entry_point("supervisor")
    
    # Add conditional edges from supervisor
    workflow.add_conditional_edges(
        "supervisor",
        route_condition,
        {
            "function_analyzer": "function_analyzer",
            "prototyper": "prototyper",
            "enhancer": "enhancer",
            "build": "build",
            "execution": "execution", 
            "crash_analyzer": "crash_analyzer",
            "__end__": END
        }
    )
    
    # Add edges back to supervisor from all nodes
    workflow.add_edge("function_analyzer", "supervisor")
    workflow.add_edge("prototyper", "supervisor")
    workflow.add_edge("enhancer", "supervisor")
    workflow.add_edge("build", "supervisor")
    workflow.add_edge("execution", "supervisor")
    workflow.add_edge("crash_analyzer", "supervisor")
    
    return workflow

def create_simple_workflow() -> StateGraph:
    """
    Create a simplified linear workflow for testing.
    
    Returns:
        Simple linear workflow: FunctionAnalyzer -> Prototyper -> Build
    """
    workflow = StateGraph(FuzzingWorkflowState)
    
    # Add nodes
    workflow.add_node("function_analyzer", function_analyzer_node)
    workflow.add_node("prototyper", prototyper_node)
    workflow.add_node("build", build_node)
    
    # Set entry point
    workflow.set_entry_point("function_analyzer")
    
    # Add linear edges
    workflow.add_edge("function_analyzer", "prototyper")
    workflow.add_edge("prototyper", "build")
    workflow.add_edge("build", END)
    
    return workflow
