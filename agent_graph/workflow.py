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
    
    def __init__(self, llm: LLM, args: argparse.Namespace, use_checkpointer: bool = True):
        """
        Initialize the fuzzing workflow.
        
        Args:
            llm: LLM instance for agents
            args: Command line arguments
            use_checkpointer: Whether to use memory checkpointer for persistence
        """
        self.llm = llm
        self.args = args
        self.workflow_graph = None
        self.config = ConfigAdapter.create_config(llm, args)
        
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
        # Create workflow if not already created
        if not self.workflow_graph:
            self.create_workflow(workflow_type)
        
        # Create initial state (objects will be converted internally)
        initial_state = create_initial_state(
            benchmark=benchmark,
            trial=trial,
            work_dirs=self.args.work_dirs
        )
        
        # Compile and run the workflow with checkpointer
        compile_kwargs = {}
        if self.checkpointer:
            compile_kwargs['checkpointer'] = self.checkpointer
        
        compiled_workflow = self.workflow_graph.compile(**compile_kwargs)
        
        # Execute the workflow with configurable parameters
        # Use thread_id for conversation persistence
        config = {
            "configurable": {
                "llm": self.llm,
                "args": self.args,
                "thread_id": f"{benchmark.id}_trial_{trial}"
            },
            "recursion_limit": getattr(self.args, 'max_iterations', 5) * 10  # Allow enough cycles
        }
        
        try:
            final_state = compiled_workflow.invoke(initial_state, config=config)
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
        from agent_graph.state import get_token_usage_summary
        import logger
        token_summary = get_token_usage_summary(final_state)
        logger.info(f"\n{token_summary}", trial=trial)
        
        return final_state
    
    def _create_full_workflow(self) -> StateGraph:
        """Create the full supervisor-based workflow."""
        from agent_graph.nodes.coverage_analyzer_node import coverage_analyzer_node
        from agent_graph.nodes.context_analyzer_node import context_analyzer_node
        
        workflow = StateGraph(FuzzingWorkflowState)
        
        # Add all nodes
        workflow.add_node("supervisor", supervisor_node)
        workflow.add_node("function_analyzer", function_analyzer_node)
        workflow.add_node("prototyper", prototyper_node)
        workflow.add_node("enhancer", enhancer_node)
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
