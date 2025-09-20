# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Main LangGraph workflow implementation for fuzzing."""

import argparse
from typing import Dict, Any

from langgraph.graph import StateGraph, END
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


class FuzzingWorkflow:
    """
    Main fuzzing workflow class that manages the LangGraph execution.
    
    This class provides a high-level interface for running the fuzzing workflow
    with proper configuration and state management.
    """
    
    def __init__(self, llm: LLM, args: argparse.Namespace):
        """
        Initialize the fuzzing workflow.
        
        Args:
            llm: LLM instance for agents
            args: Command line arguments
        """
        self.llm = llm
        self.args = args
        self.workflow_graph = None
        self.config = ConfigAdapter.create_config(llm, args)
    
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
        
        # Compile and run the workflow
        compiled_workflow = self.workflow_graph.compile()
        
        # Execute the workflow with configurable parameters
        final_state = compiled_workflow.invoke(
            initial_state,
            config={
                "configurable": {
                    "llm": self.llm,
                    "args": self.args
                }
            }
        )
        
        return final_state
    
    def _create_full_workflow(self) -> StateGraph:
        """Create the full supervisor-based workflow."""
        workflow = StateGraph(FuzzingWorkflowState)
        
        # Add all nodes
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
