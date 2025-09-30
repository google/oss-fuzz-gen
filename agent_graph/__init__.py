"""
LangGraph-based multi-agent fuzzing workflow implementation.

This package provides a complete migration of the original agent-based
fuzzing system to LangGraph, maintaining full compatibility with existing
agents while adding dynamic workflow capabilities.

Key Components:
- adapters: Compatibility layer between LangGraph and original agents
- nodes: LangGraph node wrappers for original agents  
- state: Workflow state management
- workflow: Main workflow definitions
- tests: Migration validation tests

Usage:
    from agent_graph import FuzzingWorkflow
    
    workflow = FuzzingWorkflow(llm, args)
    result = workflow.run(benchmark, trial)
"""

from .workflow import FuzzingWorkflow, create_fuzzing_workflow, create_simple_workflow
from .state import FuzzingWorkflowState, create_initial_state
from .adapters import StateAdapter, AgentNodeWrapper, ConfigAdapter

__all__ = [
    'FuzzingWorkflow',
    'create_fuzzing_workflow', 
    'create_simple_workflow',
    'FuzzingWorkflowState',
    'create_initial_state',
    'StateAdapter',
    'AgentNodeWrapper',
    'ConfigAdapter',
]
