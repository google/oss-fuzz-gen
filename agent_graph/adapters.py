"""
Adapter layer for migrating original agents to LangGraph.

This module provides the compatibility layer between LangGraph state management
and the original agent system's Result objects.
"""
import argparse
from typing import Dict, Any, List, Optional

from .workdir import LangGraphWorkDirs
from .benchmark import LangGraphBenchmark as Benchmark
from llm_toolkit.models import LLM
from results import (
    Result, BuildResult, RunResult, AnalysisResult, 
    FunctionAnalysisResult, CrashResult, CoverageResult
)
from agent_graph.state import FuzzingWorkflowState

class StateAdapter:
    """
    Adapter for converting between LangGraph state and Result objects.
    
    This is the core compatibility layer that allows original agents
    to work with LangGraph state management.
    """
    
    @staticmethod
    def state_to_result_history(state: FuzzingWorkflowState) -> List[Result]:
        """
        Convert LangGraph state to a Result history list that original agents expect.
        
        Args:
            state: Current LangGraph workflow state
            
        Returns:
            List of Result objects reconstructed from state
        """
        benchmark = Benchmark.from_dict(state["benchmark"])
        work_dirs = LangGraphWorkDirs.from_dict(state["work_dirs"])
        trial = state["trial"]
        
        result_history = []
        
        # Create base Result
        base_result = Result(
            benchmark=benchmark,
            trial=trial,
            work_dirs=work_dirs,
            fuzz_target_source=state.get("fuzz_target_source", ""),
            build_script_source=state.get("build_script_source", ""),
            function_analysis=StateAdapter._extract_function_analysis(state)
        )
        result_history.append(base_result)
        
        # Add BuildResult if build information exists
        if state.get("compile_success") is not None:
            build_result = BuildResult(
                benchmark=benchmark,
                trial=trial,
                work_dirs=work_dirs,
                fuzz_target_source=state.get("fuzz_target_source", ""),
                build_script_source=state.get("build_script_source", ""),
                compiles=state.get("compile_success", False),
                compile_error="\n".join(state.get("build_errors", [])),
                compile_log=state.get("compile_log", ""),
                binary_exists=state.get("binary_exists", False),
                is_function_referenced=state.get("is_function_referenced", False),
                function_analysis=StateAdapter._extract_function_analysis(state)
            )
            result_history.append(build_result)
        
        # Add RunResult if execution information exists
        if state.get("run_success") is not None:
            run_result = RunResult(
                benchmark=benchmark,
                trial=trial,
                work_dirs=work_dirs,
                fuzz_target_source=state.get("fuzz_target_source", ""),
                build_script_source=state.get("build_script_source", ""),
                compiles=state.get("compile_success", False),
                run_success=state.get("run_success", False),
                run_error=state.get("run_error", ""),
                run_log=state.get("run_log", ""),
                artifact_path=state.get("artifact_path", ""),
                crash_func=state.get("crash_func", ""),
                function_analysis=StateAdapter._extract_function_analysis(state)
            )
            result_history.append(run_result)
        
        # Add AnalysisResult if analysis information exists
        if state.get("analysis_complete"):
            analysis_result = AnalysisResult(
                benchmark=benchmark,
                trial=trial,
                work_dirs=work_dirs,
                fuzz_target_source=state.get("fuzz_target_source", ""),
                build_script_source=state.get("build_script_source", ""),
                compiles=state.get("compile_success", False),
                run_result=result_history[-1] if result_history else None,
                crash_result=StateAdapter._extract_crash_result(state, benchmark, trial, work_dirs),
                coverage_result=StateAdapter._extract_coverage_result(state, benchmark, trial, work_dirs),
                function_analysis=StateAdapter._extract_function_analysis(state)
            )
            result_history.append(analysis_result)
        
        return result_history
    
    @staticmethod
    def result_to_state_update(result: Result) -> Dict[str, Any]:
        """
        Convert a Result object to LangGraph state updates.
        
        Args:
            result: Result object from agent execution
            
        Returns:
            Dictionary of state updates for LangGraph
        """
        state_update = {}
        
        # Basic result information
        if hasattr(result, 'fuzz_target_source'):
            state_update["fuzz_target_source"] = result.fuzz_target_source
        if hasattr(result, 'build_script_source'):
            state_update["build_script_source"] = result.build_script_source
        
        # Function analysis information
        if hasattr(result, 'function_analysis') and result.function_analysis:
            fa = result.function_analysis
            state_update["function_analysis"] = {
                "description": fa.description,
                "function_signature": fa.function_signature,
                "project_name": fa.project_name,
                "requirements": fa.requirements,
                "function_analysis_path": getattr(fa, 'function_analysis_path', '')
            }
        
        # Build result information
        if isinstance(result, BuildResult):
            state_update.update({
                "compile_success": result.compiles,
                "build_errors": result.compile_error.split('\n') if result.compile_error else [],
                "compile_log": result.compile_log,
                "binary_exists": result.binary_exists,
                "is_function_referenced": result.is_function_referenced
            })
        
        # Run result information
        if isinstance(result, RunResult):
            state_update.update({
                "run_success": result.run_success,
                "run_error": result.run_error,
                "run_log": result.run_log,
                "artifact_path": result.artifact_path,
                "crash_func": result.crash_func
            })
        
        # Analysis result information
        if isinstance(result, AnalysisResult):
            state_update["analysis_complete"] = True
            
            if result.crash_result:
                cr = result.crash_result
                state_update["crash_analysis"] = {
                    "true_bug": cr.true_bug,
                    "insight": cr.insight,
                    "stacktrace": cr.stacktrace
                }
            
            if result.coverage_result:
                cov = result.coverage_result
                state_update["coverage_analysis"] = {
                    "coverage_summary": cov.coverage_summary,
                    "line_coverage_report": cov.line_coverage_report,
                    "function_coverage_report": cov.function_coverage_report,
                    "coverage_rate": cov.coverage_rate
                }
        
        # Add message about the completed operation
        if hasattr(result, 'author') and result.author:
            agent_name = result.author.name if hasattr(result.author, 'name') else str(result.author)
            state_update["messages"] = [{
                "role": "assistant", 
                "content": f"{agent_name} completed successfully"
            }]
        
        return state_update
    
    @staticmethod
    def _extract_function_analysis(state: FuzzingWorkflowState) -> Optional[FunctionAnalysisResult]:
        """Extract function analysis from state."""
        fa_data = state.get("function_analysis")
        if not fa_data:
            return None
        
        return FunctionAnalysisResult(
            description=fa_data.get("description", ""),
            function_signature=fa_data.get("function_signature", ""),
            project_name=fa_data.get("project_name", ""),
            requirements=fa_data.get("requirements", ""),
            function_analysis_path=fa_data.get("function_analysis_path", "")
        )
    
    @staticmethod
    def _extract_crash_result(state: FuzzingWorkflowState, benchmark: Benchmark, 
                             trial: int, work_dirs: LangGraphWorkDirs) -> Optional[CrashResult]:
        """Extract crash result from state."""
        crash_data = state.get("crash_analysis")
        if not crash_data:
            return None
        
        return CrashResult(
            benchmark=benchmark,
            trial=trial,
            work_dirs=work_dirs,
            true_bug=crash_data.get("true_bug", False),
            insight=crash_data.get("insight", ""),
            stacktrace=crash_data.get("stacktrace", ""),
            chat_history={}
        )
    
    @staticmethod
    def _extract_coverage_result(state: FuzzingWorkflowState, benchmark: Benchmark,
                                trial: int, work_dirs: LangGraphWorkDirs) -> Optional[CoverageResult]:
        """Extract coverage result from state."""
        cov_data = state.get("coverage_analysis")
        if not cov_data:
            return None
        
        return CoverageResult(
            benchmark=benchmark,
            trial=trial,
            work_dirs=work_dirs,
            coverage_summary=cov_data.get("coverage_summary", ""),
            line_coverage_report=cov_data.get("line_coverage_report", ""),
            function_coverage_report=cov_data.get("function_coverage_report", ""),
            coverage_rate=cov_data.get("coverage_rate", 0.0),
            chat_history={}
        )

class AgentNodeWrapper:
    """
    Wrapper that converts original agents into LangGraph-compatible node functions.
    
    This wrapper handles the interface conversion between LangGraph's state-based
    approach and the original agents' Result-based approach.
    """
    
    @staticmethod
    def create_agent_node(agent_class, **agent_kwargs):
        """
        Create a LangGraph node function from an original agent class.
        
        Args:
            agent_class: The original agent class (e.g., FunctionAnalyzer)
            **agent_kwargs: Additional arguments for agent initialization
            
        Returns:
            Function that can be used as a LangGraph node
        """
        def agent_node(state: FuzzingWorkflowState, config: Dict[str, Any]) -> Dict[str, Any]:
            """LangGraph node function that wraps the original agent."""
            try:
                # Extract configuration from LangGraph's configurable system
                configurable = config.get("configurable", {})
                llm = configurable["llm"]
                args = configurable["args"]
                benchmark = Benchmark.from_dict(state["benchmark"])
                trial = state["trial"]
                
                # Convert state to result history
                result_history = StateAdapter.state_to_result_history(state)
                
                # Create and execute the original agent
                if hasattr(agent_class, '__init__'):
                    # Check if agent needs benchmark parameter (ADKBaseAgent)
                    import inspect
                    init_signature = inspect.signature(agent_class.__init__)
                    if 'benchmark' in init_signature.parameters:
                        agent = agent_class(
                            trial=trial,
                            llm=llm,
                            args=args,
                            benchmark=benchmark,
                            **agent_kwargs
                        )
                    else:
                        agent = agent_class(
                            trial=trial,
                            llm=llm,
                            args=args,
                            **agent_kwargs
                        )
                else:
                    # Fallback for agents without explicit __init__
                    agent = agent_class(trial, llm, args, **agent_kwargs)
                
                # Execute the agent with the result history
                result = agent.execute(result_history)
                
                # Convert result back to state updates
                state_update = StateAdapter.result_to_state_update(result)
                
                return state_update
                
            except Exception as e:
                # Handle errors gracefully
                import logger
                logger.error(f'Error in {agent_class.__name__} node: {str(e)}', trial=state.get("trial", 0))
                return {
                    "errors": [{
                        "node": agent_class.__name__,
                        "message": str(e),
                        "type": type(e).__name__
                    }]
                }
        
        # Set function name for debugging
        agent_node.__name__ = f"{agent_class.__name__}_node"
        return agent_node

class ConfigAdapter:
    """
    Adapter for managing configuration objects needed by original agents.
    
    This handles the conversion between LangGraph's config system and 
    the original agents' parameter expectations.
    """
    
    @staticmethod
    def create_config(llm: LLM, args: argparse.Namespace, **kwargs) -> Dict[str, Any]:
        """
        Create a configuration dictionary for LangGraph nodes.
        
        Args:
            llm: The LLM instance
            args: Command line arguments
            **kwargs: Additional configuration parameters
            
        Returns:
            Configuration dictionary for LangGraph
        """
        config = {
            "llm": llm,
            "args": args,
            **kwargs
        }
        return config
    
    @staticmethod
    def extract_from_config(config: Dict[str, Any], key: str, default=None):
        """
        Safely extract a value from config dictionary.
        
        Args:
            config: Configuration dictionary
            key: Key to extract
            default: Default value if key not found
            
        Returns:
            Extracted value or default
        """
        return config.get(key, default)
