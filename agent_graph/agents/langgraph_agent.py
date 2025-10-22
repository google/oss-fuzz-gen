"""
LangGraph-native agent base class.

This module provides a clean agent interface designed specifically for LangGraph,
without the legacy ADK/session baggage.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import argparse

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.memory import get_agent_messages, add_agent_message
from agent_graph.prompt_loader import get_prompt_manager
from agent_graph.agents.utils import parse_tag, parse_tags


class LangGraphAgent(ABC):
    """
    Base class for LangGraph-compatible agents.
    
    Key differences from ADKBaseAgent:
    - No session management (state-based)
    - Agent-specific message history
    - Direct LLM interaction
    - Cleaner interface
    """
    
    def __init__(
        self,
        name: str,
        llm: LLM,
        trial: int,
        args: argparse.Namespace,
        system_message: str = ""
    ):
        """
        Initialize a LangGraph agent.
        
        Args:
            name: Unique agent name (e.g., "function_analyzer")
            llm: LLM instance
            trial: Trial number
            args: Command line arguments
            system_message: System instruction for this agent
        """
        self.name = name
        self.llm = llm
        self.trial = trial
        self.args = args
        self.system_message = system_message
    
    def chat_llm(
        self,
        state: FuzzingWorkflowState,
        prompt: str
    ) -> str:
        """
        Chat with LLM using agent-specific message history.
        
        This method:
        1. Gets this agent's message history from state
        2. Adds the new prompt as a user message
        3. Calls LLM with the agent's messages
        4. Adds the response as an assistant message
        5. Trims messages to 50k tokens
        
        Args:
            state: The workflow state
            prompt: User prompt to send to LLM
        
        Returns:
            LLM response text
        """
        # Get this agent's messages (initializes with system message if first time)
        messages = get_agent_messages(state, self.name, self.system_message)
        
        # Add user prompt
        add_agent_message(state, self.name, "user", prompt)
        
        # Get updated messages for LLM call
        messages = state["agent_messages"][self.name]
        
        # Log the prompt
        logger.info(
            f'<AGENT {self.name} PROMPT>\n{prompt}\n</AGENT {self.name} PROMPT>',
            trial=self.trial
        )
        
        # Call LLM with this agent's messages only
        response = self.llm.chat_with_messages(messages)
        
        # Add assistant response
        add_agent_message(state, self.name, "assistant", response)
        
        # Log the response
        logger.info(
            f'<AGENT {self.name} RESPONSE>\n{response}\n</AGENT {self.name} RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    def ask_llm(self, prompt: str) -> str:
        """
        Ask LLM a one-off question without conversation history.
        
        This is useful for stateless queries that don't need context.
        
        Args:
            prompt: The question/prompt
        
        Returns:
            LLM response
        """
        messages = [{"role": "user", "content": prompt}]
        
        logger.info(
            f'<AGENT {self.name} ONEOFF>\n{prompt}\n</AGENT {self.name} ONEOFF>',
            trial=self.trial
        )
        
        response = self.llm.chat_with_messages(messages)
        
        logger.info(
            f'<AGENT {self.name} ONEOFF RESPONSE>\n{response}\n</AGENT {self.name} ONEOFF RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    @abstractmethod
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Execute the agent's main logic.
        
        Args:
            state: Current workflow state
        
        Returns:
            Dictionary of state updates
        """
        pass


class LangGraphFunctionAnalyzer(LangGraphAgent):
    """Function analyzer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("function_analyzer")
        
        super().__init__(
            name="function_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Analyze the target function."""
        import os
        benchmark = state["benchmark"]
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "function_analyzer",
            project_name=benchmark.get('project', 'unknown'),
            function_name=benchmark.get('function_name', 'unknown'),
            function_signature=benchmark.get('function_signature', 'unknown'),
            additional_context=""
        )
        
        # Chat with LLM
        response = self.chat_llm(state, prompt)
        
        # Parse response and create structured output
        # TODO: Add proper parsing logic
        analysis_result = {
            "summary": response[:500],  # First 500 chars as summary
            "raw_analysis": response,
            "analyzed": True
        }
        
        # Write requirements to file (matching original FunctionAnalyzer behavior)
        requirements_path = ""
        if response:
            try:
                # Get work_dirs from state
                work_dirs_dict = state.get("work_dirs", {})
                requirements_dir = work_dirs_dict.get("requirements", "")
                
                if requirements_dir:
                    os.makedirs(requirements_dir, exist_ok=True)
                    requirements_path = os.path.join(requirements_dir, f'{self.trial:02d}.txt')
                    
                    with open(requirements_path, 'w') as f:
                        f.write(response)
                    
                    logger.info(f'Requirements written to {requirements_path}', trial=self.trial)
                    analysis_result["requirements_path"] = requirements_path
            except Exception as e:
                logger.warning(f'Failed to write requirements file: {e}', trial=self.trial)
        
        return {
            "function_analysis": analysis_result
        }


class LangGraphPrototyper(LangGraphAgent):
    """Prototyper agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("prototyper")
        
        super().__init__(
            name="prototyper",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Generate fuzz target code."""
        benchmark = state["benchmark"]
        function_analysis = state.get("function_analysis", {})
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "prototyper",
            project_name=benchmark.get('project', 'unknown'),
            function_name=benchmark.get('function_name', 'unknown'),
            function_signature=benchmark.get('function_signature', 'unknown'),
            language=language,
            function_analysis=function_analysis.get('raw_analysis', 'No analysis available'),
            additional_context=""
        )
        
        # Chat with LLM (using prototyper's own message history)
        response = self.chat_llm(state, prompt)
        
        # Extract code from <fuzz target> tags
        fuzz_target_code = parse_tag(response, 'fuzz target')
        
        # If no tags found, use the whole response as fallback
        if not fuzz_target_code:
            fuzz_target_code = response
        
        return {
            "fuzz_target_source": fuzz_target_code,
            "compile_success": None,  # Reset to trigger build
            "retry_count": 0  # Reset retry count for new target
        }


class LangGraphEnhancer(LangGraphAgent):
    """Enhancer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("enhancer")
        
        super().__init__(
            name="enhancer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Fix compilation errors."""
        benchmark = state["benchmark"]
        current_code = state.get("fuzz_target_source", "")
        build_errors = state.get("build_errors", [])
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Format build errors
        error_text = "\n".join(build_errors[:10])
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "enhancer",
            language=language,
            current_code=current_code,
            build_errors=error_text,
            additional_context=""
        )
        
        # Chat with LLM (using enhancer's own message history)
        response = self.chat_llm(state, prompt)
        
        # Extract code from <fuzz target> tags
        fuzz_target_code = parse_tag(response, 'fuzz target')
        
        # If no tags found, use the whole response as fallback
        if not fuzz_target_code:
            fuzz_target_code = response
        
        return {
            "fuzz_target_source": fuzz_target_code,
            "retry_count": state.get("retry_count", 0) + 1,
            "compile_success": None,  # Reset to trigger rebuild
            "build_errors": []  # Clear previous errors
        }


class LangGraphCrashAnalyzer(LangGraphAgent):
    """Crash analyzer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("crash_analyzer")
        
        super().__init__(
            name="crash_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Analyze crash information."""
        benchmark = state["benchmark"]
        crash_info = state.get("crash_info", {})
        fuzz_target = state.get("fuzz_target_source", "")
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "crash_analyzer",
            crash_info=crash_info.get('error_message', 'No error message'),
            stack_trace=crash_info.get('stack_trace', 'No stack trace'),
            language=language,
            fuzz_target_code=fuzz_target[:1000],
            additional_context=""
        )
        
        # Chat with LLM (using crash_analyzer's own message history)
        response = self.chat_llm(state, prompt)
        
        return {
            "crash_analysis": {
                "root_cause": response,
                "severity": "high",
                "analyzed": True
            }
        }


class LangGraphCoverageAnalyzer(LangGraphAgent):
    """
    Coverage analyzer agent for LangGraph.
    
    This agent follows the original CoverageAnalyzer's approach:
    - Uses ProjectContainerTool for bash command execution
    - Multi-round interaction until conclusion is reached
    - Parses insights, suggestions, and conclusion tags
    """
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        super().__init__(
            name="coverage_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=""  # Will use prompt builder instead
        )
        self.inspect_tool = None
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze coverage to understand why it's low and provide insights.
        
        Following the original CoverageAnalyzer logic from coverage_analyzer.py.
        """
        from llm_toolkit import prompt_builder
        from llm_toolkit.prompt_builder import CoverageAnalyzerTemplateBuilder
        from tool.container_tool import ProjectContainerTool
        from experiment.workdir import WorkDirs
        from experiment import benchmark as benchmarklib
        
        # Get benchmark object (need to convert from dict)
        benchmark_dict = state["benchmark"]
        benchmark = benchmarklib.Benchmark.from_dict(benchmark_dict)
        
        fuzz_target_source = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        
        # Initialize inspect_tool with the fuzz target and build script
        self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
        self.inspect_tool.write_to_file(content=fuzz_target_source,
                                       file_path=benchmark.target_path)
        if build_script_source:
            self.inspect_tool.write_to_file(
                content=build_script_source,
                file_path=self.inspect_tool.build_script_path)
        self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
        
        # Get function requirements
        function_requirements = self._get_function_requirements(state)
        
        # Build initial prompt using the original template builder
        builder = CoverageAnalyzerTemplateBuilder(
            self.llm, 
            benchmark,
            None  # We'll pass coverage data through state
        )
        
        # Create a mock RunResult-like object for the builder
        class CoverageData:
            def __init__(self, state_data):
                self.coverage_summary = state_data.get("coverage_summary", "")
                self.coverage_percent = state_data.get("coverage_percent", 0.0)
                self.line_coverage_diff = state_data.get("line_coverage_diff", 0.0)
                self.cov_pcs = state_data.get("cov_pcs", 0)
                self.total_pcs = state_data.get("total_pcs", 0)
        
        coverage_data = CoverageData(state)
        builder_with_data = CoverageAnalyzerTemplateBuilder(
            self.llm, benchmark, coverage_data
        )
        
        prompt = builder_with_data.build(
            example_pair=[],
            tool_guides=self.inspect_tool.tutorial(),
            project_dir=self.inspect_tool.project_dir,
            function_requirements=function_requirements
        )
        
        # Multi-round interaction
        coverage_result = {}
        cur_round = 0
        max_round = self.args.max_round
        
        try:
            client = self.llm.get_chat_client(model=self.llm.get_model())
            while prompt and prompt.get() and cur_round < max_round:
                # Chat with LLM
                response = self.llm.chat_llm(client=client, prompt=prompt)
                
                # Log the interaction
                logger.info(
                    f'<COVERAGE ANALYZER ROUND {cur_round}>\n{response}\n</COVERAGE ANALYZER ROUND {cur_round}>',
                    trial=self.trial
                )
                
                # Handle the response
                prompt = self._handle_response(cur_round, response, coverage_result)
                cur_round += 1
                
        finally:
            # Cleanup container
            if self.inspect_tool:
                logger.debug(
                    'Stopping and removing inspect container',
                    trial=self.trial
                )
                self.inspect_tool.terminate()
        
        return {
            "coverage_analysis": coverage_result
        }
    
    def _get_function_requirements(self, state: FuzzingWorkflowState) -> str:
        """Get function requirements from previous analysis."""
        import os
        
        # Try to read from requirements file
        work_dirs_dict = state.get("work_dirs", {})
        requirements_dir = work_dirs_dict.get("requirements", "")
        
        if requirements_dir and os.path.isdir(requirements_dir):
            requirements_path = os.path.join(requirements_dir, f'{self.trial:02d}.txt')
            if os.path.exists(requirements_path):
                with open(requirements_path, 'r') as f:
                    return f.read()
        
        # Fallback to state
        function_analysis = state.get("function_analysis", {})
        return function_analysis.get("raw_analysis", "")
    
    def _handle_response(
        self, 
        cur_round: int, 
        response: str, 
        coverage_result: Dict[str, Any]
    ) -> Optional[Any]:
        """
        Handle LLM response - execute bash commands or extract conclusion.
        
        This follows the original _container_tool_reaction logic.
        """
        from llm_toolkit import prompt_builder
        
        prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])
        
        # First, try to handle bash commands
        prompt = self._handle_bash_commands(response, prompt)
        
        # If no bash commands were executed, check for conclusion
        if not prompt.gettext():
            conclusion = parse_tag(response, 'conclusion')
            if conclusion:
                logger.info(
                    f'----- ROUND {cur_round:02d} Received conclusion -----',
                    trial=self.trial
                )
                coverage_result['improve_required'] = conclusion.strip().lower() == 'true'
                coverage_result['insights'] = parse_tag(response, 'insights') or ""
                coverage_result['suggestions'] = parse_tag(response, 'suggestions') or ""
                coverage_result['analyzed'] = True
                return None  # Done
            else:
                # No conclusion yet, prompt is still empty
                prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])
        
        # Check for invalid responses
        if not response or not prompt.get():
            prompt.append('No valid instruction received. Please follow the '
                         'interaction protocols for available tools:\n\n')
            prompt.append(f'{self.inspect_tool.tutorial()}\n\n')
        
        return prompt
    
    def _handle_bash_commands(self, response: str, prompt: Any) -> Any:
        """Execute bash commands from LLM response."""
        for command in parse_tags(response, 'bash'):
            result = self.inspect_tool.execute(command)
            prompt_text = self._format_bash_result(result, prompt)
            prompt.append(prompt_text)
        return prompt
    
    def _format_bash_result(self, process, previous_prompt=None) -> str:
        """Format bash execution result."""
        if previous_prompt:
            previous_prompt_text = previous_prompt.gettext()
        else:
            previous_prompt_text = ''
        stdout = self.llm.truncate_prompt(process.stdout, previous_prompt_text).strip()
        stderr = self.llm.truncate_prompt(
            process.stderr, 
            stdout + previous_prompt_text
        ).strip()
        return (f'<bash>\n{process.args}\n</bash>\n'
                f'<return code>\n{process.returncode}\n</return code>\n'
                f'<stdout>\n{stdout}\n</stdout>\n'
                f'<stderr>\n{stderr}\n</stderr>\n')


class LangGraphContextAnalyzer(LangGraphAgent):
    """
    Context analyzer agent for LangGraph - analyzes crash feasibility.
    
    This agent follows the original ContextAnalyzer's approach:
    - Uses ADK-style tools (but implemented for LangGraph)
    - Tools: get_function_implementation, search_project_files, report_final_result
    - Multi-round interaction until final result is reported
    """
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        super().__init__(
            name="context_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=""  # Will use prompt builder instead
        )
        self.inspect_tool = None
        self.project_functions = None
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze crash feasibility by examining project context.
        
        Following the original ContextAnalyzer logic from context_analyzer.py.
        Uses ADK-style tool functions that LLM can call.
        """
        from llm_toolkit import prompt_builder
        from llm_toolkit.prompt_builder import ContextAnalyzerTemplateBuilder
        from tool.container_tool import ProjectContainerTool
        from experiment.workdir import WorkDirs
        from experiment import benchmark as benchmarklib
        from data_prep import introspector
        
        # Get benchmark object
        benchmark_dict = state["benchmark"]
        benchmark = benchmarklib.Benchmark.from_dict(benchmark_dict)
        
        # Validate that we have crash analysis result
        crash_analysis = state.get("crash_analysis", {})
        if not crash_analysis:
            logger.error('No crash_analysis in state', trial=self.trial)
            return {"errors": [{"message": "No crash analysis found"}]}
        
        # Initialize inspect_tool for project file search
        self.inspect_tool = ProjectContainerTool(benchmark)
        self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
        
        # Get function requirements
        function_requirements = self._get_function_requirements(state)
        
        # Build initial prompt using the original template builder
        builder = ContextAnalyzerTemplateBuilder(self.llm, benchmark)
        
        # Create a mock AnalysisResult for the builder
        class MockAnalysisResult:
            def __init__(self, state_data):
                self.crash_result = type('obj', (object,), {
                    'stacktrace': state_data.get('crash_info', {}).get('stack_trace', ''),
                    'true_bug': True  # We don't know yet
                })()
        
        mock_result = MockAnalysisResult(state)
        prompt = builder.build_context_analysis_prompt(
            mock_result,
            function_requirements,
            self.inspect_tool.tutorial(),
            self.inspect_tool.project_dir
        )
        
        # Multi-round interaction - simulating ADK tool calling
        context_result = None
        cur_round = 0
        max_round = self.args.max_round
        
        try:
            while cur_round < max_round:
                # Chat with LLM
                client = None  # ADK agents use None for client
                response = self.llm.ask_llm(prompt=prompt)
                
                # Log the interaction
                logger.info(
                    f'<CONTEXT ANALYZER ROUND {cur_round}>\n{response}\n</CONTEXT ANALYZER ROUND {cur_round}>',
                    trial=self.trial
                )
                
                # Try to parse result from response (simulating report_final_result tool)
                context_result = self._try_parse_final_result(response)
                if context_result:
                    break
                
                # Handle tool calls (bash commands)
                prompt = self._handle_tool_calls(response, prompt)
                
                if not prompt or not prompt.get():
                    # Invalid response, ask for correction
                    prompt = self._handle_invalid_response(response, builder)
                
                cur_round += 1
                
        finally:
            # Cleanup container
            if self.inspect_tool:
                logger.debug(
                    'Stopping and removing inspect container',
                    trial=self.trial
                )
                self.inspect_tool.terminate()
        
        if not context_result:
            context_result = {
                "feasible": False,
                "analysis": "Analysis incomplete",
                "source_code_evidence": "",
                "recommendations": "",
                "analyzed": False
            }
        
        return {
            "context_analysis": context_result
        }
    
    def _get_function_requirements(self, state: FuzzingWorkflowState) -> str:
        """Get function requirements from previous analysis."""
        import os
        
        # Try to read from requirements file
        work_dirs_dict = state.get("work_dirs", {})
        requirements_dir = work_dirs_dict.get("requirements", "")
        
        if requirements_dir and os.path.isdir(requirements_dir):
            requirements_path = os.path.join(requirements_dir, f'{self.trial:02d}.txt')
            if os.path.exists(requirements_path):
                with open(requirements_path, 'r') as f:
                    return f.read()
        
        # Fallback to state
        function_analysis = state.get("function_analysis", {})
        return function_analysis.get("raw_analysis", "")
    
    def _try_parse_final_result(self, response: str) -> Optional[Dict[str, Any]]:
        """
        Try to parse final result from response.
        
        Looks for structured output similar to report_final_result tool.
        """
        # Look for the structured result tags
        feasible_str = parse_tag(response, 'feasible')
        analysis = parse_tag(response, 'analysis')
        evidence = parse_tag(response, 'source_code_evidence')
        recommendations = parse_tag(response, 'recommendations')
        
        # Only consider it a final result if we have the key fields
        if feasible_str and analysis:
            return {
                "feasible": feasible_str.strip().lower() in ['true', 'yes', '1'],
                "analysis": analysis,
                "source_code_evidence": evidence,
                "recommendations": recommendations,
                "analyzed": True
            }
        
        return None
    
    def _handle_tool_calls(self, response: str, prompt: Any) -> Any:
        """
        Handle tool calls from LLM response.
        
        Simulates ADK tools: search_project_files, get_function_implementation
        """
        from llm_toolkit import prompt_builder
        
        new_prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])
        
        # Handle bash commands for search_project_files
        bash_commands = parse_tags(response, 'bash')
        if bash_commands:
            for command in bash_commands:
                result = self.inspect_tool.execute(command)
                prompt_text = self._format_bash_result(result, prompt)
                new_prompt.append(prompt_text)
            return new_prompt
        
        # Handle get_function_implementation requests
        # Look for patterns like "get_function_implementation(project, function)"
        func_impl_match = parse_tag(response, 'get_function_implementation')
        if func_impl_match:
            # Parse project and function names from the request
            impl_response = self._get_function_implementation_from_text(func_impl_match)
            new_prompt.append(impl_response)
            return new_prompt
        
        return new_prompt
    
    def _get_function_implementation_from_text(self, request: str) -> str:
        """
        Get function implementation from introspector.
        
        This simulates the get_function_implementation tool.
        """
        from data_prep import introspector
        import re
        
        # Try to extract project and function names
        # Simple pattern matching - might need refinement
        match = re.search(r'project[:\s]+(\w+).*?function[:\s]+(\w+)', request, re.IGNORECASE | re.DOTALL)
        if not match:
            return "Error: Could not parse project and function names from request"
        
        project_name = match.group(1)
        function_name = match.group(2)
        
        # Initialize project functions if needed
        if self.project_functions is None:
            logger.info(
                f'Initializing project functions for "{project_name}"',
                trial=self.trial
            )
            functions_list = introspector.query_introspector_all_functions(project_name)
            
            if functions_list:
                self.project_functions = {
                    func['debug_summary']['name']: func
                    for func in functions_list
                    if isinstance(func.get('debug_summary'), dict) and
                    isinstance(func['debug_summary'].get('name'), str) and
                    func['debug_summary']['name'].strip()
                }
            else:
                self.project_functions = {}
        
        # Get function source
        response = f"Project name: {project_name}\nFunction name: {function_name}\n"
        function_source = ''
        
        if self.project_functions:
            function_dict = self.project_functions.get(function_name, {})
            function_signature = function_dict.get('function_signature', '')
            
            function_source = introspector.query_introspector_function_source(
                project_name, function_signature
            )
        
        if function_source.strip():
            response += f"\nFunction source code:\n{function_source}\n"
        else:
            response += f'\nError: Function "{function_name}" not found in project "{project_name}"\n'
        
        return response
    
    def _handle_invalid_response(self, response: str, builder: Any) -> Any:
        """Handle invalid LLM response."""
        from llm_toolkit import prompt_builder
        
        logger.warning(f'Invalid response from LLM: {response[:200]}...', trial=self.trial)
        
        prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])
        prompt.append('No valid instruction received. Please follow the interaction protocols.\n\n')
        prompt.append(self.inspect_tool.tutorial())
        prompt.append('\n\n')
        prompt.append(builder.get_response_format().get() if hasattr(builder, 'get_response_format') else '')
        
        return prompt
    
    def _format_bash_result(self, process, previous_prompt=None) -> str:
        """Format bash execution result."""
        if previous_prompt:
            previous_prompt_text = previous_prompt.gettext()
        else:
            previous_prompt_text = ''
        stdout = self.llm.truncate_prompt(process.stdout, previous_prompt_text).strip()
        stderr = self.llm.truncate_prompt(
            process.stderr, 
            stdout + previous_prompt_text
        ).strip()
        return (f'<bash>\n{process.args}\n</bash>\n'
                f'<return code>\n{process.returncode}\n</return code>\n'
                f'<stdout>\n{stdout}\n</stdout>\n'
                f'<stderr>\n{stderr}\n</stderr>\n')

