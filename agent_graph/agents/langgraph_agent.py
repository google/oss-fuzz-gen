"""
LangGraph-native agent base class.

This module provides a clean agent interface designed specifically for LangGraph,
without the legacy ADK/session baggage.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import argparse
import subprocess as sp

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
        
        # Track token usage
        if hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Add assistant response
        add_agent_message(state, self.name, "assistant", response)
        
        # Log the response
        logger.info(
            f'<AGENT {self.name} RESPONSE>\n{response}\n</AGENT {self.name} RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    def ask_llm(self, prompt: str, state: Optional[FuzzingWorkflowState] = None) -> str:
        """
        Ask LLM a one-off question without conversation history.
        
        This is useful for stateless queries that don't need context.
        
        Args:
            prompt: The question/prompt
            state: Optional state for tracking token usage
        
        Returns:
            LLM response
        """
        messages = [{"role": "user", "content": prompt}]
        
        logger.info(
            f'<AGENT {self.name} ONEOFF>\n{prompt}\n</AGENT {self.name} ONEOFF>',
            trial=self.trial
        )
        
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage if state is provided
        if state and hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
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
        
        # Configuration for iterative analysis
        self.max_examples = getattr(args, 'max_function_examples', 20)
        self.convergence_threshold = getattr(args, 'convergence_threshold', 3)
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Analyze the target function."""
        import os
        from data_prep import introspector
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
        benchmark = state["benchmark"]
        project_name = benchmark.get('project', 'unknown')
        function_signature = benchmark.get('function_signature', 'unknown')
        function_name = benchmark.get('function_name', 'unknown')
        
        # Query FuzzIntrospector for function source code
        logger.info(f'Querying FuzzIntrospector for source code of {function_signature}', trial=self.trial)
        func_source = introspector.query_introspector_function_source(
            project_name, function_signature
        )
        
        if not func_source:
            logger.warning(
                f'No source code found in FuzzIntrospector for project: {project_name}, '
                f'function: {function_signature}. Using fallback guidance.',
                trial=self.trial
            )
            # Provide a structured fallback that guides the LLM
            func_source = f"""// Source code not available in FuzzIntrospector database for:
// Function: {function_signature}
// Project: {project_name}
//
// NOTE: Please analyze this function conservatively based on:
// 1. The function signature and parameter types
// 2. Common patterns for similar functions in {project_name}
// 3. Standard practices for the involved data types
// 4. Typical constraints that real callers would respect
//
// Avoid making assumptions about internal implementation details.
// Focus on what can be inferred from the signature and common usage patterns."""
        else:
            logger.info(f'Source code found ({len(func_source)} chars)', trial=self.trial)
        
        # Use iterative analysis - LLM learns from examples through conversation
        logger.info('Using iterative analysis approach', trial=self.trial)
        response = self._execute_iterative_analysis(
            state, project_name, function_signature, function_name, func_source
        )
        
        # 从响应中提取session_memory更新（archetype、初始API约束等）
        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # 合并更新到session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        # Parse response and create structured output
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
            "function_analysis": analysis_result,
            "session_memory": updated_session_memory
        }
    
    def _execute_iterative_analysis(
        self,
        state: FuzzingWorkflowState,
        project_name: str,
        function_signature: str,
        function_name: str,
        func_source: str
    ) -> str:
        """
        Execute iterative analysis of the function using cross-reference examples.
        """
        from agent_graph.prompt_loader import get_prompt_manager
        from data_prep import introspector
        
        logger.info(f'Starting iterative analysis for {function_signature}', trial=self.trial)
        
        # Phase 1: Analyze the function itself to get basic understanding
        logger.info('Phase 1: Analyzing function source code', trial=self.trial)
        prompt_manager = get_prompt_manager()
        initial_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_initial",
            FUNCTION_SIGNATURE=function_signature,
            FUNCTION_SOURCE=func_source
        )
        initial_analysis = self.chat_llm(state, initial_prompt)
        logger.debug(f'Initial analysis: {initial_analysis[:200]}...', trial=self.trial)
        
        # Phase 2: Get call site metadata
        logger.info('Phase 2: Querying call sites metadata', trial=self.trial)
        call_sites = introspector.query_introspector_call_sites_metadata(project_name, function_signature)
        
        examples_analyzed = 0
        no_new_insight_count = 0
        
        if call_sites:
            logger.info(f'Found {len(call_sites)} call sites, processing up to {self.max_examples}', trial=self.trial)
            call_sites = call_sites[:self.max_examples]
            
            # Phase 3: Iteratively learn from usage examples
            for i, call_site in enumerate(call_sites, 1):
                logger.info(f'Processing example {i}/{len(call_sites)}', trial=self.trial)
                
                # Extract context
                context = self._extract_call_context(call_site, project_name)
                if not context:
                    logger.debug(f'Could not extract context for example {i}, skipping', trial=self.trial)
                    continue
                
                # Build prompt - LLM maintains context through conversation
                iteration_prompt = self._build_iteration_prompt(context, i, examples_analyzed)
                
                # Get LLM analysis
                try:
                    response = self.chat_llm(state, iteration_prompt)
                    examples_analyzed += 1
                    
                    # Simple heuristic: if response is very short, might indicate no new insights
                    if len(response.strip()) < 100:
                        no_new_insight_count += 1
                    else:
                        no_new_insight_count = 0
                    
                    logger.info(f'Example {i}: Analyzed (response length: {len(response)})', trial=self.trial)
                    
                except Exception as e:
                    logger.error(f'Error calling LLM for example {i}: {e}', trial=self.trial)
                    continue
                
                # Check convergence: stop if no new insights for N consecutive examples
                if no_new_insight_count >= self.convergence_threshold:
                    logger.info(
                        f'Converged after {examples_analyzed} examples '
                        f'({no_new_insight_count} consecutive examples without significant insights)',
            trial=self.trial
        )
                    break
        else:
            logger.warning(f'No call sites found for {function_signature}', trial=self.trial)
        
        # Phase 4: Generate final comprehensive analysis
        logger.info(f'Analysis complete. Generating final summary based on {examples_analyzed} examples', trial=self.trial)
        
        prompt_manager = get_prompt_manager()
        final_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_final_summary",
            PROJECT_NAME=project_name,
            FUNCTION_SIGNATURE=function_signature,
            EXAMPLES_COUNT=examples_analyzed
        )
        
        final_response = self.chat_llm(state, final_prompt)
        
        return final_response
    
    def _extract_call_context(
        self,
        call_site: dict,
        project: str,
        context_lines: int = 15
    ) -> Optional[dict]:
        """
        Extract the context around a function call without loading the entire caller function.
        
        This is much more token-efficient than loading full source code.
        """
        from data_prep import introspector
        
        src_func = call_site.get('src_func')
        if not src_func:
            logger.debug('Call site has no src_func, skipping', trial=self.trial)
            return None
        
        # Try to get the source code of the calling function
        caller_sig = introspector.query_introspector_function_signature(project, src_func)
        if not caller_sig:
            logger.debug(f'Could not get signature for caller function: {src_func}', trial=self.trial)
            return None
        
        # Get the full source of the calling function
        caller_source = introspector.query_introspector_function_source(project, caller_sig)
        if not caller_source:
            logger.debug(f'Could not get source for caller function: {caller_sig}', trial=self.trial)
            return None
        
        lines = caller_source.splitlines()
        
        # Try to find the call in the source code
        call_line_idx = self._find_call_in_source(lines, src_func)
        
        if call_line_idx is None:
            # Fallback: use the entire function but limit to first N lines
            logger.debug(f'Could not find exact call location, using function start', trial=self.trial)
            call_line_idx = min(10, len(lines) // 2)
        
        # Extract context
        start_idx = max(0, call_line_idx - context_lines)
        end_idx = min(len(lines), call_line_idx + context_lines + 1)
        
        context_before = '\n'.join(lines[start_idx:call_line_idx])
        call_statement = lines[call_line_idx] if call_line_idx < len(lines) else ''
        context_after = '\n'.join(lines[call_line_idx + 1:end_idx])
        
        # Extract parameter setup
        parameter_setup = self._extract_parameter_setup(lines, call_line_idx, call_statement)
        
        # Extract return value usage
        return_usage = self._extract_return_usage(lines, call_line_idx, call_statement)
        
        return {
            'caller_name': src_func,
            'caller_signature': caller_sig,
            'call_line_number': call_line_idx + 1,  # 1-indexed for display
            'context_before': context_before,
            'call_statement': call_statement,
            'context_after': context_after,
            'parameter_setup': parameter_setup,
            'return_usage': return_usage,
            'full_context': f"{context_before}\n{call_statement}\n{context_after}",
        }
    
    def _find_call_in_source(self, lines: List[str], func_name: str) -> Optional[int]:
        """Try to find where a function is called in the source code."""
        import re
        # Extract just the function name without namespaces/classes
        simple_name = func_name.split('::')[-1].split('.')[-1]
        
        for i, line in enumerate(lines):
            # Look for function call patterns
            if simple_name in line and '(' in line:
                return i
        
        return None
    
    def _extract_parameter_setup(self, lines: List[str], call_idx: int, call_stmt: str) -> str:
        """Extract code that sets up parameters for the call."""
        import re
        setup_lines = []
        
        # Try to find variable names in the call statement
        if '(' in call_stmt:
            param_part = call_stmt.split('(', 1)[1].split(')')[0]
            # Look for identifiers
            potential_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', param_part)
            
            # Search backwards for declarations of these variables
            for i in range(max(0, call_idx - 20), call_idx):
                line = lines[i]
                for var in potential_vars:
                    if var in line and ('=' in line or 'new' in line or 'malloc' in line):
                        setup_lines.append(f"Line {i+1}: {line.strip()}")
                        break
        
        return '\n'.join(setup_lines) if setup_lines else "No clear parameter setup found"
    
    def _extract_return_usage(self, lines: List[str], call_idx: int, call_stmt: str) -> str:
        """Extract code that uses the return value from the call."""
        usage_lines = []
        
        # Check if return value is assigned to a variable
        if '=' in call_stmt:
            var_name = call_stmt.split('=')[0].strip().split()[-1]
            
            # Search forward for usage of this variable
            for i in range(call_idx + 1, min(len(lines), call_idx + 20)):
                line = lines[i]
                if var_name in line:
                    usage_lines.append(f"Line {i+1}: {line.strip()}")
                    # Stop after finding a few uses
                    if len(usage_lines) >= 5:
                        break
        
        return '\n'.join(usage_lines) if usage_lines else "No clear return value usage found"
    
    def _build_iteration_prompt(
        self,
        context: dict,
        example_number: int,
        examples_analyzed: int
    ) -> str:
        """Build prompt for analyzing a single usage example using template file."""
        from agent_graph.prompt_loader import get_prompt_manager
        
        prompt_manager = get_prompt_manager()
        return prompt_manager.build_user_prompt(
            "function_analyzer_iteration",
            EXAMPLE_NUMBER=example_number,
            EXAMPLES_ANALYZED=examples_analyzed,
            CALLER_NAME=context.get('caller_name', 'unknown'),
            CALL_LINE_NUMBER=context.get('call_line_number', '?'),
            CONTEXT_BEFORE=context.get('context_before', ''),
            CALL_STATEMENT=context.get('call_statement', ''),
            CONTEXT_AFTER=context.get('context_after', ''),
            PARAMETER_SETUP=context.get('parameter_setup', 'N/A'),
            RETURN_USAGE=context.get('return_usage', 'N/A')
        )


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
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
        benchmark = state["benchmark"]
        function_analysis = state.get("function_analysis", {})
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Check if this is a regeneration (after compilation failures)
        is_regeneration = state.get("compile_success") == False and state.get("fuzz_target_source", "") != ""
        
        # Build base prompt from template file
        prompt_manager = get_prompt_manager()
        
        # If regenerating, add context about previous failures
        additional_context = ""
        if is_regeneration:
            build_errors = state.get("build_errors", [])
            if build_errors:
                additional_context = f"\n**Note**: Previous code generation failed to compile. Key errors:\n"
                additional_context += "\n".join(build_errors[:3])  # Show first 3 errors
                additional_context += "\n\nPlease generate a completely new approach that avoids these issues."
        
        base_prompt = prompt_manager.build_user_prompt(
            "prototyper",
            project_name=benchmark.get('project', 'unknown'),
            function_name=benchmark.get('function_name', 'unknown'),
            function_signature=benchmark.get('function_signature', 'unknown'),
            language=language,
            function_analysis=function_analysis.get('raw_analysis', 'No analysis available'),
            additional_context=additional_context
        )
        
        # 注入session_memory，让Prototyper能看到archetype和API约束
        prompt = build_prompt_with_session_memory(
            state,
            base_prompt,
            agent_name=self.name
        )
        
        # Chat with LLM (using prototyper's own message history)
        response = self.chat_llm(state, prompt)
        
        # 从响应中提取session_memory更新
        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # 合并更新到session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        # Extract code from <fuzz target> tags
        fuzz_target_code = parse_tag(response, 'fuzz target')
        
        # If no tags found, use the whole response as fallback
        if not fuzz_target_code:
            fuzz_target_code = response
        
        # Prepare state update
        state_update = {
            "fuzz_target_source": fuzz_target_code,
            "compile_success": None,  # Reset to trigger build
            "build_errors": [],  # Clear previous errors
            "retry_count": 0,  # Reset retry count for new target
            "session_memory": updated_session_memory  # ✅ 返回更新
        }
        
        # If this is a regeneration, update regeneration counter and reset compilation retry count
        if is_regeneration:
            prototyper_regenerate_count = state.get("prototyper_regenerate_count", 0)
            state_update["prototyper_regenerate_count"] = prototyper_regenerate_count + 1
            state_update["compilation_retry_count"] = 0  # Reset enhancer retry count
            logger.info(f'Prototyper regeneration #{prototyper_regenerate_count + 1}, '
                       f'resetting compilation_retry_count', trial=self.trial)
        
        return state_update


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
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
        benchmark = state["benchmark"]
        current_code = state.get("fuzz_target_source", "")
        previous_code = state.get("previous_fuzz_target_source", "")
        build_errors = state.get("build_errors", [])
        workflow_phase = state.get("workflow_phase", "compilation")
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Format build errors
        error_text = "\n".join(build_errors[:10])
        
        # Generate code context (diff or full code)
        code_context = self._generate_code_context(current_code, previous_code, build_errors)
        
        # Build base prompt from template file
        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "enhancer",
            language=language,
            current_code=code_context,  # Use context instead of full code
            build_errors=error_text,
            additional_context=""
        )
        
        # 注入session_memory，让Enhancer能看到所有共识约束
        prompt = build_prompt_with_session_memory(
            state,
            base_prompt,
            agent_name=self.name
        )
        
        # Chat with LLM (using enhancer's own message history)
        response = self.chat_llm(state, prompt)
        
        # 从响应中提取session_memory更新
        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # 合并更新到session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        # Extract code from <fuzz target> tags
        fuzz_target_code = parse_tag(response, 'fuzz target')
        
        # If no tags found, use the whole response as fallback
        if not fuzz_target_code:
            fuzz_target_code = response
        
        # Prepare state update
        state_update = {
            "fuzz_target_source": fuzz_target_code,
            "previous_fuzz_target_source": current_code,  # Save current as previous for next iteration
            "compile_success": None,  # Reset to trigger rebuild
            "build_errors": [],  # Clear previous errors
            "session_memory": updated_session_memory  # 更新session_memory
        }
        
        # Update counters based on workflow phase
        if workflow_phase == "compilation":
            # In compilation phase, update compilation_retry_count
            compilation_retry_count = state.get("compilation_retry_count", 0)
            state_update["compilation_retry_count"] = compilation_retry_count + 1
            logger.info(f'Compilation retry count: {compilation_retry_count + 1}', trial=self.trial)
        else:
            # In optimization phase, update regular retry_count
            retry_count = state.get("retry_count", 0)
            state_update["retry_count"] = retry_count + 1
        
        return state_update
    
    def _generate_code_context(self, current_code: str, previous_code: str, build_errors: list) -> str:
        """
        Generate code context for enhancer based on diff strategy.
        
        Strategy: Extract only the error-relevant parts of code to reduce token usage.
        
        Args:
            current_code: Current fuzz target code
            previous_code: Previous version (if any)
            build_errors: List of build errors
        
        Returns:
            Code context string (diff or relevant sections)
        """
        if not current_code:
            return ""
        
        # Extract line numbers from errors
        error_lines = set()
        for error in build_errors:
            # Parse error messages to extract line numbers
            # Common formats: "file.cpp:123:45: error", "line 123:", etc.
            import re
            matches = re.findall(r':(\d+):', error) or re.findall(r'line (\d+)', error)
            for match in matches:
                try:
                    line_num = int(match)
                    # Add context: ±10 lines around error
                    for i in range(max(1, line_num - 10), line_num + 11):
                        error_lines.add(i)
                except (ValueError, IndexError):
                    continue
        
        # If we have specific error lines, extract only those sections
        if error_lines:
            code_lines = current_code.split('\n')
            relevant_lines = []
            last_included = -100  # Track for adding "..."
            
            for line_num in sorted(error_lines):
                if line_num <= len(code_lines):
                    # Add "..." if there's a gap
                    if line_num - last_included > 1 and last_included != -100:
                        relevant_lines.append("// ... (lines omitted) ...")
                    
                    relevant_lines.append(f"/* Line {line_num} */ {code_lines[line_num - 1]}")
                    last_included = line_num
            
            if relevant_lines:
                context = "**Code sections relevant to errors:**\n```cpp\n" + "\n".join(relevant_lines) + "\n```"
                logger.debug(f'Extracted {len(relevant_lines)} relevant lines from {len(code_lines)} total lines', 
                            trial=self.trial)
                return context
        
        # Fallback: if no specific lines identified or code is small, return full code
        if len(current_code) < 5000:  # Less than ~5KB, just send it all
            return current_code
        
        # For large code without specific error lines, return first and last parts
        code_lines = current_code.split('\n')
        if len(code_lines) > 100:
            first_50 = '\n'.join(code_lines[:50])
            last_50 = '\n'.join(code_lines[-50:])
            return f"{first_50}\n\n// ... (middle section omitted) ...\n\n{last_50}"
        
        return current_code


class LangGraphCrashAnalyzer(LangGraphAgent):
    """
    Crash analyzer agent for LangGraph.
    
    This agent follows the original CrashAnalyzer's approach:
    - Uses GDBTool for interactive debugging
    - Uses ProjectContainerTool for bash commands
    - Multi-round interaction until conclusion is reached
    - Parses GDB commands, bash commands, and conclusion tags
    """
    
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
        self.gdb_tool = None
        self.bash_tool = None
        self.gdb_tool_used = False
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze crash using GDB and provide insights.
        
        First checks if this is a false positive (fuzz target bug), then 
        performs detailed analysis if it's a potential true bug.
        """
        import os
        import subprocess as sp
        from tool.container_tool import ProjectContainerTool
        from tool.gdb_tool import GDBTool
        from experiment.workdir import WorkDirs
        from experiment import benchmark as benchmarklib
        from experiment import evaluator as evaluator_lib
        from experiment import oss_fuzz_checkout
        
        # Get benchmark object
        benchmark_dict = state["benchmark"]
        benchmark = benchmarklib.Benchmark.from_dict(benchmark_dict)
        
        # Get crash info and source
        crash_info = state.get("crash_info", {})
        fuzz_target_source = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        run_error = crash_info.get("error_message", "")
        stack_trace = crash_info.get("stack_trace", "")
        artifact_path = crash_info.get("artifact_path", "")
        run_log = state.get("run_log", "")
        
        # First, perform semantic check to detect false positives
        semantic_result = self._check_false_positive(
            run_log=run_log,
            project_name=benchmark.project,
            stack_trace=stack_trace
        )
        
        # If it's a known false positive, skip detailed GDB analysis
        if semantic_result["is_false_positive"]:
            logger.info(
                f'Crash identified as false positive: {semantic_result["reason"]}',
                trial=self.trial
            )
            return {
                "crash_analysis": {
                    "root_cause": semantic_result["description"],
                    "true_bug": False,
                    "false_positive_type": semantic_result["fp_type"],
                    "severity": "low",
                    "analyzed": True,
                    "gdb_used": False,
                    "semantic_check": semantic_result
                }
            }
        
        # Validate artifact path
        if not artifact_path or not os.path.exists(artifact_path):
            logger.error(f'Artifact path {artifact_path} does not exist', 
                        trial=self.trial)
            return {
                "errors": [{
                    "node": "CrashAnalyzer",
                    "message": f"Artifact path {artifact_path} not found"
                }]
            }
        
        # Create work directories
        work_dirs = state.get("work_dirs")
        if not work_dirs:
            logger.error('No work_dirs in state', trial=self.trial)
            return {"errors": [{"message": "No work_dirs found"}]}
        
        WorkDirs(work_dirs, keep=True)
        
        # Generate project name for GDB container
        generated_target_name = os.path.basename(benchmark.target_path)
        sample_id = os.path.splitext(generated_target_name)[0]
        generated_oss_fuzz_project = (
            f'{benchmark.id}-{sample_id}-gdb-{self.trial:02d}')
        generated_oss_fuzz_project = oss_fuzz_checkout.rectify_docker_tag(
            generated_oss_fuzz_project)
        
        # Write fuzz target and build script to files
        fuzz_target_path = os.path.join(work_dirs, 'fuzz_targets',
                                       f'{self.trial:02d}.fuzz_target')
        os.makedirs(os.path.dirname(fuzz_target_path), exist_ok=True)
        with open(fuzz_target_path, 'w') as ft_file:
            ft_file.write(fuzz_target_source)
        
        if build_script_source:
            build_script_path = os.path.join(work_dirs, 'fuzz_targets',
                                           f'{self.trial:02d}.build_script')
            with open(build_script_path, 'w') as ft_file:
                ft_file.write(build_script_source)
        else:
            build_script_path = ''
        
        # Create OSS-Fuzz project with GDB support
        # Create a minimal RunResult-like object for compatibility
        class MockRunResult:
            def __init__(self, benchmark, artifact_path):
                self.benchmark = benchmark
                self.artifact_path = artifact_path
        
        mock_result = MockRunResult(benchmark, artifact_path)
        
        evaluator_lib.Evaluator.create_ossfuzz_project_with_gdb(
            benchmark, generated_oss_fuzz_project, fuzz_target_path,
            mock_result, build_script_path, artifact_path)
        
        # Initialize GDB tool
        self.gdb_tool = GDBTool(
            benchmark,
            result=mock_result,
            name='gdb',
            project_name=generated_oss_fuzz_project
        )
        
        # Setup GDB environment
        logger.info('Setting up GDB environment', trial=self.trial)
        self.gdb_tool.execute(
            'apt update && '
            'apt install -y software-properties-common && '
            'add-apt-repository -y ppa:ubuntu-toolchain-r/test && '
            'apt update && '
            'apt install -y gdb screen')
        self.gdb_tool.execute('export CFLAGS="$CFLAGS -g -O0"')
        self.gdb_tool.execute('export CXXFLAGS="$CXXFLAGS -g -O0"')
        self.gdb_tool.execute('compile > /dev/null')
        
        # Launch GDB session
        self.gdb_tool.execute(
            f'screen -dmS gdb_session -L '
            f'-Logfile /tmp/gdb_log.txt '
            f'gdb /out/{benchmark.target_name}')
        
        self.gdb_tool_used = False
        
        # Initialize bash tool for additional commands
        self.bash_tool = ProjectContainerTool(
            benchmark, name='check', project_name=generated_oss_fuzz_project)
        self.bash_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
        
        # Build initial prompt using PromptManager
        from agent_graph.prompt_loader import get_prompt_manager
        prompt_manager = get_prompt_manager()
        
        # Build user prompt with crash information
        user_prompt = prompt_manager.build_user_prompt(
            "crash_analyzer",
            CRASH_INFO=run_error,
            STACK_TRACE=stack_trace,
            FUZZ_TARGET_CODE=fuzz_target_source,
            ADDITIONAL_CONTEXT=f"Project: {benchmark.project}\nFunction: {benchmark.function_name}"
        )
        
        # Add tool tutorials
        user_prompt += "\n\n**Available Tools**:\n\n"
        user_prompt += self.gdb_tool.tutorial() + "\n\n"
        user_prompt += self.bash_tool.tutorial()
        
        # Create prompt object
        prompt = self.llm.prompt_type()(None)
        prompt.add_priming(user_prompt)
        
        # Multi-round interaction
        crash_result = {
            "true_bug": None,
            "insight": "",
            "stacktrace": stack_trace
        }
        
        cur_round = 0
        max_round = self.args.max_round
        
        try:
            client = self.llm.get_chat_client(model=self.llm.get_model())
            while prompt and prompt.get() and cur_round < max_round:
                # Chat with LLM
                response = self.llm.chat_llm(client=client, prompt=prompt)
                
                # Track token usage
                if hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
                    from agent_graph.state import update_token_usage
                    usage = self.llm.last_token_usage
                    update_token_usage(
                        state,
                        self.name,
                        usage.get('prompt_tokens', 0),
                        usage.get('completion_tokens', 0),
                        usage.get('total_tokens', 0)
                    )
                
                # Log the interaction
                logger.info(
                    f'<CRASH ANALYZER ROUND {cur_round}>\n{response}\n</CRASH ANALYZER ROUND {cur_round}>',
                    trial=self.trial
                )
                
                # Handle the response
                prompt = self._handle_response(cur_round, response, crash_result)
                cur_round += 1
                
                # If no more prompt, we're done
                if not prompt:
                    break
                    
        finally:
            # Cleanup: stop the containers
            logger.debug(f'Stopping crash analyze containers: {self.gdb_tool.container_id}, {self.bash_tool.container_id}',
                        trial=self.trial)
            if self.gdb_tool:
                self.gdb_tool.terminate()
            if self.bash_tool:
                self.bash_tool.terminate()
        
        # Return analysis result
        return {
            "crash_analysis": {
                "root_cause": crash_result.get("insight", "No analysis provided"),
                "true_bug": crash_result.get("true_bug", False),
                "severity": "high" if crash_result.get("true_bug") else "low",
                "analyzed": True,
                "gdb_used": self.gdb_tool_used
            }
        }
    
    def _extract_crash_function(self, stack_trace: str) -> str:
        """Extract the crashing function from stack trace."""
        if not stack_trace:
            return ""
        
        # Try to find function name in stack trace
        # Common patterns: "in functionName", "at functionName", "functionName()"
        import re
        patterns = [
            r'in\s+(\w+)',
            r'at\s+(\w+)',
            r'(\w+)\s*\(',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, stack_trace)
            if match:
                return match.group(1)
        
        return ""
    
    def _handle_response(self, cur_round: int, response: str, 
                        crash_result: dict) -> Optional[Any]:
        """Handle LLM response and determine next action."""
        # Create empty prompt for building response
        prompt = self.llm.prompt_type()(None)
        
        # Check for hallucinated tool usage
        if self._parse_tag(response, 'gdb output') or \
           self._parse_tag(response, 'gdb command'):
            extra_note = ('NOTE: It seems you have hallucinated interaction with the GDB tool. '
                         'You MUST restart the GDB interaction again and erase the previous '
                         'interaction from your memory.')
            self.gdb_tool_used = False
            return self._handle_invalid_tool_usage(
                [self.gdb_tool, self.bash_tool], cur_round, response, 
                prompt, extra_note)
        
        # Check for conclusion with tool commands
        if self._parse_tag(response, 'conclusion') and \
           (self._parse_tag(response, 'gdb') or self._parse_tag(response, 'bash')):
            extra_note = 'NOTE: You cannot provide both tool commands and conclusion in the same response.'
            return self._handle_invalid_tool_usage(
                [self.gdb_tool, self.bash_tool], cur_round, response, 
                prompt, extra_note)
        
        # Handle conclusion
        if self._parse_tag(response, 'conclusion'):
            if not self.gdb_tool_used:
                extra_note = 'NOTE: You MUST use the provided GDB tool to analyze the crash before providing a conclusion.'
                return self._handle_invalid_tool_usage(
                    [self.gdb_tool, self.bash_tool], cur_round, response, 
                    prompt, extra_note)
            return self._handle_conclusion(cur_round, response, crash_result)
        
        # Handle GDB commands
        if self._parse_tag(response, 'gdb'):
            self.gdb_tool_used = True
            return self._handle_gdb_command(response, self.gdb_tool, prompt)
        
        # Handle bash commands
        if self._parse_tag(response, 'bash'):
            return self._handle_bash_command(response, self.bash_tool, prompt)
        
        # Invalid response
        return self._handle_invalid_tool_usage(
            [self.gdb_tool, self.bash_tool], cur_round, response, prompt)
    
    def _handle_gdb_command(self, response: str, tool, prompt) -> Any:
        """Handle GDB command execution."""
        import subprocess as sp
        
        prompt_text = ''
        for command in self._parse_tags(response, 'gdb'):
            process = tool.execute_in_screen(command)
            prompt_text += self._format_gdb_execution_result(
                command, process, previous_prompt=prompt) + '\n'
            prompt.append(prompt_text)
        return prompt
    
    def _format_gdb_execution_result(self, gdb_command: str,
                                    process: sp.CompletedProcess,
                                    previous_prompt=None) -> str:
        """Format GDB execution result for LLM."""
        if previous_prompt:
            previous_prompt_text = previous_prompt.get()
        else:
            previous_prompt_text = ''
        
        raw_lines = process.stdout.strip().splitlines()
        if raw_lines and raw_lines[-1].strip().startswith("(gdb)"):
            raw_lines.pop()
        if raw_lines:
            raw_lines[0] = f'(gdb) {raw_lines[0].strip()}'
        processed_stdout = '\n'.join(raw_lines)
        
        stdout = self.llm.truncate_prompt(processed_stdout,
                                         previous_prompt_text).strip()
        stderr = self.llm.truncate_prompt(process.stderr,
                                         stdout + previous_prompt_text).strip()
        
        return (f'<gdb command>\n{gdb_command.strip()}\n</gdb command>\n'
               f'<gdb output>\n{stdout}\n</gdb output>\n'
               f'<stderr>\n{stderr}\n</stderr>\n')
    
    def _handle_bash_command(self, response: str, tool, prompt) -> Any:
        """Handle bash command execution."""
        prompt_text = ''
        for command in self._parse_tags(response, 'bash'):
            process = tool.execute(command)
            prompt_text += self._format_bash_execution_result(
                process, previous_prompt=prompt) + '\n'
            prompt.append(prompt_text)
        return prompt
    
    def _format_bash_execution_result(self, process, previous_prompt=None) -> str:
        """Format bash execution result for LLM."""
        if previous_prompt:
            previous_prompt_text = previous_prompt.get()
        else:
            previous_prompt_text = ''
        
        stdout = self.llm.truncate_prompt(process.stdout,
                                         previous_prompt_text).strip()
        stderr = self.llm.truncate_prompt(process.stderr,
                                         stdout + previous_prompt_text).strip()
        
        return (f'<bash>\n{process.args}\n</bash>\n'
               f'<return code>\n{process.returncode}\n</return code>\n'
               f'<stdout>\n{stdout}\n</stdout>\n'
               f'<stderr>\n{stderr}\n</stderr>\n')
    
    def _handle_conclusion(self, cur_round: int, response: str,
                          crash_result: dict) -> None:
        """Parse LLM conclusion and analysis."""
        logger.info(f'----- ROUND {cur_round:02d} Received conclusion -----',
                   trial=self.trial)
        
        conclusion = self._parse_tag(response, 'conclusion')
        if conclusion == 'False':
            crash_result['true_bug'] = False
        elif conclusion == 'True':
            crash_result['true_bug'] = True
        else:
            logger.error(f'***** Failed to match conclusion in {cur_round:02d} rounds *****',
                        trial=self.trial)
        
        crash_result['insight'] = self._parse_tag(response, 'analysis and suggestion')
        if not crash_result['insight']:
            logger.error(f'Round {cur_round:02d} No analysis and suggestion in conclusion: {response}',
                        trial=self.trial)
        
        # Return None to stop the loop
        return None
    
    def _handle_invalid_tool_usage(self, tools, cur_round: int, 
                                  response: str, prompt, extra: str = '') -> Any:
        """Handle invalid tool usage by re-teaching the LLM."""
        logger.warning(f'ROUND {cur_round:02d} Invalid response from LLM: {response}',
                      trial=self.trial)
        
        prompt_text = ('No valid instruction received. Please follow the '
                      'interaction protocols for available tools:\n\n')
        for tool in tools:
            prompt_text += f'{tool.tutorial()}\n\n'
        prompt.append(prompt_text)
        
        if extra:
            prompt.append(extra)
        
        return prompt
    
    def _parse_tag(self, response: str, tag: str) -> str:
        """Parse XML-style tags from LLM response."""
        import re
        match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
        return match.group(1).strip() if match else ''
    
    def _parse_tags(self, response: str, tag: str) -> list[str]:
        """Parse multiple XML-style tags from LLM response."""
        import re
        matches = re.findall(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
        return [content.strip() for content in matches]
    
    def _check_false_positive(self, run_log: str, project_name: str, 
                             stack_trace: str) -> Dict[str, Any]:
        """
        Check if crash is a false positive (fuzz target bug).
        
        Migrated from SemanticAnalyzer logic.
        
        Returns:
            Dictionary with keys:
            - is_false_positive: bool
            - fp_type: str (type of false positive)
            - reason: str (short reason)
            - description: str (detailed description)
        """
        import re
        
        # Regex patterns (migrated from SemanticAnalyzer)
        LIBFUZZER_MODULES_LOADED_REGEX = re.compile(
            r'^INFO:\s+Loaded\s+\d+\s+(modules|PC tables)\s+\((\d+)\s+.*\).*')
        LIBFUZZER_COV_REGEX = re.compile(r'.*cov: (\d+) ft:')
        LIBFUZZER_COV_LINE_PREFIX = re.compile(r'^#(\d+)')
        LIBFUZZER_STACK_FRAME_LINE_PREFIX = re.compile(r'^\s+#\d+')
        CRASH_STACK_WITH_SOURCE_INFO = re.compile(r'in.*:\d+:\d+$')
        
        LIBFUZZER_LOG_STACK_FRAME_LLVM = '/src/llvm-project/compiler-rt'
        LIBFUZZER_LOG_STACK_FRAME_LLVM2 = '/work/llvm-stage2/projects/compiler-rt'
        LIBFUZZER_LOG_STACK_FRAME_CPP = '/usr/local/bin/../include/c++'
        EARLY_FUZZING_ROUND_THRESHOLD = 3
        
        lines = run_log.split('\n')
        
        # Parse coverage info
        initcov, donecov, lastround = None, None, None
        for line in lines:
            if line.startswith('#'):
                match = LIBFUZZER_COV_LINE_PREFIX.match(line)
                roundno = int(match.group(1)) if match else None
                
                if roundno is not None:
                    lastround = roundno
                    if 'INITED' in line and 'cov: ' in line:
                        initcov = int(line.split('cov: ')[1].split(' ft:')[0])
                    elif 'DONE' in line and 'cov: ' in line:
                        donecov = int(line.split('cov: ')[1].split(' ft:')[0])
        
        # Extract symptom from run log
        symptom = self._extract_symptom(run_log)
        
        # Parse stack traces
        crash_stacks = self._parse_stacks_from_libfuzzer_logs(lines)
        
        # FP case 1: Common fuzz target errors
        if symptom == 'null-deref':
            return {
                "is_false_positive": True,
                "fp_type": "NULL_DEREF",
                "reason": "Null pointer dereference",
                "description": "Null-deref indicating inadequate parameter initialization or wrong function usage"
            }
        
        if symptom == 'signal':
            return {
                "is_false_positive": True,
                "fp_type": "SIGNAL",
                "reason": "Signal (assertion failure)",
                "description": "Signal indicating assertion failure due to inadequate parameter initialization"
            }
        
        if symptom.endswith('fuzz target exited'):
            return {
                "is_false_positive": True,
                "fp_type": "EXIT",
                "reason": "Fuzz target exited",
                "description": "Fuzz target exited in a controlled manner, blocking bug discovery"
            }
        
        if symptom.endswith('fuzz target overwrites its const input'):
            return {
                "is_false_positive": True,
                "fp_type": "OVERWRITE_CONST",
                "reason": "Modified const input",
                "description": "Fuzz target overwrites its const input"
            }
        
        if 'out-of-memory' in symptom or 'out of memory' in symptom:
            return {
                "is_false_positive": True,
                "fp_type": "FP_OOM",
                "reason": "Out of memory",
                "description": "OOM indicating malloc parameter is too large (e.g., using size directly)"
            }
        
        # FP case 2: Crash at init or first few rounds
        if lastround is None or lastround <= EARLY_FUZZING_ROUND_THRESHOLD:
            return {
                "is_false_positive": True,
                "fp_type": "FP_NEAR_INIT_CRASH",
                "reason": "Crash near initialization",
                "description": f"Crash occurred at round {lastround} (≤{EARLY_FUZZING_ROUND_THRESHOLD}), likely initialization issue"
            }
        
        # FP case 3: No func in 1st thread stack belongs to testing project
        if len(crash_stacks) > 0:
            first_stack = crash_stacks[0]
            for stack_frame in first_stack:
                if self._stack_func_is_of_testing_project(stack_frame):
                    if 'LLVMFuzzerTestOneInput' in stack_frame:
                        return {
                            "is_false_positive": True,
                            "fp_type": "FP_TARGET_CRASH",
                            "reason": "Crash in fuzz target code",
                            "description": "Crash occurred in LLVMFuzzerTestOneInput, not in project code"
                        }
                    break
        
        # Not a known false positive
        return {
            "is_false_positive": False,
            "fp_type": "NONE",
            "reason": "Potential true bug",
            "description": "No false positive pattern detected, proceeding with detailed analysis"
        }
    
    def _extract_symptom(self, fuzzlog: str) -> str:
        """Extract crash symptom from libFuzzer log."""
        # This should match SemanticCheckResult.extract_symptom behavior
        # Simplified version - real implementation would need full logic
        if 'AddressSanitizer: SEGV on unknown address' in fuzzlog:
            return 'null-deref'
        if 'fuzz target exited' in fuzzlog:
            return 'fuzz target exited'
        if 'fuzz target overwrites its const input' in fuzzlog:
            return 'fuzz target overwrites its const input'
        if 'out-of-memory' in fuzzlog or 'out of memory' in fuzzlog:
            return 'out-of-memory'
        # Check for signal
        if 'ERROR: libFuzzer: deadly signal' in fuzzlog:
            return 'signal'
        return 'unknown'
    
    def _parse_stacks_from_libfuzzer_logs(self, lines: list[str]) -> list[list[str]]:
        """Parse stack traces from libFuzzer logs."""
        import re
        LIBFUZZER_STACK_FRAME_LINE_PREFIX = re.compile(r'^\s+#\d+')
        
        stacks = []
        stack, stack_parsing = [], False
        
        for line in lines:
            is_stack_frame_line = LIBFUZZER_STACK_FRAME_LINE_PREFIX.match(line) is not None
            if (not stack_parsing) and is_stack_frame_line:
                stack_parsing = True
                stack = [line.strip()]
            elif stack_parsing and is_stack_frame_line:
                stack.append(line.strip())
            elif stack_parsing and (not is_stack_frame_line):
                stack_parsing = False
                stacks.append(stack)
        
        if stack_parsing:
            stacks.append(stack)
        
        return stacks
    
    def _stack_func_is_of_testing_project(self, stack_frame: str) -> bool:
        """Check if stack frame belongs to testing project."""
        import re
        CRASH_STACK_WITH_SOURCE_INFO = re.compile(r'in.*:\d+:\d+$')
        LIBFUZZER_LOG_STACK_FRAME_LLVM = '/src/llvm-project/compiler-rt'
        LIBFUZZER_LOG_STACK_FRAME_LLVM2 = '/work/llvm-stage2/projects/compiler-rt'
        LIBFUZZER_LOG_STACK_FRAME_CPP = '/usr/local/bin/../include/c++'
        
        return (bool(CRASH_STACK_WITH_SOURCE_INFO.match(stack_frame)) and
                LIBFUZZER_LOG_STACK_FRAME_LLVM not in stack_frame and
                LIBFUZZER_LOG_STACK_FRAME_LLVM2 not in stack_frame and
                LIBFUZZER_LOG_STACK_FRAME_CPP not in stack_frame)


class LangGraphCoverageAnalyzer(LangGraphAgent):
    """
    Coverage analyzer agent for LangGraph.
    
    This agent follows the original CoverageAnalyzer's approach:
    - Uses ProjectContainerTool for bash command execution
    - Multi-round interaction until conclusion is reached
    - Parses insights, suggestions, and conclusion tags
    """
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("coverage_analyzer")
        
        super().__init__(
            name="coverage_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
        self.inspect_tool = None
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze coverage to understand why it's low and provide insights.
        
        Following the original CoverageAnalyzer logic from coverage_analyzer.py.
        """
        from tool.container_tool import ProjectContainerTool
        from experiment.workdir import WorkDirs
        from experiment import benchmark as benchmarklib
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
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
        
        # Get fuzzing log from state
        fuzzing_log = state.get("run_log", "")
        if not fuzzing_log:
            # Try to get coverage summary as fallback
            coverage_summary = state.get("coverage_summary", "")
            fuzzing_log = f"Coverage: {state.get('coverage_percent', 0.0):.2f}%\n{coverage_summary}"
        
        # Build base prompt using the new prompt_loader
        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "coverage_analyzer",
            project=benchmark.project,
            function_signature=benchmark.function_signature,
            language=benchmark.file_type.value,
            project_language=benchmark.language,
            project_dir=self.inspect_tool.project_dir,
            fuzz_target=fuzz_target_source,
            fuzzing_log=fuzzing_log,
            function_requirements=function_requirements,
            additional_context=self.inspect_tool.tutorial()
        )
        
        # 注入session_memory，让CoverageAnalyzer能看到已有的覆盖率策略
        user_prompt = build_prompt_with_session_memory(
            state,
            base_prompt,
            agent_name=self.name
        )
        
        # Multi-round interaction
        coverage_result = {}
        cur_round = 0
        max_round = self.args.max_round
        all_responses = []  # 收集所有响应，用于提取session_memory更新
        
        try:
            # Start with the initial user prompt
            current_prompt = user_prompt
            
            while current_prompt and cur_round < max_round:
                # Chat with LLM using the agent's chat_llm method
                response = self.chat_llm(state, current_prompt)
                
                # 收集响应
                all_responses.append(response)
                
                # Log the round
                logger.info(
                    f'<COVERAGE ANALYZER ROUND {cur_round}>\n{response}\n</COVERAGE ANALYZER ROUND {cur_round}>',
                    trial=self.trial
                )
                
                # Handle the response and get next prompt
                current_prompt = self._handle_response(cur_round, response, coverage_result)
                cur_round += 1
                
                # If no more prompts, we're done
                if not current_prompt:
                    break
                
        finally:
            # Cleanup container
            if self.inspect_tool:
                logger.debug(
                    'Stopping and removing inspect container',
                    trial=self.trial
                )
                self.inspect_tool.terminate()
        
        # 从所有响应中提取session_memory更新（主要是覆盖率策略）
        combined_response = "\n\n".join(all_responses)
        session_memory_updates = extract_session_memory_updates_from_response(
            combined_response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # 合并更新到session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        return {
            "coverage_analysis": coverage_result,
            "session_memory": updated_session_memory  # ✅ 返回更新
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
    ) -> Optional[str]:
        """
        Handle LLM response - execute bash commands or extract conclusion.
        
        This follows the original _container_tool_reaction logic.
        Returns a prompt string for the next round, or None if done.
        """
        # First, try to handle bash commands
        bash_results = self._handle_bash_commands(response)
        
        # If bash commands were executed, return their results for next round
        if bash_results:
            return bash_results
        
        # If no bash commands, check for conclusion
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
        
        # No valid instruction received
        if not response:
            return ('No valid instruction received. Please follow the '
                   'interaction protocols for available tools:\n\n' +
                   f'{self.inspect_tool.tutorial()}\n\n')
        
        return None
    
    def _handle_bash_commands(self, response: str) -> Optional[str]:
        """
        Execute bash commands from LLM response.
        Returns formatted command results, or None if no commands were found.
        """
        bash_commands = parse_tags(response, 'bash')
        if not bash_commands:
            return None
        
        results = []
        for command in bash_commands:
            result = self.inspect_tool.execute(command)
            result_text = self._format_bash_result(result)
            results.append(result_text)
        
        return '\n'.join(results) if results else None
    
    def _format_bash_result(self, process) -> str:
        """Format bash execution result."""
        # Truncate output if too long
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()
        
        # Limit output size to avoid token overflow
        max_output_len = 10000
        if len(stdout) > max_output_len:
            stdout = stdout[:max_output_len] + f'\n... (truncated {len(stdout) - max_output_len} chars)'
        if len(stderr) > max_output_len:
            stderr = stderr[:max_output_len] + f'\n... (truncated {len(stderr) - max_output_len} chars)'
        
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
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("context_analyzer")
        
        super().__init__(
            name="context_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
        self.inspect_tool = None
        self.project_functions = None
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze crash feasibility by examining project context.
        
        Following the original ContextAnalyzer logic from context_analyzer.py.
        Uses ADK-style tool functions that LLM can call.
        """
        from tool.container_tool import ProjectContainerTool
        from experiment.workdir import WorkDirs
        from experiment import benchmark as benchmarklib
        from data_prep import introspector
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
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
        
        # Build initial prompt using PromptManager
        from agent_graph.prompt_loader import get_prompt_manager
        prompt_manager = get_prompt_manager()
        
        # Get crash analysis from previous step
        crash_insight = crash_analysis.get("insight", "")
        stack_trace = state.get("crash_info", {}).get("stack_trace", "")
        fuzz_target = state.get("fuzz_target_source", "")
        
        # Build base user prompt with context information
        base_prompt = prompt_manager.build_user_prompt(
            "context_analyzer",
            PROJECT_NAME=benchmark.project,
            FUZZ_TARGET=fuzz_target,
            FUNCTION_REQUIREMENTS=function_requirements,
            CRASH_STACKTRACE=stack_trace,
            CRASH_ANALYSIS=crash_insight,
            ADDITIONAL_CONTEXT=f"**Available Tools**:\n\n{self.inspect_tool.tutorial()}\n\nProject directory: {self.inspect_tool.project_dir}"
        )
        
        # 注入session_memory，让ContextAnalyzer能看到已有的决策和约束
        user_prompt = build_prompt_with_session_memory(
            state,
            base_prompt,
            agent_name=self.name
        )
        
        # Create prompt object
        prompt = self.llm.prompt_type()(None)
        prompt.add_priming(user_prompt)
        
        # Multi-round interaction - simulating ADK tool calling
        context_result = None
        cur_round = 0
        max_round = self.args.max_round
        all_responses = []  # 收集所有响应，用于提取session_memory更新
        
        try:
            while cur_round < max_round:
                # Chat with LLM
                client = None  # ADK agents use None for client
                response = self.llm.ask_llm(prompt=prompt)
                
                # 收集响应
                all_responses.append(response)
                
                # Track token usage
                if hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
                    from agent_graph.state import update_token_usage
                    usage = self.llm.last_token_usage
                    update_token_usage(
                        state,
                        self.name,
                        usage.get('prompt_tokens', 0),
                        usage.get('completion_tokens', 0),
                        usage.get('total_tokens', 0)
                    )
                
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
                    prompt = self._handle_invalid_response(response)
                
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
        
        # 从所有响应中提取session_memory更新（主要是关键决策）
        combined_response = "\n\n".join(all_responses)
        session_memory_updates = extract_session_memory_updates_from_response(
            combined_response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # 合并更新到session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        return {
            "context_analysis": context_result,
            "session_memory": updated_session_memory  # ✅ 返回更新
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
        new_prompt = self.llm.prompt_type()(None)
        
        # Handle bash commands for search_project_files
        bash_commands = parse_tags(response, 'bash')
        if bash_commands:
            for command in bash_commands:
                result = self.inspect_tool.execute(command)
                prompt_text = self._format_bash_result(result)
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
    
    def _format_bash_result(self, result: Any) -> str:
        """
        Format bash tool result for prompt.
        
        Args:
            result: Result from inspect_tool.execute()
            
        Returns:
            Formatted string for prompt
        """
        if isinstance(result, dict):
            stdout = result.get('stdout', '')
            stderr = result.get('stderr', '')
            returncode = result.get('returncode', 0)
            
            formatted = ""
            if stdout:
                formatted += f"<stdout>\n{stdout}\n</stdout>\n"
            if stderr:
                formatted += f"<stderr>\n{stderr}\n</stderr>\n"
            if returncode != 0:
                formatted += f"<returncode>{returncode}</returncode>\n"
            
            return formatted if formatted else "No output"
        
        # Fallback for string or other types
        return str(result)
    
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
    
    def _handle_invalid_response(self, response: str) -> Any:
        """Handle invalid LLM response."""
        logger.warning(f'Invalid response from LLM: {response[:200]}...', trial=self.trial)
        
        # Create a simple error correction prompt
        prompt = self.llm.prompt_type()(None)
        prompt.add_problem('No valid instruction received. Please follow the interaction protocols.\n\n')
        prompt.add_problem(self.inspect_tool.tutorial())
        prompt.add_problem('\n\nPlease provide a valid analysis following the requested format.')
        
        return prompt

