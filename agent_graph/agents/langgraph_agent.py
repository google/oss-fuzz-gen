"""
LangGraph-native agent base class.

This module provides a clean agent interface designed specifically for LangGraph,
without the legacy ADK/session baggage.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
import argparse
import os
import subprocess as sp

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.memory import get_agent_messages, add_agent_message
from agent_graph.prompt_loader import get_prompt_manager
from agent_graph.agents.utils import parse_tag, parse_tags
from agent_graph.logger import LangGraphLogger, NullLogger


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
        system_message: str = "",
        enable_detailed_logging: bool = True
    ):
        """
        Initialize a LangGraph agent.
        
        Args:
            name: Unique agent name (e.g., "function_analyzer")
            llm: LLM instance
            trial: Trial number
            args: Command line arguments
            system_message: System instruction for this agent
            enable_detailed_logging: If True, log all LLM interactions to files
        """
        self.name = name
        self.llm = llm
        self.trial = trial
        self.args = args
        self.system_message = system_message
        
        # Initialize detailed logging system (uses NullLogger pattern to avoid None checks)
        self.enable_detailed_logging = enable_detailed_logging
        
        # Get base_dir from work_dirs if available
        base_dir = None
        if hasattr(args, 'work_dirs') and args.work_dirs:
            base_dir = str(args.work_dirs.base)
        
        self._langgraph_logger = (
            LangGraphLogger.get_logger(workflow_id="fuzzing_workflow", trial=trial, base_dir=base_dir)
            if enable_detailed_logging
            else NullLogger()
        )
        self._round = 0
    
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
        6. Logs interaction to detailed log files
        
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
        
        # Increment round counter for detailed logging
        self._round += 1
        
        # Log the prompt (both standard and detailed)
        logger.info(
            f'<AGENT {self.name} PROMPT>\n{prompt}\n</AGENT {self.name} PROMPT>',
            trial=self.trial
        )
        
        # Detailed logging: log prompt with metadata
        prompt_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'temperature': getattr(self.args, 'temperature', None),
                'num_messages': len(messages)
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        # Call LLM with this agent's messages only
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage
        token_usage = None
        if hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Add assistant response
        add_agent_message(state, self.name, "assistant", response)
        
        # Log the response (both standard and detailed)
        logger.info(
            f'<AGENT {self.name} RESPONSE>\n{response}\n</AGENT {self.name} RESPONSE>',
            trial=self.trial
        )
        
        # Detailed logging: log response with metadata
        response_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'tokens': token_usage
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
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
        
        # Increment round counter for detailed logging
        self._round += 1
        
        logger.info(
            f'<AGENT {self.name} ONEOFF>\n{prompt}\n</AGENT {self.name} ONEOFF>',
            trial=self.trial
        )
        
        # Detailed logging: log one-off prompt
        if self._langgraph_logger:
            prompt_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'temperature': getattr(self.args, 'temperature', None),
                'type': 'one-off (no history)'
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage if state is provided
        token_usage = None
        if state and hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Detailed logging: log one-off response
        if self._langgraph_logger:
            response_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'tokens': token_usage,
                'type': 'one-off (no history)'
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
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
        from agent_graph.api_context_extractor import get_api_context, format_api_context_for_prompt
        
        benchmark = state["benchmark"]
        project_name = benchmark.get('project', 'unknown')
        function_signature = benchmark.get('function_signature', 'unknown')
        function_name = benchmark.get('function_name', 'unknown')
        
        # Query FuzzIntrospector for function source code
        logger.info(f'Querying FuzzIntrospector for source code of {function_signature}', trial=self.trial)
        func_source = introspector.query_introspector_function_source(
            project_name, function_signature
        )
        
        # Extract API context using APIContextExtractor (integrated)
        logger.info(f'🔍 Extracting API context for {function_signature}', trial=self.trial)
        api_context = get_api_context(project_name, function_signature)
        if api_context:
            param_count = len(api_context.get('parameters', []))
            init_pattern_count = len(api_context.get('initialization_patterns', []))
            example_count = len(api_context.get('usage_examples', []))
            related_func_count = len(api_context.get('related_functions', []))
            typedef_count = len(api_context.get('type_definitions', {}))
            
            logger.info(
                f'✅ API context extracted: {param_count} parameters, '
                f'{init_pattern_count} init patterns, {example_count} usage examples',
                trial=self.trial
            )
            
            # Log detailed context information
            logger.info(
                f'📊 Detailed API Context Information:\n'
                f'  ├─ Parameters ({param_count}):\n' +
                '\n'.join([f'  │   • {p.get("name", "?")} ({p.get("type", "?")})' 
                          for p in api_context.get('parameters', [])[:10]]) +
                ('\n  │   • ... (more parameters)' if param_count > 10 else '') +
                f'\n  ├─ Type Definitions ({typedef_count}):\n' +
                '\n'.join([f'  │   • {name}' 
                          for name in list(api_context.get('type_definitions', {}).keys())[:5]]) +
                ('\n  │   • ... (more types)' if typedef_count > 5 else '') +
                f'\n  ├─ Initialization Patterns ({init_pattern_count}):\n' +
                '\n'.join([f'  │   • {p.get("parameter", "?")} ({p.get("type", "?")}) -> {p.get("method", "?")[:50]}...' 
                          for p in api_context.get('initialization_patterns', [])]) +
                f'\n  ├─ Related Functions ({related_func_count}):\n' +
                '\n'.join([f'  │   • {f.get("name", "?")} [{f.get("type", "?")}]' 
                          for f in api_context.get('related_functions', [])[:10]]) +
                ('\n  │   • ... (more functions)' if related_func_count > 10 else '') +
                f'\n  └─ Usage Examples ({example_count}):\n' +
                '\n'.join([f'  │   • {e.get("function", "?")} @ {e.get("file", "?")[:50]}...' 
                          for e in api_context.get('usage_examples', [])]),
                trial=self.trial
            )
        else:
            logger.warning(f'⚠️ No API context extracted for {function_signature}', trial=self.trial)
        
        # Build API dependency graph using tree-sitter + FuzzIntrospector
        logger.info(f'🔗 Building API dependency graph for {function_signature}', trial=self.trial)
        api_dependencies = None
        try:
            from agent_graph.api_dependency_analyzer import APIDependencyAnalyzer
            analyzer = APIDependencyAnalyzer(project_name)
            api_dependencies = analyzer.build_dependency_graph(function_signature)
            
            if api_dependencies and api_dependencies.get('call_sequence'):
                prereq_count = len(api_dependencies.get('prerequisites', []))
                data_dep_count = len(api_dependencies.get('data_dependencies', []))
                call_seq_len = len(api_dependencies.get('call_sequence', []))
                
                logger.info(
                    f'✅ API dependency graph built: {prereq_count} prerequisites, '
                    f'{data_dep_count} data deps, call sequence length: {call_seq_len}',
                    trial=self.trial
                )
                
                # Log detailed dependency information
                logger.info(
                    f'🔗 Detailed API Dependency Information:\n'
                    f'  ├─ Call Sequence ({call_seq_len}):\n' +
                    '\n'.join([f'  │   {i+1}. {func}{"" if func != function_signature else " ← TARGET"}' 
                              for i, func in enumerate(api_dependencies.get('call_sequence', []))]) +
                    f'\n  ├─ Prerequisites ({prereq_count}):\n' +
                    '\n'.join([f'  │   • {prereq}()' 
                              for prereq in api_dependencies.get('prerequisites', [])]) +
                    f'\n  └─ Data Dependencies ({data_dep_count}):\n' +
                    '\n'.join([f'  │   • {src} → {dst}' 
                              for src, dst in api_dependencies.get('data_dependencies', [])]),
                    trial=self.trial
                )
            else:
                logger.warning(f'⚠️ No API dependencies extracted for {function_signature}', trial=self.trial)
        except Exception as e:
            logger.warning(f'⚠️ Failed to build API dependency graph: {e}', trial=self.trial)
        
        # Query FuzzIntrospector for header information
        logger.info(f'Querying FuzzIntrospector for header files of {function_signature}', trial=self.trial)
        header_info = self._extract_header_information(project_name, function_signature)
        
        # Extract headers from existing fuzzers (proven to work)
        existing_fuzzer_headers = self._extract_existing_fuzzer_headers(project_name)
        header_info["existing_fuzzer_headers"] = existing_fuzzer_headers
        
        # Log detailed header information
        # existing_fuzzer_headers is a dict with 'standard_headers' and 'project_headers' keys
        std_count = len(existing_fuzzer_headers.get('standard_headers', []))
        proj_count = len(existing_fuzzer_headers.get('project_headers', []))
        logger.info(
            f'📚 Header information extracted from FuzzIntrospector:\n'
            f'  Definition headers: {header_info.get("definition_headers", [])}\n'
            f'  Required type headers: {header_info.get("required_type_headers", [])}\n'
            f'  Existing fuzzer headers: {std_count} standard, {proj_count} project headers',
            trial=self.trial
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
            state, project_name, function_signature, function_name, func_source, api_context
        )
        
        # 从响应中提取session_memory更新（archetype、初始API约束等）
        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # 合并更新到session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        # Extract SRS JSON from response
        srs_data = self._extract_srs_json(response)
        
        # Parse response and create structured output
        analysis_result = {
            "summary": response[:500],  # First 500 chars as summary
            "raw_analysis": response,
            "analyzed": True,
            "header_information": header_info,  # Include header info for Prototyper
            "srs_data": srs_data,  # Include structured SRS data
            "api_context": api_context,  # Include API context for downstream agents
            "api_dependencies": api_dependencies  # Include API dependency graph
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
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
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
        func_source: str,
        api_context: Optional[Dict] = None
    ) -> str:
        """
        Execute iterative analysis of the function using cross-reference examples.
        """
        from agent_graph.prompt_loader import get_prompt_manager
        from data_prep import introspector
        
        logger.info(f'Starting iterative analysis for {function_signature}', trial=self.trial)
        
        # Phase 1: Analyze the function itself to get basic understanding
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 1: Analyzing function source code', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        prompt_manager = get_prompt_manager()
        
        # Build initial prompt with API context if available
        from agent_graph.api_context_extractor import format_api_context_for_prompt
        api_context_text = ""
        if api_context:
            api_context_text = format_api_context_for_prompt(api_context)
            logger.info(f'📝 Injecting API context into initial prompt ({len(api_context_text)} chars)', trial=self.trial)
            logger.debug(f'API context preview:\n{api_context_text[:500]}...', trial=self.trial)
        else:
            logger.info('📝 No API context available for initial prompt', trial=self.trial)
        
        logger.info(f'📄 Function source code length: {len(func_source)} chars', trial=self.trial)
        logger.debug(f'Function source preview:\n{func_source[:300]}...', trial=self.trial)
        
        initial_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_initial",
            FUNCTION_SIGNATURE=function_signature,
            FUNCTION_SOURCE=func_source,
            API_CONTEXT=api_context_text
        )
        logger.info(f'📤 Sending initial prompt to LLM (total length: {len(initial_prompt)} chars)', trial=self.trial)
        initial_analysis = self.chat_llm(state, initial_prompt)
        logger.info(f'📥 Received initial analysis (length: {len(initial_analysis)} chars)', trial=self.trial)
        logger.debug(f'Initial analysis preview:\n{initial_analysis[:200]}...', trial=self.trial)
        
        # Phase 2: Get call site metadata
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 2: Querying call sites metadata from FuzzIntrospector', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        call_sites = introspector.query_introspector_call_sites_metadata(project_name, function_signature)
        
        examples_analyzed = 0
        no_new_insight_count = 0
        
        if call_sites:
            logger.info(
                f'🔍 FuzzIntrospector found {len(call_sites)} call sites for {function_name}. '
                f'Will process up to {self.max_examples} examples to extract API behavior semantics.',
                trial=self.trial
            )
            
            # Log overview of call sites
            logger.info(
                f'📋 Call sites overview:\n' +
                '\n'.join([f'  {idx+1}. {cs.get("src_func", "?")} @ {cs.get("src_file", "?")[:50]}...:L{cs.get("src_line", "?")}'
                          for idx, cs in enumerate(call_sites[:min(10, len(call_sites))])]) +
                (f'\n  ... and {len(call_sites) - 10} more' if len(call_sites) > 10 else ''),
                trial=self.trial
            )
            
            call_sites = call_sites[:self.max_examples]
            
            # Phase 3: Iteratively learn from usage examples
            logger.info('=' * 80, trial=self.trial)
            logger.info('🔬 Phase 3: Iteratively analyzing API usage examples', trial=self.trial)
            logger.info('=' * 80, trial=self.trial)
            for i, call_site in enumerate(call_sites, 1):
                logger.info(f'📍 Processing example {i}/{len(call_sites)}:', trial=self.trial)
                logger.info(f'   Source: {call_site.get("src_func", "unknown")}', trial=self.trial)
                logger.info(f'   File: {call_site.get("src_file", "unknown")}', trial=self.trial)
                logger.info(f'   Line: {call_site.get("src_line", "?")}', trial=self.trial)
                
                # Extract context
                logger.info(f'   ⏳ Extracting call context...', trial=self.trial)
                context = self._extract_call_context(call_site, project_name)
                if not context:
                    logger.warning(f'   ⚠️ Could not extract context for example {i}, skipping', trial=self.trial)
                    continue
                
                logger.info(f'   ✅ Context extracted:', trial=self.trial)
                logger.info(f'      Caller: {context.get("caller_name", "?")}', trial=self.trial)
                logger.info(f'      Call line: {context.get("call_line_number", "?")}', trial=self.trial)
                logger.info(f'      Context size: {len(context.get("full_context", ""))} chars', trial=self.trial)
                logger.debug(f'      Call statement: {context.get("call_statement", "?")[:100]}...', trial=self.trial)
                
                # Build prompt - LLM maintains context through conversation
                logger.info(f'   📝 Building iteration prompt for example {i}...', trial=self.trial)
                iteration_prompt = self._build_iteration_prompt(context, i, examples_analyzed)
                logger.info(f'   📤 Sending iteration prompt to LLM (length: {len(iteration_prompt)} chars)...', trial=self.trial)
                
                # Get LLM analysis
                try:
                    response = self.chat_llm(state, iteration_prompt)
                    examples_analyzed += 1
                    
                    # Simple heuristic: if response is very short, might indicate no new insights
                    if len(response.strip()) < 100:
                        no_new_insight_count += 1
                        logger.info(f'   📥 Response received (length: {len(response)} chars) - appears brief, may indicate convergence', trial=self.trial)
                    else:
                        no_new_insight_count = 0
                        logger.info(f'   📥 Response received (length: {len(response)} chars) - contains new insights', trial=self.trial)
                    
                    logger.debug(f'   Response preview: {response[:150]}...', trial=self.trial)
                    
                except Exception as e:
                    logger.error(f'   ❌ Error calling LLM for example {i}: {e}', trial=self.trial)
                    continue
                
                # Check convergence: stop if no new insights for N consecutive examples
                if no_new_insight_count >= self.convergence_threshold:
                    logger.info(
                        f'🎯 Converged after {examples_analyzed} examples '
                        f'({no_new_insight_count} consecutive examples without significant insights)',
                        trial=self.trial
                    )
                    break
            
            # Log summary of extraction
            logger.info(
                f'✅ Successfully extracted and analyzed {examples_analyzed} API usage examples from FuzzIntrospector. '
                f'These examples provide real-world behavioral semantics for {function_name}.',
                trial=self.trial
            )
        else:
            logger.warning(f'⚠️  No call sites found in FuzzIntrospector for {function_signature}. '
                          f'Analysis will rely on function signature and source code only.',
                          trial=self.trial)
        
        # Phase 4: Generate final comprehensive analysis
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 4: Generating final comprehensive analysis', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        logger.info(f'📊 Summary: Analyzed {examples_analyzed} API usage examples from real code', trial=self.trial)
        
        # Retrieve archetype knowledge from long-term memory
        logger.info('🧠 Retrieving archetype knowledge from long-term memory...', trial=self.trial)
        archetype_knowledge = self._retrieve_archetype_knowledge(state)
        logger.info(f'   Archetype knowledge length: {len(archetype_knowledge)} chars', trial=self.trial)
        if archetype_knowledge and len(archetype_knowledge) > 0:
            logger.debug(f'   Archetype knowledge preview: {archetype_knowledge[:200]}...', trial=self.trial)
        else:
            logger.info('   No archetype knowledge available', trial=self.trial)
        
        prompt_manager = get_prompt_manager()
        final_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_final_summary",
            FUNCTION_SIGNATURE=function_signature,
            EXAMPLES_COUNT=examples_analyzed,
            ARCHETYPE_KNOWLEDGE=archetype_knowledge
        )
        
        logger.info(f'📤 Sending final summary request to LLM (prompt length: {len(final_prompt)} chars)...', trial=self.trial)
        final_response = self.chat_llm(state, final_prompt)
        logger.info(f'📥 Received final analysis (length: {len(final_response)} chars)', trial=self.trial)
        
        # Validate output structure and extract metadata
        is_valid, missing, metadata = self._validate_and_extract_metadata(final_response, function_name)
        
        if not is_valid:
            logger.warning(
                f"Function analysis output incomplete. Missing: {missing}",
                trial=self.trial
            )
        else:
            logger.info("✓ Function analysis structure validated successfully", trial=self.trial)
        
        # If @must_call_target is extracted, add to session memory
        if metadata.get("must_call_target") == "yes":
            from agent_graph.state import add_api_constraint
            add_api_constraint(
                state,
                f"CRITICAL: Must call {metadata.get('target_function', function_name)} in fuzz driver",
                source="function_analyzer",
                confidence="high"
            )
        
        # Store extracted target function name in state
        if metadata.get("target_function"):
            state["target_function_name"] = metadata["target_function"]
        
        return final_response
    
    def _validate_and_extract_metadata(
        self,
        analysis_output: str,
        function_name: str
    ) -> tuple[bool, list[str], dict]:
        """
        Validate function analysis output and extract metadata.
        
        Returns:
            (is_valid, missing_items, extracted_metadata)
        """
        import re
        
        required_tags = [
            "@target_function:",
            "@must_call_target:",
            "@category:",
            "@complexity:",
            "@state_model:",
            "@recommended_approach:"
        ]
        
        missing = []
        metadata = {}
        
        # Check for required tags
        for tag in required_tags:
            if tag not in analysis_output:
                missing.append(f"Missing tag: {tag}")
            else:
                # Extract value
                tag_clean = tag.rstrip(":")
                pattern = rf"{re.escape(tag)}\s*[`]?([^`\n]+)[`]?"
                match = re.search(pattern, analysis_output)
                if match:
                    value = match.group(1).strip()
                    metadata[tag_clean.lstrip("@")] = value
        
        # Check for "Recommended Test Vectors" section
        if "Recommended Test Vectors" not in analysis_output and "**Recommended Test Vectors**" not in analysis_output:
            missing.append("Missing section: Recommended Test Vectors")
        
        is_valid = len(missing) == 0
        return is_valid, missing, metadata
    
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
        
        context_dict = {
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
        
        # Log extracted context for debugging and analysis
        logger.info(
            f"📋 Extracted API usage context from FuzzIntrospector:\n"
            f"  Caller: {src_func}\n"
            f"  Line: {call_line_idx + 1}\n"
            f"  Call statement: {call_statement.strip()}\n"
            f"  Parameter setup: {parameter_setup[:100]}{'...' if len(parameter_setup) > 100 else ''}\n"
            f"  Return usage: {return_usage[:100]}{'...' if len(return_usage) > 100 else ''}",
            trial=self.trial
        )
        
        # Log the full context in debug mode
        logger.debug(
            f"Full context extracted:\n"
            f"--- Context Before ({len(context_before)} chars) ---\n"
            f"{context_before}\n"
            f"--- Call Statement ---\n"
            f"{call_statement}\n"
            f"--- Context After ({len(context_after)} chars) ---\n"
            f"{context_after}",
            trial=self.trial
        )
        
        return context_dict
    
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
    
    def _retrieve_archetype_knowledge(self, state: FuzzingWorkflowState) -> str:
        """
        Retrieve relevant archetype knowledge from long-term memory.
        
        Attempts to infer archetype from conversation history, or returns all archetypes
        for reference.
        """
        try:
            from long_term_memory.retrieval import KnowledgeRetriever
            
            retriever = KnowledgeRetriever()
            
            # Try to extract archetype from conversation history
            archetype = self._infer_archetype_from_history(state)
            
            if archetype and archetype in retriever.list_archetypes():
                logger.info(f'Inferred archetype: {archetype}, retrieving knowledge', trial=self.trial)
                bundle = retriever.get_bundle(archetype)
                
                # Format knowledge for injection
                knowledge = f"""
# Relevant Pattern Knowledge

## Archetype: {archetype}

{bundle['archetype']}

## Common Pitfalls
"""
                for pitfall_name, pitfall_content in bundle['pitfalls'].items():
                    knowledge += f"\n### {pitfall_name}\n{pitfall_content[:500]}...\n"
                
                return knowledge
            else:
                # Return list of archetypes for reference
                archetypes_list = retriever.list_archetypes()
                logger.info(f'No archetype inferred, providing archetype list', trial=self.trial)
                return f"""
# Available Archetype Patterns

Consider which pattern best matches this API:
{', '.join(archetypes_list)}

Use this knowledge to structure your analysis.
"""
        except Exception as e:
            logger.warning(f'Failed to retrieve archetype knowledge: {e}', trial=self.trial)
            return ""
    
    def _infer_archetype_from_history(self, state: FuzzingWorkflowState) -> Optional[str]:
        """
        Try to infer archetype from conversation history.
        
        Looks for archetype mentions in the conversation.
        """
        # Check conversation history for archetype mentions
        agent_messages = state.get("agent_messages", {}).get(self.name, [])
        
        archetype_keywords = {
            "stateless_parser": ["stateless", "parse", "single call", "no state"],
            "object_lifecycle": ["create", "destroy", "lifecycle", "init", "free"],
            "state_machine": ["state machine", "multi-step", "sequence", "configure"],
            "stream_processor": ["stream", "chunk", "incremental", "loop"],
            "round_trip": ["round-trip", "encode", "decode", "compress"],
            "file_based": ["file path", "filename", "temp file"]
        }
        
        # Count keyword matches
        scores = {arch: 0 for arch in archetype_keywords}
        
        for message in agent_messages[-5:]:  # Check last 5 messages
            content = message.get("content", "").lower()
            for arch, keywords in archetype_keywords.items():
                for keyword in keywords:
                    if keyword in content:
                        scores[arch] += 1
        
        # Return archetype with highest score (if > 0)
        max_arch = max(scores, key=scores.get)
        return max_arch if scores[max_arch] > 0 else None
    
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
    
    def _extract_header_information(
        self,
        project_name: str,
        function_signature: str
    ) -> dict:
        """
        Extract header information from FuzzIntrospector.
        
        Returns:
            dict with keys:
                - function_header: Primary header file for the function
                - related_headers: List of related project headers
                - definition_file_headers: Headers extracted from function definition file (NEW)
                - is_c_api: Whether the function is a C API (based on naming convention)
        """
        from data_prep import introspector
        from agent_graph.header_extractor import get_function_definition_headers
        
        header_info = {
            "function_header": None,
            "related_headers": [],
            "definition_file_headers": None,
            "is_c_api": False
        }
        
        try:
            # ===== STEP 0: Detect if this is a C API function =====
            # C API characteristics:
            # 1. Function name uses underscore_style (e.g., ada_can_parse_with_base)
            # 2. No namespace prefix (e.g., no ada::parse)
            # 3. Often has C-style types (char*, size_t) without std::
            function_name = function_signature.split('(')[0].strip().split()[-1]
            is_c_api = self._detect_c_api(function_name, function_signature)
            header_info["is_c_api"] = is_c_api
            
            if is_c_api:
                logger.info(
                    f'Detected C API function (underscore naming): {function_name}',
                    trial=self.trial
                )
            # ======================================================
            
            # ===== STEP 1: Query FI for header files (HIGHEST PRIORITY for C APIs) =====
            logger.info(f'Querying FI header files for {function_signature}', trial=self.trial)
            all_headers = introspector.query_introspector_header_files_to_include(
                project_name, function_signature
            )
            
            if all_headers:
                logger.info(f'Found {len(all_headers)} headers from FI', trial=self.trial)
                
                # Filter project headers (exclude standard library)
                project_headers = []
                for header in all_headers:
                    # Keep headers that are in project source (/src/PROJECT_NAME/...)
                    if f'/src/{project_name}/' in header or '/src/' in header[:20]:
                        # Convert to include format
                        include_path = self._convert_to_include_path(header, project_name)
                        if include_path:
                            project_headers.append(include_path)
                
                if project_headers:
                    # First header is usually the function's declaration
                    header_info["function_header"] = project_headers[0]
                    header_info["related_headers"] = project_headers[1:5]  # Up to 4 more
                    logger.info(f'Primary header from FI: {project_headers[0]}', trial=self.trial)
            else:
                logger.debug(f'No headers returned from FI for {function_signature}', trial=self.trial)
            # ==========================================================================
            
            # ===== STEP 2: Extract headers from function definition file (fallback for C++) =====
            logger.info(f'Extracting headers from function definition file', trial=self.trial)
            definition_headers = get_function_definition_headers(
                project_name, function_signature
            )
            
            if definition_headers:
                header_info["definition_file_headers"] = definition_headers
                logger.info(
                    f'Extracted {len(definition_headers.get("standard_headers", []))} standard '
                    f'and {len(definition_headers.get("project_headers", []))} project headers '
                    f'from definition file: {definition_headers.get("definition_file", "unknown")}',
                    trial=self.trial
                )
            else:
                logger.debug(f'No definition file headers found', trial=self.trial)
            # ==================================================================================
            
        except Exception as e:
            logger.warning(f'Failed to extract header information: {e}', trial=self.trial)
        
        return header_info
    
    def _detect_c_api(self, function_name: str, function_signature: str) -> bool:
        """
        Detect if a function is a C API based on naming conventions.
        
        C API characteristics:
        - Underscore naming (e.g., ada_can_parse, json_parse_string)
        - No namespace prefix (no ::)
        - Typically 2+ underscores in name
        
        Args:
            function_name: Extracted function name (e.g., 'ada_can_parse_with_base')
            function_signature: Full signature for additional context
        
        Returns:
            True if likely a C API function
        """
        # C++ API indicators (negative signals)
        if '::' in function_name:
            return False  # C++ namespace
        
        # Remove common prefixes to get pure name
        name_parts = function_name.split('::')[-1]  # Get last part after ::
        
        # C API naming pattern: lowercase_with_underscores
        # Require at least 2 underscores and all lowercase (except for specific prefixes)
        underscore_count = name_parts.count('_')
        
        if underscore_count >= 2:
            # Check if it's all lowercase (C API convention)
            # Allow numbers and underscores
            clean_name = name_parts.replace('_', '').replace('0', '').replace('1', '').replace('2', '').replace('3', '').replace('4', '').replace('5', '').replace('6', '').replace('7', '').replace('8', '').replace('9', '')
            if clean_name.islower():
                return True
        
        return False
    
    def _convert_to_include_path(self, absolute_path: str, project_name: str) -> str:
        """
        Convert absolute path to include format.
        e.g., /src/mosh/src/terminal/terminal.h -> "src/terminal/terminal.h"
        """
        if not absolute_path:
            return ""
        
        # Try to extract the part after /src/PROJECT_NAME/
        if f'/src/{project_name}/' in absolute_path:
            parts = absolute_path.split(f'/src/{project_name}/', 1)
            if len(parts) > 1:
                return parts[1]
        
        # Fallback: extract after any /src/
        if '/src/' in absolute_path:
            parts = absolute_path.split('/src/', 1)
            if len(parts) > 1:
                subparts = parts[1].split('/', 1)
                if len(subparts) > 1:
                    return subparts[1]
        
        # Last resort: return filename only
        return absolute_path.split('/')[-1]
    
    def _extract_existing_fuzzer_headers(
        self,
        project_name: str
    ) -> dict:
        """
        Extract actual include statements from existing fuzzers.
        These headers are proven to work and should be prioritized.
        
        Args:
            project_name: Name of the project
            
        Returns:
            dict with keys:
                - standard_headers: List of standard library includes (e.g., ["cstddef", "cstdint"])
                - project_headers: List of project-specific includes (e.g., ["src/terminal/parser.h"])
        """
        from data_prep import introspector
        import re
        
        result = {
            "standard_headers": [],
            "project_headers": []
        }
        
        try:
            # 1. Get all fuzzers for the project
            logger.info(f'Querying existing fuzzers for {project_name}', trial=self.trial)
            harnesses = introspector.query_introspector_for_harness_intrinsics(project_name)
            
            if not harnesses:
                logger.warning(f'No existing fuzzers found for {project_name}', trial=self.trial)
                return result
            
            all_includes = {"standard": set(), "project": set()}
            
            # 2. Analyze each fuzzer (limit to first 10 for efficiency)
            for harness in harnesses[:10]:
                fuzzer_path = harness.get('source', '')
                if not fuzzer_path:
                    continue
                
                logger.debug(f'Analyzing fuzzer: {fuzzer_path}', trial=self.trial)
                
                # 3. Get fuzzer source code
                fuzzer_source = introspector.query_introspector_source_code(
                    project_name, fuzzer_path
                )
                
                if not fuzzer_source:
                    continue
                
                # 4. Parse includes from source
                # Pattern for #include <...> (standard library)
                standard_includes = re.findall(r'#include\s+<([^>]+)>', fuzzer_source)
                for inc in standard_includes:
                    # Filter common fuzzer-only headers
                    if inc not in ['fuzzer/FuzzedDataProvider.h']:
                        all_includes["standard"].add(inc)
                
                # Pattern for #include "..." (project headers)
                project_includes = re.findall(r'#include\s+"([^"]+)"', fuzzer_source)
                for inc in project_includes:
                    # Filter out fuzzer-specific and test files
                    inc_lower = inc.lower()
                    if 'fuzzer' not in inc_lower and 'test' not in inc_lower and 'mock' not in inc_lower:
                        all_includes["project"].add(inc)
            
            result["standard_headers"] = sorted(list(all_includes["standard"]))
            result["project_headers"] = sorted(list(all_includes["project"]))
            
            total_count = len(result["standard_headers"]) + len(result["project_headers"])
            logger.info(f'Extracted {total_count} includes from existing fuzzers '
                       f'({len(result["standard_headers"])} standard, {len(result["project_headers"])} project)',
                       trial=self.trial)
            
        except Exception as e:
            logger.warning(f'Failed to extract existing fuzzer headers: {e}', trial=self.trial)
        
        return result
    
    def _extract_srs_json(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract and parse SRS JSON from the response.
        
        Args:
            response: The LLM response containing SRS specification
            
        Returns:
            Parsed SRS JSON data or None if not found/invalid
        """
        import json
        import re
        
        try:
            # Look for <srs_json>...</srs_json> tags
            match = re.search(r'<srs_json>\s*(\{.*?\})\s*</srs_json>', response, re.DOTALL)
            if match:
                json_str = match.group(1)
                srs_data = json.loads(json_str)
                logger.info(f'Successfully extracted SRS JSON data', trial=self.trial)
                return srs_data
            else:
                logger.warning(f'No <srs_json> tags found in response', trial=self.trial)
                return None
        except json.JSONDecodeError as e:
            logger.warning(f'Failed to parse SRS JSON: {e}', trial=self.trial)
            return None
        except Exception as e:
            logger.warning(f'Error extracting SRS JSON: {e}', trial=self.trial)
            return None


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
        
        # Retrieve skeleton from long-term memory based on archetype
        # (skeleton already contains header information injected by Function Analyzer)
        skeleton_code = self._retrieve_skeleton(function_analysis)
        
        # Format SRS specification (use structured data if available, otherwise raw analysis)
        srs_specification = self._format_srs_specification(function_analysis)
        
        base_prompt = prompt_manager.build_user_prompt(
            "prototyper",
            project_name=benchmark.get('project', 'unknown'),
            function_name=benchmark.get('function_name', 'unknown'),
            function_signature=benchmark.get('function_signature', 'unknown'),
            srs_specification=srs_specification,
            additional_context=additional_context,
            skeleton_code=skeleton_code
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
        
        # Extract code from <fuzz_target> tags
        fuzz_target_code = parse_tag(response, 'fuzz_target')
        
        # If no tags found, use the whole response as fallback
        if not fuzz_target_code:
            fuzz_target_code = response
        
        # 🔥 NEW: Validate generated code for internal API usage
        validation_warnings = self._validate_api_usage(
            fuzz_target_code,
            benchmark.get('project', 'unknown')
        )
        
        # Prepare state update
        state_update = {
            "fuzz_target_source": fuzz_target_code,
            "compile_success": None,  # Reset to trigger build
            "build_errors": [],  # Clear previous errors
            "retry_count": 0,  # Reset retry count for new target
            "session_memory": updated_session_memory,  # ✅ 返回更新
            "api_validation_warnings": validation_warnings  # Store for Enhancer to see
        }
        
        # If this is a regeneration, update regeneration counter and reset compilation retry count
        if is_regeneration:
            prototyper_regenerate_count = state.get("prototyper_regenerate_count", 0)
            state_update["prototyper_regenerate_count"] = prototyper_regenerate_count + 1
            state_update["compilation_retry_count"] = 0  # Reset enhancer retry count
            logger.info(f'Prototyper regeneration #{prototyper_regenerate_count + 1}, '
                       f'resetting compilation_retry_count', trial=self.trial)
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
        return state_update
    
    def _validate_api_usage(self, code: str, project_name: str) -> str:
        """
        Validate generated code for internal/private API usage.
        
        Args:
            code: Generated fuzz target code
            project_name: Project name
        
        Returns:
            Formatted validation warnings (empty string if no issues)
        """
        try:
            from agent_graph.api_validator import validate_fuzz_target
            
            is_valid, report = validate_fuzz_target(code, project_name)
            
            if not is_valid:
                logger.warning(
                    f'Generated code contains internal API usage - validation failed',
                    trial=self.trial
                )
                logger.info(f'Validation report:\n{report}', trial=self.trial)
                return report
            else:
                logger.info('Generated code passed API validation', trial=self.trial)
                return ""
        
        except Exception as e:
            logger.warning(f'API validation failed with error: {e}', trial=self.trial)
            return ""
    
    def _format_srs_specification(self, function_analysis: dict) -> str:
        """
        Format SRS specification for the Prototyper prompt.
        
        Args:
            function_analysis: Analysis containing SRS data
            
        Returns:
            Formatted SRS specification string
        """
        srs_data = function_analysis.get('srs_data')
        
        # If no structured SRS data, fall back to raw analysis
        if not srs_data:
            return function_analysis.get('raw_analysis', 'No analysis available')
        
        # Build formatted SRS specification
        output = []
        
        # Add archetype information
        archetype = srs_data.get('archetype', {})
        output.append("### Archetype Pattern")
        output.append(f"**Primary Pattern**: {archetype.get('primary_pattern', 'Unknown')}")
        output.append(f"**Reference**: {archetype.get('reference', 'N/A')}")
        output.append(f"**Confidence**: {archetype.get('confidence', 'Unknown')}")
        output.append(f"**Evidence**: {archetype.get('evidence_count', 'N/A')}")
        output.append("")
        
        # Add functional requirements
        frs = srs_data.get('functional_requirements', [])
        if frs:
            output.append("### Functional Requirements")
            for fr in frs:
                output.append(f"**{fr.get('id', 'FR-?')}** [{fr.get('priority', 'MANDATORY')}]")
                output.append(f"- **Requirement**: {fr.get('requirement', 'N/A')}")
                if fr.get('parameter'):
                    output.append(f"- **Parameter**: {fr['parameter']}")
                output.append(f"- **Rationale**: {fr.get('rationale', 'N/A')}")
                impl = fr.get('implementation', {})
                if impl.get('code'):
                    output.append(f"- **Implementation**:")
                    output.append(f"```{impl.get('language', 'c')}")
                    output.append(impl['code'])
                    output.append("```")
                output.append(f"- **Failure Mode**: {fr.get('failure_mode', 'Unknown')}")
                output.append("")
        
        # Add preconditions
        pres = srs_data.get('preconditions', [])
        if pres:
            output.append("### Preconditions")
            for pre in pres:
                output.append(f"**{pre.get('id', 'PRE-?')}** [{pre.get('priority', 'MANDATORY')}]")
                output.append(f"- **Requirement**: {pre.get('requirement', 'N/A')}")
                output.append(f"- **Check Method**: {pre.get('check_method', 'N/A')}")
                output.append(f"- **Rationale**: {pre.get('rationale', 'N/A')}")
                output.append(f"- **Violation → {pre.get('violation_consequence', 'Unknown')}**")
                output.append("")
        
        # Add postconditions
        posts = srs_data.get('postconditions', [])
        if posts:
            output.append("### Postconditions")
            for post in posts:
                output.append(f"**{post.get('id', 'POST-?')}** [{post.get('priority', 'MANDATORY')}]")
                output.append(f"- **Requirement**: {post.get('requirement', 'N/A')}")
                output.append(f"- **Check Method**: {post.get('check_method', 'N/A')}")
                output.append(f"- **Rationale**: {post.get('rationale', 'N/A')}")
                output.append("")
        
        # Add constraints
        cons = srs_data.get('constraints', [])
        if cons:
            output.append("### Constraints")
            for con in cons:
                output.append(f"**{con.get('id', 'CON-?')}** [Type: {con.get('type', 'Unknown')}]")
                output.append(f"- **Requirement**: {con.get('requirement', 'N/A')}")
                if con.get('parameter'):
                    output.append(f"- **Parameter**: {con['parameter']}")
                output.append(f"- **Valid Range/Sequence**: {con.get('valid_range_or_sequence', 'N/A')}")
                output.append(f"- **Rationale**: {con.get('rationale', 'N/A')}")
                
                # Add execution sequence if available
                impl = con.get('implementation', {})
                sequence = impl.get('sequence', [])
                if sequence:
                    output.append("- **Execution Sequence**:")
                    for step in sequence:
                        output.append(f"  {step.get('step', '?')}. {step.get('description', 'N/A')}")
                        if step.get('code'):
                            output.append(f"     ```c")
                            output.append(f"     {step['code']}")
                            output.append(f"     ```")
                output.append("")
        
        # Add parameter strategies
        params = srs_data.get('parameter_strategies', [])
        if params:
            output.append("### Parameter Strategies")
            for param in params:
                output.append(f"**Parameter**: `{param.get('parameter', 'unknown')}`")
                output.append(f"- **Type**: {param.get('type', 'unknown')}")
                output.append(f"- **Strategy**: {param.get('strategy', 'DIRECT_FUZZ')}")
                output.append(f"- **Construction**: {param.get('construction_method', 'N/A')}")
                if param.get('constraints'):
                    output.append(f"- **Constraints**: {param['constraints']}")
                if param.get('fixed_value'):
                    output.append(f"- **Fixed Value**: {param['fixed_value']}")
                if param.get('driver_code'):
                    output.append(f"- **Driver Code**:")
                    output.append(f"```c")
                    output.append(param['driver_code'])
                    output.append("```")
                output.append("")
        
        # Add metadata
        metadata = srs_data.get('metadata', {})
        if metadata:
            output.append("### Metadata")
            output.append(f"- **Category**: {metadata.get('category', 'Unknown')}")
            output.append(f"- **Complexity**: {metadata.get('complexity', 'Unknown')}")
            output.append(f"- **State Model**: {metadata.get('state_model', 'Unknown')}")
            output.append(f"- **Recommended Approach**: {metadata.get('recommended_approach', 'direct_call')}")
            output.append(f"- **Purpose**: {metadata.get('purpose', 'N/A')}")
            output.append("")
        
        # Add API Dependency Graph Information
        api_dependencies = function_analysis.get('api_dependencies')
        if api_dependencies and api_dependencies.get('call_sequence'):
            output.append("### 🔗 API Dependency Analysis")
            output.append("")
            output.append("**CRITICAL**: Follow this dependency graph to ensure correct initialization sequence!")
            output.append("")
            
            # Call sequence
            call_seq = api_dependencies.get('call_sequence', [])
            if call_seq:
                output.append("#### ✅ Recommended Call Sequence")
                output.append("Follow this order to ensure correct initialization:")
                for i, func in enumerate(call_seq, 1):
                    marker = " ← **TARGET FUNCTION**" if i == len(call_seq) else ""
                    output.append(f"{i}. `{func}`{marker}")
                output.append("")
            
            # Prerequisites
            prereqs = api_dependencies.get('prerequisites', [])
            if prereqs:
                output.append("#### ⚠️ Prerequisites (MUST call before target)")
                output.append("These initialization functions **MUST** be called before the target function:")
                for prereq in prereqs:
                    output.append(f"- `{prereq}()` - Initialization function")
                output.append("")
            
            # Data dependencies
            data_deps = api_dependencies.get('data_dependencies', [])
            if data_deps:
                output.append("#### 📊 Data Flow Dependencies")
                for src, dst in data_deps:
                    output.append(f"- `{src}` produces data consumed by `{dst}`")
                output.append("")
            
            # Initialization code template
            init_code = api_dependencies.get('initialization_code', [])
            if init_code:
                output.append("#### 💡 Initialization Code Template")
                output.append("```c")
                output.extend(init_code)
                output.append("```")
                output.append("")
        
        return "\n".join(output)
    
    def _retrieve_skeleton(self, function_analysis: dict) -> str:
        """
        Retrieve skeleton code from long-term memory based on archetype.
        Injects header information into the skeleton.
        
        Args:
            function_analysis: Analysis containing archetype and header information
            
        Returns:
            Skeleton code with header information or empty string if not found
        """
        try:
            from long_term_memory.retrieval import KnowledgeRetriever
            
            # Extract archetype from analysis
            # Priority 1: Check SRS JSON data (most reliable)
            srs_data = function_analysis.get('srs_data', {})
            archetype_info = srs_data.get('archetype', {})
            archetype = archetype_info.get('primary_pattern')
            
            # Priority 2: Fallback to raw analysis text
            if not archetype:
                raw_analysis = function_analysis.get('raw_analysis', '')
                archetype = self._extract_archetype_from_analysis(raw_analysis)
            
            if not archetype:
                logger.info('No archetype found in analysis, skipping skeleton retrieval', trial=self.trial)
                return ""
            
            retriever = KnowledgeRetriever()
            
            if archetype not in retriever.list_archetypes():
                logger.warning(f'Unknown archetype: {archetype}, skipping skeleton retrieval', trial=self.trial)
                return ""
            
            logger.info(f'Retrieving skeleton for archetype: {archetype}', trial=self.trial)
            skeleton = retriever.get_skeleton(archetype)
            
            # Inject header information into skeleton
            header_info = function_analysis.get('header_information', {})
            header_section = self._format_header_section(header_info, archetype)
            
            # Insert header info at the top of skeleton
            skeleton_with_headers = f"""{header_section}

{skeleton}"""
            
            return f"""
# Reference Skeleton

**⚠️ CRITICAL: This is a TEMPLATE showing the PATTERN, NOT code to copy literally!**

**How to use:**
1. 🥇 **COPY patterns from EXISTING FUZZERS** (highest priority - proven to compile)
2. 🥈 **Replace PLACEHOLDERS** with actual function calls from the public API
3. 🥉 **Keep the STRUCTURE** (error handling, cleanup order) but adapt the content

**Placeholders** like `PARSE_FUNCTION()`, `RESULT_TYPE`, `MIN_SIZE` are NOT real identifiers - replace them with actual API calls!

```c
{skeleton_with_headers}
```
"""
        except Exception as e:
            logger.warning(f'Failed to retrieve skeleton: {e}', trial=self.trial)
            return ""
    
    def _format_header_section(self, header_info: dict, archetype: str = None) -> str:
        """
        Format header information as C/C++ comments for skeleton injection.
        
        Priority (NEW - API-aware):
        - For C APIs: FuzzIntrospector headers > Definition file headers
        - For C++ APIs: Definition file headers > FuzzIntrospector headers
        
        Rationale:
        - C APIs often have separate declaration headers (e.g., ada_c.h vs ada.cpp)
        - C++ APIs usually declare in the same header they include (e.g., ada.h)
        
        Args:
            header_info: Dictionary containing header information
            archetype: Archetype name (used to determine required standard headers)
        """
        if not header_info:
            return "// NOTE: Header file information not available"
        
        # Detect API type
        is_c_api = header_info.get('is_c_api', False)
        
        # Start with LibFuzzer required headers
        header_lines = [
            "// === HEADER FILES ===",
            "// IMPORTANT: These headers are carefully selected from the project's source code.",
            "// Do NOT modify unless you encounter build errors (e.g., 'file not found').",
            "// If you see errors about internal headers (../../internal/, _impl.h, etc.),",
            "// remove them and use the public API headers instead.",
            "//",
            "// LibFuzzer required headers",
            "#include <stddef.h>",
            "#include <stdint.h>"
        ]
        
        # Add archetype-specific standard headers
        if archetype == "round_trip":
            header_lines.extend([
                "#include <stdlib.h>",
                "#include <string.h>",
                "#include <assert.h>"
            ])
        elif archetype == "file_based":
            header_lines.extend([
                "#include <stdio.h>",
                "#include <unistd.h>"
            ])
        
        header_lines.append("")  # Blank line after standard headers
        
        # ===== HEADER PRIORITY: EXISTING FUZZERS FIRST =====
        # RATIONALE: Existing fuzzer headers are PROVEN to compile in OSS-Fuzz
        # They are the ONLY source that guarantees correct paths and availability
        
        func_header = header_info.get('function_header')
        related_headers = header_info.get('related_headers', [])
        definition_headers = header_info.get('definition_file_headers')
        existing = header_info.get('existing_fuzzer_headers', {})
        
        has_fi_headers = func_header or related_headers
        has_definition = definition_headers and (
            definition_headers.get('standard_headers') or 
            definition_headers.get('project_headers')
        )
        has_existing = existing.get('standard_headers') or existing.get('project_headers')
        
        # PRIORITY 1 (HIGHEST): Headers from existing fuzzers
        if has_existing:
            header_lines.append("//")
            header_lines.append("// PRIMARY HEADERS (from working fuzzers - COPY THESE):")
            header_lines.append("// ⚠️ THESE ARE PROVEN TO COMPILE - use exactly as shown")
            header_lines.append("//")
            
            # Add project headers from existing fuzzers (highest confidence)
            existing_proj = existing.get('project_headers', [])[:5]  # Top 5 most common
            if existing_proj:
                # CRITICAL FILTER: Remove inappropriate headers
                filtered_headers = []
                for proj_h in existing_proj:
                    # ⚠️ KEEP .cpp/.cc files if they appear in existing fuzzers!
                    # Some projects (e.g., ada-url, header-only libs) explicitly include
                    # implementation files. If existing fuzzers use them, they're valid.
                    # DO NOT filter them out - trust the existing fuzzer patterns.
                    # (Previously we skipped .cpp files, but this broke single-header patterns)
                    
                    # For C API functions: prioritize C headers but keep .cpp if used by existing fuzzers
                    if is_c_api:
                        base_name = proj_h.lower()
                        
                        # ALWAYS keep .cpp/.cc/.cxx files (implementation includes)
                        # Even C API fuzzers may need them (e.g., ada_c.c needs ada.cpp)
                        if proj_h.endswith('.cpp') or proj_h.endswith('.cc') or proj_h.endswith('.cxx'):
                            filtered_headers.append(proj_h)
                            logger.debug(f'Keeping implementation file for C API (from existing fuzzers): {proj_h}', trial=self.trial)
                        # Keep C API headers (e.g., ada_c.h)
                        elif '_c.h' in base_name or base_name.endswith('_c.h'):
                            filtered_headers.append(proj_h)
                        # Keep generic .h files (might be C-compatible)
                        elif base_name.endswith('.h') and not any(cpp_indicator in base_name for cpp_indicator in ['.hpp', 'xx']):
                            filtered_headers.append(proj_h)
                        else:
                            # Skip pure C++ headers (ada.h, ada.hpp) for C API
                            logger.debug(f'Skipping C++ header for C API function: {proj_h}', trial=self.trial)
                    else:
                        # For C++ API: keep all headers (including both C++ and C headers)
                        filtered_headers.append(proj_h)
                
                if filtered_headers:
                    header_lines.append("// Project headers (copy these first):")
                    for proj_h in filtered_headers:
                        header_lines.append(f'#include "{proj_h}"')
                    header_lines.append("")
                else:
                    logger.warning(f'All existing project headers were filtered out for {"C" if is_c_api else "C++"} API', trial=self.trial)
            
            # Add standard headers from existing fuzzers (as comments - uncomment if needed)
            existing_std = existing.get('standard_headers', [])[:8]
            if existing_std:
                header_lines.append("// Standard headers from working fuzzers (uncomment if needed):")
                for std_h in existing_std:
                    header_lines.append(f'// #include <{std_h}>')
                header_lines.append("")
        
        # PRIORITY 2: API-specific headers (FI or Definition) - AS FALLBACK/REFERENCE
        # CASE 1: C API - FuzzIntrospector headers as SECONDARY/REFERENCE
        if is_c_api and has_fi_headers:
            header_lines.append("//")
            header_lines.append("// SECONDARY: FuzzIntrospector headers (C API - uncomment if needed):")
            header_lines.append("// NOTE: Existing fuzzer headers above are higher priority")
            header_lines.append("//")
            
            # Add FI's primary header as COMMENT (not directly included)
            if func_header:
                header_lines.append(f'// #include "{func_header}"  // FI suggestion')
                logger.info(f'FI header for C API (as reference): {func_header}', trial=self.trial)
            
            # Add related FI headers as comments (optional)
            if related_headers:
                for h in related_headers[:3]:
                    header_lines.append(f'// #include "{h}"')
            
            header_lines.append("")
            
            # Definition file headers become TERTIARY (supplementary standard headers only)
            if has_definition:
                std_headers = definition_headers.get('standard_headers', [])[:10]  # Limit to top 10
                if std_headers:
                    header_lines.append("// Supplementary standard headers (from definition file):")
                    for std_h in sorted(set(std_headers)):
                        header_lines.append(f'// #include {std_h}  // Uncomment if needed')
                    header_lines.append("")
        
        # CASE 2: C++ API OR No FI headers - Definition file headers as SECONDARY
        elif has_definition and not has_existing:
            # Only use definition headers if NO existing fuzzer headers are available
            header_lines.append("//")
            if is_c_api:
                header_lines.append("// SECONDARY: Headers from definition file (C API fallback):")
            else:
                header_lines.append("// SECONDARY: Headers from definition file (C++ API):")
            header_lines.append("//")
            
            # Add project headers (from definition file) - most important
            proj_headers = definition_headers.get('project_headers', [])
            if proj_headers:
                for proj_h in sorted(set(proj_headers)):
                    # Already includes " "
                    header_lines.append(f'#include {proj_h}')
                header_lines.append("")
            
            # Add standard library headers (from definition file) as comments
            std_headers = definition_headers.get('standard_headers', [])[:10]
            if std_headers:
                header_lines.append("// Standard headers from definition (uncomment if needed):")
                for std_h in sorted(set(std_headers)):
                    # Already includes < >
                    header_lines.append(f'// #include {std_h}')
                header_lines.append("")
            
            # FI headers become TERTIARY (as comments)
            if has_fi_headers:
                header_lines.append("// FuzzIntrospector headers (uncomment if needed):")
                if func_header:
                    header_lines.append(f'// #include "{func_header}"')
                for h in related_headers[:3]:
                    header_lines.append(f'// #include "{h}"')
                header_lines.append("")
        
        # CASE 3: Fallback - only FI headers available (lowest priority)
        elif has_fi_headers and not has_existing:
            header_lines.append("//")
            header_lines.append("// Headers from FuzzIntrospector (use with caution):")
            header_lines.append("//")
            
            if func_header:
                header_lines.append(f'// #include "{func_header}"  // May need path adjustment')
            
            if related_headers:
                for h in related_headers[:3]:
                    header_lines.append(f'// #include "{h}"')
            
            header_lines.append("")
        # ===============================================
        
        header_lines.append("// ====================")
        return "\n".join(header_lines)
    
    def _extract_archetype_from_analysis(self, analysis_text: str) -> Optional[str]:
        """
        Extract archetype from function analysis text.
        
        Looks for explicit archetype declarations or infers from keywords.
        """
        if not analysis_text:
            return None
        
        # Look for explicit archetype declaration
        import re
        
        # Pattern 1: "Primary pattern: {archetype}"
        # FIX: Use non-greedy match and stop at line end to avoid capturing next line
        pattern1 = r"Primary pattern:\s*([A-Za-z\-\s]+?)(?:\n|$)"
        match = re.search(pattern1, analysis_text, re.IGNORECASE)
        if match:
            archetype_name = match.group(1).strip().lower()
            # Normalize to our archetype names
            mapping = {
                "stateless parser": "stateless_parser",
                "object lifecycle": "object_lifecycle",
                "state machine": "state_machine",
                "stream processor": "stream_processor",
                "round-trip": "round_trip",
                "round trip": "round_trip",
                "file-based": "file_based",
                "file based": "file_based"
            }
            result = mapping.get(archetype_name)
            if result:
                logger.debug(f"Extracted archetype via Pattern 1: '{archetype_name}' -> '{result}'", trial=self.trial)
                return result
        
        # Pattern 2: "Archetype: {archetype}"
        # FIX: Use non-greedy match and stop at line end
        pattern2 = r"Archetype:\s*([A-Za-z\-\s]+?)(?:\n|$)"
        match = re.search(pattern2, analysis_text, re.IGNORECASE)
        if match:
            archetype_name = match.group(1).strip().lower()
            mapping = {
                "stateless parser": "stateless_parser",
                "object lifecycle": "object_lifecycle",
                "state machine": "state_machine",
                "stream processor": "stream_processor",
                "round-trip": "round_trip",
                "round trip": "round_trip",
                "file-based": "file_based",
                "file based": "file_based"
            }
            result = mapping.get(archetype_name)
            if result:
                logger.debug(f"Extracted archetype via Pattern 2: '{archetype_name}' -> '{result}'", trial=self.trial)
                return result
        
        logger.debug(f"No archetype pattern matched in analysis text (length: {len(analysis_text)})", trial=self.trial)
        return None
    


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
        
        # Extract header information from function_analysis (if available)
        function_analysis = state.get("function_analysis", {})
        header_info = function_analysis.get("header_information", {})
        header_hints = self._format_header_hints(header_info, build_errors)
        
        # 🔥 NEW: Add API validation warnings if available
        api_warnings = state.get("api_validation_warnings", "")
        
        # Combine all additional context
        additional_context_parts = []
        if header_hints:
            additional_context_parts.append(header_hints)
        if api_warnings:
            additional_context_parts.append("\n---\n\n# ⚠️  API Validation Warnings\n\n" + api_warnings)
        
        additional_context = "\n".join(additional_context_parts)
        
        # Build base prompt from template file
        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "enhancer",
            language=language,
            function_name=benchmark.get('function_name', 'unknown'),
            current_code=code_context,  # Use context instead of full code
            build_errors=error_text,
            additional_context=additional_context
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
        
        # Extract code from <fuzz_target> tags
        fuzz_target_code = parse_tag(response, 'fuzz_target')
        
        # If no tags found, use the whole response as fallback
        if not fuzz_target_code:
            fuzz_target_code = response
        
        # 🔥 CRITICAL VALIDATION: Check if target function name was changed
        target_function_name = benchmark.get('function_name', '')
        if target_function_name:
            violation_detected, violation_msg = self._validate_target_function_preserved(
                fuzz_target_code, 
                target_function_name
            )
            
            if violation_detected:
                logger.error(
                    f'❌ CRITICAL VIOLATION: Target function was changed! {violation_msg}',
                    trial=self.trial
                )
                # Force rebuild with error message explaining the violation
                state_update = {
                    "compile_success": False,
                    "build_errors": [
                        f"❌ VALIDATION ERROR: {violation_msg}",
                        f"",
                        f"YOU MUST CALL FUNCTION: {target_function_name}",
                        f"",
                        f"The target function name MUST remain exactly as specified.",
                        f"DO NOT replace it with similar-named functions.",
                        f"",
                        f"Add a direct call to {target_function_name}() inside LLVMFuzzerTestOneInput.",
                    ],
                    "session_memory": updated_session_memory
                }
                
                # Update retry counter
                if workflow_phase == "compilation":
                    compilation_retry_count = state.get("compilation_retry_count", 0)
                    state_update["compilation_retry_count"] = compilation_retry_count + 1
                else:
                    retry_count = state.get("retry_count", 0)
                    state_update["retry_count"] = retry_count + 1
                
                self._langgraph_logger.flush_agent_logs(self.name)
                return state_update
        
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
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
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
    
    def _format_header_hints(self, header_info: dict, build_errors: list) -> str:
        """
        Format header information as hints for the Enhancer to fix header-related errors.
        
        This method provides the LLM with known correct header paths extracted by
        FunctionAnalyzer, preventing it from blindly guessing incorrect paths.
        
        CRITICAL: This method now provides EXPLICIT PRIORITY GUIDANCE to prevent
        LLM from using internal headers extracted from source code.
        
        Args:
            header_info: Dictionary containing header information from FunctionAnalyzer
            build_errors: List of build errors to determine if header hints are needed
        
        Returns:
            Formatted string with header hints, or empty string if not needed
        """
        if not header_info:
            return ""
        
        # Check if there are header-related errors
        has_header_errors = any(
            'file not found' in error.lower() or 
            'no such file' in error.lower() or
            '#include' in error.lower()
            for error in build_errors
        )
        
        if not has_header_errors:
            # No header errors, don't add unnecessary context
            return ""
        
        hint_lines = [
            "",
            "# ⚡ Known Header Information (STRICT PRIORITY ORDER)",
            "",
            "⚠️  **CRITICAL**: Use headers in this STRICT priority order. Lower priority sources may contain",
            "INTERNAL implementation headers that WILL FAIL to compile in OSS-Fuzz fuzz targets.",
            ""
        ]
        
        # ANTI-PATTERN: Show what was FILTERED OUT first (negative examples)
        definition_headers = header_info.get('definition_file_headers', {})
        filtered_headers = definition_headers.get('filtered_headers', [])
        
        if filtered_headers:
            hint_lines.extend([
                "## ⛔ FILTERED HEADERS (DO NOT USE - WILL FAIL)",
                "",
                "The following headers were REMOVED because they cause compilation errors in fuzz targets.",
                "These are INTERNAL implementation details, NOT public API:",
                ""
            ])
            for item in filtered_headers[:10]:  # Show up to 10 examples
                hint_lines.append(f"  ❌ `{item['header']:40}` ← {item['reason']}")
            hint_lines.extend([
                "",
                "**If you see build errors mentioning these headers:**",
                "  1. ❌ DO NOT add them back - they are internal-only",
                "  2. ✅ Use the PUBLIC headers below instead",
                "  3. ✅ Public headers expose all necessary functionality",
                "",
                "---",
                ""
            ])
        
        # Priority 0: Headers from existing fuzzers (HIGHEST PRIORITY - PROVEN)
        existing_headers = header_info.get('existing_fuzzer_headers', {})
        existing_standard = existing_headers.get('standard_headers', [])
        existing_proj = existing_headers.get('project_headers', [])
        
        if existing_standard or existing_proj:
            hint_lines.extend([
                "## 🥇 PRIORITY 1: Headers from Working Fuzzers (COPY THESE)",
                "",
                "✅ **These headers are PROVEN to compile in OSS-Fuzz. USE EXACTLY AS SHOWN:**",
                ""
            ])
            
            if existing_standard:
                hint_lines.append("**Standard headers (from working fuzzers):**")
                for h in sorted(set(existing_standard))[:12]:
                    hint_lines.append(f"  #include <{h}>")
                hint_lines.append("")
            
            if existing_proj:
                hint_lines.append("**Project headers (from working fuzzers):**")
                for h in sorted(set(existing_proj))[:12]:
                    hint_lines.append(f'  #include "{h}"')
                hint_lines.append("")
            
            hint_lines.extend([
                "**WHY THIS IS PRIORITY 1**: These patterns are extracted from existing fuzzers that",
                "successfully compile in OSS-Fuzz. Copy these patterns for maximum success rate.",
                "",
                "---",
                ""
            ])
        
        # Priority 1: Public API headers from definition file
        if definition_headers:
            def_file = definition_headers.get('definition_file', 'unknown')
            std_headers = definition_headers.get('standard_headers', [])
            proj_headers = definition_headers.get('project_headers', [])
            
            if proj_headers or std_headers:
                hint_lines.extend([
                    "## 🥈 PRIORITY 2: Public API Headers (SAFE TO USE)",
                    "",
                    f"✅ From function definition file: `{def_file}`",
                    "✅ These passed internal/third-party filtering - safe for fuzz targets",
                    ""
                ])
                
                if proj_headers:
                    hint_lines.append("**Project public API headers:**")
                    for h in sorted(set(proj_headers))[:12]:
                        hint_lines.append(f"  {h}")
                    hint_lines.append("")
                
                if std_headers:
                    hint_lines.append("**Standard library headers:**")
                    for h in sorted(set(std_headers))[:12]:
                        hint_lines.append(f"  {h}")
                    hint_lines.append("")
                
                hint_lines.extend([
                    "---",
                    ""
                ])
        
        # Priority 2: FuzzIntrospector inferred headers (LOWEST PRIORITY)
        func_header = header_info.get('function_header')
        related_headers = header_info.get('related_headers', [])
        
        if func_header or related_headers:
            hint_lines.extend([
                "## 🥉 PRIORITY 3: FuzzIntrospector Suggestions (USE WITH CAUTION)",
                "",
                "⚠️  These are inferred by static analysis and may not always be correct.",
                ""
            ])
            
            if func_header:
                hint_lines.append(f"**Primary header:** `{func_header}`")
                hint_lines.append("")
            
            if related_headers:
                hint_lines.append("**Related headers:**")
                for h in related_headers[:8]:
                    hint_lines.append(f"  - {h}")
                hint_lines.append("")
            
            hint_lines.extend([
                "---",
                ""
            ])
        
        # Add explicit usage guidance
        hint_lines.extend([
            "## ⚡ How to Fix Header Errors (STRICT RULES)",
            "",
            "### Rule 1: Start with existing fuzzer headers (🥇 Priority 1)",
            "```c",
            "// ✅ CORRECT: Copy exact patterns from working fuzzers",
            "#include <igraph/igraph.h>",
            "#include <stdio.h>",
            "```",
            "",
            "### Rule 2: Add public API headers (🥈 Priority 2) if needed",
            "```c",
            '// ✅ CORRECT: Use filtered public headers',
            '#include "libraw/libraw.h"',
            "```",
            "",
            "### Rule 3: NEVER add filtered headers",
            "```c",
            "// ❌ WRONG: Filtered headers will fail!",
            '#include "../../internal/libraw_cxx_defs.h"  // FILTERED!',
            "#include <cs/cs.h>                           // THIRD-PARTY!",
            "```",
            "",
            "### Rule 4: When you see 'file not found' errors",
            "",
            "**DO:**",
            "  ✅ Check if the missing header is in FILTERED list → Remove it",
            "  ✅ Replace with equivalent from PUBLIC headers (Priority 1 or 2)",
            "  ✅ Use headers that match working fuzzer patterns",
            "",
            "**DON'T:**",
            "  ❌ Add headers from error messages without checking if they're filtered",
            "  ❌ Try variations like `internal/xxx.h`, `../private/xxx.h`, etc.",
            "  ❌ Add third-party dependency headers (`<cs/cs.h>`, `<boost/...>`, etc.)",
            "",
            "### Common Mistakes to Avoid:",
            "",
            "```c",
            "// ❌ WRONG (blindly adding from error messages):",
            '#include "internal/libraw_cxx_defs.h"',
            "",
            "// ✅ CORRECT (using public API):",
            '#include "libraw/libraw.h"',
            "```",
            "",
            "```c",
            "// ❌ WRONG (using internal dependency):",
            "#include <cs/cs.h>",
            "",
            "// ✅ CORRECT (use project's public API instead):",
            "#include <igraph/igraph.h>",
            "```",
            ""
        ])
        
        return "\n".join(hint_lines)
    
    def _validate_target_function_preserved(
        self, 
        code: str, 
        expected_function_name: str
    ) -> Tuple[bool, str]:
        """
        Validate that the target function name is preserved in the generated code.
        
        This is a CRITICAL constraint - the LLM must NOT change the target function
        to a similar-sounding function, even if it seems reasonable.
        
        Args:
            code: Generated fuzz target code
            expected_function_name: The required target function name
        
        Returns:
            (violation_detected, violation_message)
            - violation_detected: True if function was changed/missing
            - violation_message: Human-readable description of violation
        """
        import re
        
        # Remove comments and strings to avoid false positives
        code_no_comments = re.sub(r'//.*', '', code)
        code_no_comments = re.sub(r'/\*.*?\*/', '', code_no_comments, flags=re.DOTALL)
        code_no_strings = re.sub(r'"[^"]*"', '', code_no_comments)
        code_no_strings = re.sub(r"'[^']*'", '', code_no_strings)
        
        # Check 1: Is the target function called? (not just mentioned)
        # Look for function_name( or function_name ( with possible whitespace
        function_call_pattern = rf'\b{re.escape(expected_function_name)}\s*\('
        
        if not re.search(function_call_pattern, code_no_strings):
            # Function not called - check if a similar function is called instead
            similar_functions = self._find_similar_function_calls(code_no_strings, expected_function_name)
            
            if similar_functions:
                similar_list = ', '.join(f'`{f}`' for f in similar_functions[:3])
                return (
                    True,
                    f"Target function `{expected_function_name}()` was replaced with similar function(s): {similar_list}"
                )
            else:
                return (
                    True,
                    f"Target function `{expected_function_name}()` is not called in the fuzz target"
                )
        
        # Check 2: Ensure it's called in LLVMFuzzerTestOneInput (not just a helper function)
        # Extract LLVMFuzzerTestOneInput body
        llvm_fuzzer_pattern = r'int\s+LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        llvm_match = re.search(llvm_fuzzer_pattern, code_no_strings, re.DOTALL)
        
        if llvm_match:
            fuzzer_body = llvm_match.group(1)
            
            # Check if target function is called in the fuzzer body (or nested blocks)
            # Allow for calls through helper functions, but warn if it's too indirect
            if not re.search(function_call_pattern, fuzzer_body):
                # Not directly in fuzzer body - might be in a helper function
                # This is OK, but worth noting in logs
                logger.info(
                    f'Target function {expected_function_name}() may be called indirectly (through helper function)',
                    trial=self.trial
                )
        
        # All checks passed
        return (False, "")
    
    def _find_similar_function_calls(self, code: str, target_function: str) -> List[str]:
        """
        Find function calls that are similar to the target function name.
        
        This helps detect when LLM substitutes the target function with a
        similar-named function (e.g., ada_parse → ada_can_parse).
        
        Args:
            code: Code to search (should have comments/strings removed)
            target_function: The expected function name
        
        Returns:
            List of similar function names found in the code
        """
        import re
        from difflib import SequenceMatcher
        
        # Extract all function calls from code
        function_calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code)
        
        # Filter to only functions that are "similar" to target
        similar = []
        target_lower = target_function.lower()
        
        for func in set(function_calls):
            func_lower = func.lower()
            
            # Skip if it's the target function itself
            if func == target_function:
                continue
            
            # Check similarity criteria:
            # 1. Shares a common prefix/suffix
            # 2. Contains the target as substring or vice versa
            # 3. High edit distance similarity (>0.7)
            
            similarity = SequenceMatcher(None, target_lower, func_lower).ratio()
            
            if similarity > 0.7:
                similar.append(func)
            elif target_lower in func_lower or func_lower in target_lower:
                similar.append(func)
            elif len(target_function) > 3 and len(func) > 3:
                # Check common prefix (at least 60% of shorter name)
                common_prefix_len = len(os.path.commonprefix([target_lower, func_lower]))
                min_len = min(len(target_lower), len(func_lower))
                if common_prefix_len >= int(0.6 * min_len):
                    similar.append(func)
        
        return similar


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
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
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
        """Handle invalid tool usage."""
        logger.warning(f'ROUND {cur_round:02d} Invalid response from LLM: {response}',
                      trial=self.trial)
        
        prompt_text = 'No valid instruction received. Please use the available tools properly.\n\n'
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
            additional_context=""
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
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
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
            return 'No valid instruction received. Please use the available tools properly.\n\n'
        
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
            ADDITIONAL_CONTEXT=f"Project directory: {self.inspect_tool.project_dir}"
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
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
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
        prompt.add_problem('\n\nPlease provide a valid analysis following the requested format.')
        
        return prompt


class LangGraphImprover(LangGraphAgent):
    """
    Improver agent for LangGraph.
    
    This agent is responsible for improving fuzz driver quality based on
    coverage analysis recommendations. Unlike enhancer (which fixes compilation errors),
    improver rewrites the driver to increase code coverage.
    """
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("improver")
        
        super().__init__(
            name="improver",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Improve fuzz driver based on coverage analysis recommendations."""
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
        benchmark = state["benchmark"]
        current_code = state.get("fuzz_target_source", "")
        previous_code = state.get("previous_fuzz_target_source", "")
        coverage_analysis = state.get("coverage_analysis", {})
        
        # Determine language
        language = benchmark.get('language', 'C++')
        target_function = benchmark.get('function_name', 'unknown')
        
        # Extract improvement suggestions from coverage analysis
        suggestions = coverage_analysis.get("suggestions", "No specific suggestions provided")
        insights = coverage_analysis.get("insights", "")
        improve_required = coverage_analysis.get("improve_required", True)
        
        if not improve_required:
            logger.info('Coverage analyzer says no improvement required, skipping', trial=self.trial)
            return {"session_memory": state.get("session_memory", {})}
        
        # Get coverage metrics for context
        coverage_percent = state.get("coverage_percent", 0.0)
        line_coverage_diff = state.get("line_coverage_diff", 0.0)
        
        # Compress coverage analysis for prompt efficiency (Phase 1 optimization)
        compressed_insights = self._compress_coverage_insights(insights)
        compressed_suggestions = self._compress_coverage_suggestions(suggestions)
        
        # Build base prompt from template file
        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "improver",
            language=language,
            function_name=target_function,
            current_code=current_code,
            coverage_percent=f"{coverage_percent:.2%}",
            line_coverage_diff=f"{line_coverage_diff:.2%}",
            coverage_insights=compressed_insights,
            improvement_suggestions=compressed_suggestions
        )
        
        # Inject session_memory for consensus constraints
        prompt = build_prompt_with_session_memory(
            state,
            base_prompt,
            agent_name=self.name
        )
        
        # Chat with LLM (using improver's own message history)
        response = self.chat_llm(state, prompt)
        
        # Extract session_memory updates from response
        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # Merge updates to session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        # Extract improved code from <fuzz_target> tags
        improved_code = parse_tag(response, 'fuzz_target')
        
        # If no tags found, use the whole response as fallback
        if not improved_code:
            logger.warning('No <fuzz_target> tag found in improver response', trial=self.trial)
            improved_code = response
        
        # Validate that target function is still called
        target_function_name = benchmark.get('function_name', '')
        if target_function_name:
            violation_detected, violation_msg = self._validate_target_function_preserved(
                improved_code, 
                target_function_name
            )
            
            if violation_detected:
                logger.error(
                    f'❌ CRITICAL VIOLATION: Target function was changed! {violation_msg}',
                    trial=self.trial
                )
                # Return error state, forcing retry
                state_update = {
                    "compile_success": False,
                    "build_errors": [
                        f"❌ VALIDATION ERROR: {violation_msg}",
                        f"",
                        f"YOU MUST CALL FUNCTION: {target_function_name}",
                        f"",
                        f"The target function name MUST remain exactly as specified.",
                        f"DO NOT replace it with similar-named functions.",
                        f"",
                        f"Add a direct call to {target_function_name}() inside LLVMFuzzerTestOneInput.",
                    ],
                    "session_memory": updated_session_memory
                }
                
                self._langgraph_logger.flush_agent_logs(self.name)
                return state_update
        
        # Prepare state update with improved code
        state_update = {
            "fuzz_target_source": improved_code,
            "previous_fuzz_target_source": current_code,
            "compile_success": None,  # Reset to trigger rebuild
            "run_success": None,  # Reset to trigger re-execution
            "build_errors": [],
            "coverage_analysis": None,  # Clear to allow fresh analysis
            "session_memory": updated_session_memory,
            # Reset coverage improvement counter since we made changes
            "no_coverage_improvement_count": 0
        }
        
        # Increment improvement attempt counter
        improvement_count = state.get("improvement_attempt_count", 0)
        state_update["improvement_attempt_count"] = improvement_count + 1
        logger.info(f'Improvement attempt count: {improvement_count + 1}', trial=self.trial)
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
        return state_update
    
    def _compress_coverage_insights(self, insights: str) -> str:
        """
        Compress coverage insights to reduce prompt tokens while preserving key information.
        
        Strategy:
        - Extract core issues (max 3 bullet points)
        - Remove verbose explanations and code examples
        - Keep only actionable problems
        
        Expected reduction: ~80% (from ~4000 chars to ~800 chars)
        """
        if not insights or len(insights) < 100:
            return insights
        
        import re
        
        # Extract sections
        lines = insights.split('\n')
        compressed_lines = []
        
        # Look for bullet points (-, *, •) which usually contain key issues
        bullet_points = []
        for line in lines:
            stripped = line.strip()
            # Match bullet points
            if re.match(r'^[\-\*•]\s+\*\*.*?\*\*:', stripped):
                bullet_points.append(stripped)
        
        # If we found structured bullet points, use top 3
        if bullet_points:
            compressed = "\n".join(bullet_points[:3])
        else:
            # Fallback: extract first paragraph after "Root Cause" section
            root_cause_match = re.search(r'##\s*Root Cause[^\n]*\n(.*?)(?=\n##|\n\n\n|$)', insights, re.DOTALL)
            if root_cause_match:
                root_cause_text = root_cause_match.group(1).strip()
                # Take first 500 chars of root cause
                compressed = root_cause_text[:500]
                if len(root_cause_text) > 500:
                    compressed += "..."
            else:
                # Last resort: take first 400 chars
                compressed = insights[:400] + "..." if len(insights) > 400 else insights
        
        return compressed
    
    def _compress_coverage_suggestions(self, suggestions: str) -> str:
        """
        Compress coverage suggestions to reduce prompt tokens.
        
        Strategy:
        - Extract top 3 actionable recommendations
        - Remove code examples (main prompt has templates)
        - Keep only the recommendation text, not the code blocks
        
        Expected reduction: ~75% (from ~5000 chars to ~1200 chars)
        """
        if not suggestions or len(suggestions) < 100:
            return suggestions
        
        import re
        
        # Remove code blocks (```...```)
        no_code = re.sub(r'```[a-z]*\n.*?\n```', '[code example removed - see main template]', 
                        suggestions, flags=re.DOTALL)
        
        # Extract numbered recommendations (1., 2., 3., etc.)
        recommendations = []
        
        # Pattern: "1. **Something**:" or "1. Something:"
        pattern = r'(\d+)\.\s+\*\*([^:]+)\*\*:?\s*([^\n]*(?:\n(?!\d+\.)[^\n]*)*)'
        matches = re.finditer(pattern, no_code, re.MULTILINE)
        
        for match in matches:
            num = match.group(1)
            title = match.group(2)
            description = match.group(3).strip()
            
            # Take first 200 chars of description
            if len(description) > 200:
                description = description[:200] + "..."
            
            recommendations.append(f"{num}. **{title}**: {description}")
        
        # Return top 3 recommendations
        if recommendations:
            compressed = "\n\n".join(recommendations[:3])
        else:
            # Fallback: take first 600 chars
            compressed = no_code[:600] + "..." if len(no_code) > 600 else no_code
        
        return compressed
    
    def _validate_target_function_preserved(self, code: str, target_function_name: str) -> Tuple[bool, str]:
        """
        Validate that the target function is still called in the improved code.
        
        Args:
            code: Improved fuzz target code
            target_function_name: Name of the target function that must be called
        
        Returns:
            Tuple of (violation_detected, violation_message)
        """
        import re
        
        # Check for direct function call
        call_pattern = rf'\b{re.escape(target_function_name)}\s*\('
        if re.search(call_pattern, code):
            return (False, "")
        
        # Violation detected
        violation_msg = (
            f"Target function '{target_function_name}' is not called in the improved driver. "
            f"You must call this exact function."
        )
        return (True, violation_msg)

