"""
LangGraphFunctionAnalyzer agent for LangGraph workflow.
"""
from typing import Any, Dict, List, Optional, Tuple
import argparse
import os
import re
import json

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.utils import parse_tag
from agent_graph.prompt_loader import get_prompt_manager


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
        self.max_examples = getattr(args, 'max_function_examples', 5)
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
        
        # ========================================================================
        # DATA EXTRACTION: Get from context (prepared once at startup)
        # ========================================================================
        # Philosophy: No fallbacks. If context is missing, something is wrong upstream.
        context = state.get('context', None)
        
        if not context:
            # This should NEVER happen if run_single_fuzz.py did its job
            error_msg = (
                f'❌ FATAL: No fuzzing context in state!\n'
                f'This means data preparation failed but error was hidden.\n'
                f'Check run_single_fuzz.py::_prepare_shared_data_for_benchmark().'
            )
            logger.error(error_msg, trial=self.trial)
            raise RuntimeError(error_msg)
        
        logger.info(f'✅ Using fuzzing context (prepared in {context.get("preparation_time", 0):.2f}s)', trial=self.trial)
        
        # Extract data from context - all guaranteed to exist
        func_source = context.get('source_code', '')
        api_dependencies = context.get('api_dependencies', {})
        api_context = api_dependencies.get('api_context', {})  # Nested inside dependencies
        header_info = context.get('header_info', {})
        existing_fuzzer_headers = context.get('existing_fuzzer_headers', {})
        
        # Update header_info to include existing fuzzer headers
        if header_info is None:
            header_info = {}
        header_info["existing_fuzzer_headers"] = existing_fuzzer_headers
        
        # Log data summary (works for both shared_data and fallback paths)
        if api_context:
            param_count = len(api_context.get('parameters', []))
            init_pattern_count = len(api_context.get('initialization_patterns', []))
            example_count = len(api_context.get('usage_examples', []))
            related_func_count = len(api_context.get('related_functions', []))
            typedef_count = len(api_context.get('type_definitions', {}))
            
            logger.info(
                f'📊 API context available: {param_count} parameters, '
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
            logger.warning(f'⚠️ No API context available for {function_signature}', trial=self.trial)
        
        if api_dependencies and api_dependencies.get('call_sequence'):
            prereq_count = len(api_dependencies.get('prerequisites', []))
            data_dep_count = len(api_dependencies.get('data_dependencies', []))
            call_seq_len = len(api_dependencies.get('call_sequence', []))
            
            logger.info(
                f'🔗 API dependency graph available: {prereq_count} prerequisites, '
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
        
        # Log header information
        if header_info:
            std_count = len(header_info.get("existing_fuzzer_headers", {}).get('standard_headers', []))
            proj_count = len(header_info.get("existing_fuzzer_headers", {}).get('project_headers', []))
            logger.info(
                f'📚 Header information available:\n'
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
        
        # Use stateless iterative analysis - explicit SRS knowledge state
        logger.info('Using stateless iterative analysis (no conversation history)', trial=self.trial)
        response = self._execute_stateless_iterative_analysis(
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
    
    def _execute_stateless_iterative_analysis(
        self,
        state: FuzzingWorkflowState,
        project_name: str,
        function_signature: str,
        function_name: str,
        func_source: str,
        api_context: Optional[Dict] = None
    ) -> str:
        """
        Execute stateless iterative analysis using explicit SRS knowledge state.
        
        This method replaces conversation history with structured knowledge,
        reducing token consumption by ~87% while maintaining analysis quality.
        """
        from agent_graph.prompt_loader import get_prompt_manager
        from data_prep import introspector
        from agent_graph.srs_knowledge import (
            SRSKnowledge, 
            parse_srs_json_from_response,
            parse_incremental_updates_from_response
        )
        from agent_graph.state import add_api_constraint, set_archetype
        from agent_graph.memory import add_agent_message
        
        # Phase 1: Initial analysis (stateless)
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 1: Initial analysis (stateless)', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        
        prompt_manager = get_prompt_manager()
        
        # Build initial prompt
        from agent_graph.api_context_extractor import format_api_context_for_prompt
        api_context_text = format_api_context_for_prompt(api_context) if api_context else ""
        if api_context_text:
            logger.info(f'📝 API context: {len(api_context_text)} chars', trial=self.trial)
        
        initial_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_initial",
            FUNCTION_SIGNATURE=function_signature,
            FUNCTION_SOURCE=func_source,
            API_CONTEXT=api_context_text
        )
        
        logger.info(f'📤 Initial call: {len(initial_prompt)} chars', trial=self.trial)
        initial_response = self.call_llm_stateless(initial_prompt, state, "INITIAL")
        
        # Parse SRS knowledge
        initial_srs_json = parse_srs_json_from_response(initial_response)
        if initial_srs_json:
            knowledge = SRSKnowledge.from_json(initial_srs_json)
            knowledge.target_function = function_name
            logger.info('✅ Parsed initial SRS knowledge', trial=self.trial)
        else:
            knowledge = SRSKnowledge()
            knowledge.target_function = function_name
            logger.warning('⚠️ Using minimal SRS structure', trial=self.trial)
        
        stats = knowledge.get_stats()
        logger.info(f'📊 Initial: {stats["total_preconditions"]} pre, {stats["total_constraints"]} con',
                   trial=self.trial)
        
        # Phase 2: Query call sites
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 2: Querying call sites', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        
        # Note: call_sites API 在这里是合理使用场景
        # 因为这个 agent 需要：
        #  1. 迭代式学习（从多个调用示例中逐步提取知识）
        #  2. 精细控制（参数设置、返回值使用的上下文分析）
        #  3. 元数据（文件名、行号用于日志）
        # 对于一般的 driver 生成，应该使用 test_xrefs + sample_xrefs
        call_sites = introspector.query_introspector_call_sites_metadata(project_name, function_signature)
        examples_analyzed = 0
        
        if call_sites:
            logger.info(f'🔍 Found {len(call_sites)} call sites (max: {self.max_examples})', trial=self.trial)
            call_sites = call_sites[:self.max_examples]
            
            # Phase 3: Stateless refinement
            logger.info('=' * 80, trial=self.trial)
            logger.info('🔬 Phase 3: Stateless refinement', trial=self.trial)
            logger.info('=' * 80, trial=self.trial)
            
            for i, call_site in enumerate(call_sites, 1):
                logger.info(f'📍 Example {i}/{len(call_sites)}', trial=self.trial)
                
                context = self._extract_call_context(call_site, project_name)
                if not context:
                    logger.warning(f'   ⚠️ No context, skipping', trial=self.trial)
                    continue
                
                # Build refine prompt with embedded knowledge
                refine_prompt = prompt_manager.build_user_prompt(
                    "function_analyzer_incremental_refine",
                    FUNCTION_SIGNATURE=function_signature,
                    CURRENT_SRS_KNOWLEDGE=knowledge.to_compact_text(max_items_per_section=10),
                    EXAMPLES_ANALYZED=examples_analyzed,
                    EXAMPLE_NUMBER=i,
                    CALLER_NAME=context.get('caller_name', 'unknown'),
                    CALL_LINE_NUMBER=context.get('call_line_number', '?'),
                    CONTEXT_BEFORE=context.get('context_before', ''),
                    CALL_STATEMENT=context.get('call_statement', ''),
                    CONTEXT_AFTER=context.get('context_after', ''),
                    PARAMETER_SETUP=context.get('parameter_setup', 'N/A'),
                    RETURN_USAGE=context.get('return_usage', 'N/A')
                )
                
                try:
                    refine_response = self.call_llm_stateless(refine_prompt, state, f"REFINE_{i}")
                    updates = parse_incremental_updates_from_response(refine_response)
                    changed = knowledge.merge_updates(updates, iteration=i)
                    
                    if changed:
                        examples_analyzed += 1
                        logger.info(f'   ✅ Updated', trial=self.trial)
                    else:
                        logger.info(f'   📥 No new info', trial=self.trial)
                except Exception as e:
                    logger.error(f'   ❌ Error: {e}', trial=self.trial)
                    continue
                
                if knowledge.has_converged(threshold=self.convergence_threshold):
                    logger.info(f'🎯 Converged after {examples_analyzed} examples', trial=self.trial)
                    break
        else:
            logger.warning(f'⚠️ No call sites found', trial=self.trial)
        
        # Phase 4: Generate final SRS
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 4: Final SRS', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        
        archetype_knowledge = self._retrieve_archetype_knowledge(state)
        final_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_final_summary",
            FUNCTION_SIGNATURE=function_signature,
            EXAMPLES_COUNT=examples_analyzed,
            ARCHETYPE_KNOWLEDGE=archetype_knowledge
        )
        
        # Embed accumulated knowledge
        final_prompt_full = f"""{final_prompt}

---

# ACCUMULATED KNOWLEDGE ({examples_analyzed} examples):

{knowledge.to_compact_text(max_items_per_section=20)}

Generate complete SRS incorporating all knowledge above.
"""
        
        final_response = self.call_llm_stateless(final_prompt_full, state, "FINAL")
        logger.info(f'📥 Final SRS: {len(final_response)} chars', trial=self.trial)
        
        # Update session_memory
        final_srs = parse_srs_json_from_response(final_response)
        if final_srs:
            archetype_data = final_srs.get('archetype', {})
            if archetype_data.get('primary_pattern') != 'unknown':
                set_archetype(
                    state,
                    archetype_type=archetype_data.get('primary_pattern', 'unknown'),
                    lifecycle_phases=archetype_data.get('lifecycle_phases', []),
                    source=self.name,
                    iteration=state.get('current_iteration', 0)
                )
            
            # Add top constraints to session_memory
            for pre in final_srs.get('preconditions', [])[:5]:
                if pre.get('priority') in ['MANDATORY', 'RECOMMENDED']:
                    add_api_constraint(
                        state,
                        constraint=pre.get('requirement', ''),
                        source=self.name,
                        confidence="high" if pre.get('priority') == 'MANDATORY' else "medium",
                        iteration=state.get('current_iteration', 0)
                    )
        
        # Save only final to agent_messages (not iterations)
        add_agent_message(state, self.name, "user", f"Generate SRS for {function_signature}")
        add_agent_message(state, self.name, "assistant", final_response)
        
        logger.info(f'📊 Stateless analysis complete: {examples_analyzed} examples processed', trial=self.trial)
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

