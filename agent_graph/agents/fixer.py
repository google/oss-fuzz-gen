"""
LangGraphEnhancer agent for LangGraph workflow.
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

