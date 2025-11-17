"""
LangGraphPrototyper agent for LangGraph workflow.
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
        
        # Add API Composition Information
        api_dependencies = function_analysis.get('api_dependencies')
        if api_dependencies and api_dependencies.get('call_sequence'):
            from agent_graph.api_composition_analyzer import format_api_combinations_for_prompt
            
            func_sig = function_analysis.get('function_signature', '')
            api_dep_text = format_api_combinations_for_prompt(api_dependencies, func_sig)
            
            if api_dep_text:
                output.append(api_dep_text)
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
                "file based": "file_based",
                "global initialization": "global_initialization",
                "global init": "global_initialization",
                "stateful fuzzing": "stateful_fuzzing",
                "stateful": "stateful_fuzzing"
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
                "file based": "file_based",
                "global initialization": "global_initialization",
                "global init": "global_initialization",
                "stateful fuzzing": "stateful_fuzzing",
                "stateful": "stateful_fuzzing"
            }
            result = mapping.get(archetype_name)
            if result:
                logger.debug(f"Extracted archetype via Pattern 2: '{archetype_name}' -> '{result}'", trial=self.trial)
                return result
        
        logger.debug(f"No archetype pattern matched in analysis text (length: {len(analysis_text)})", trial=self.trial)
        return None
    

