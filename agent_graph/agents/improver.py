"""
LangGraphImprover agent for LangGraph workflow.
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

