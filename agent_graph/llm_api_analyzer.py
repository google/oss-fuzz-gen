#!/usr/bin/env python3
"""
LLM-based API Dependency Analyzer

Uses LLM reasoning to identify API call patterns and dependencies,
providing a general solution that adapts to different libraries
without hardcoded heuristics.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from data_prep import introspector
from agent_graph.api_context_extractor import APIContextExtractor
from llm_toolkit.models import LLM

logger = logging.getLogger(__name__)


class LLMAPIDependencyAnalyzer:
    """
    Uses LLM to analyze API dependencies in a general, adaptable way.
    
    Instead of hardcoded heuristics, this analyzer:
    1. Gathers rich context from FuzzIntrospector
    2. Feeds it to an LLM with a structured prompt
    3. Gets back a JSON analysis of API dependencies
    
    This approach is more general and can handle diverse API patterns.
    """
    
    def __init__(
        self,
        project_name: str,
        llm: LLM,
        system_prompt: str = "",
        user_prompt_template: str = ""
    ):
        """
        Initialize the LLM-based analyzer.
        
        Args:
            project_name: Name of the project being analyzed
            llm: LLM instance to use for analysis
            system_prompt: System prompt for the LLM (analyzer instructions)
            user_prompt_template: Template for user prompt (with placeholders)
        """
        self.project_name = project_name
        self.llm = llm
        self.system_prompt = system_prompt
        self.user_prompt_template = user_prompt_template
        self.extractor = APIContextExtractor(project_name)
    
    def analyze_dependencies(
        self,
        target_function: str,
        max_xrefs: int = 5,
        max_related: int = 10
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze API dependencies for a target function using LLM.
        
        Args:
            target_function: Function signature to analyze
            max_xrefs: Maximum number of cross-references to include
            max_related: Maximum number of related functions to include
            
        Returns:
            Dictionary with structured dependency analysis, or None if failed
        """
        logger.info(f"LLM analyzing API dependencies for {target_function}")
        
        try:
            # 1. Gather context from FuzzIntrospector
            context = self._gather_context(target_function, max_xrefs, max_related)
            if not context:
                logger.warning(f"Could not gather context for {target_function}")
                return None
            
            # 2. Build prompt
            user_prompt = self._build_prompt(target_function, context)
            
            # 3. Call LLM
            messages = []
            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            messages.append({"role": "user", "content": user_prompt})
            
            logger.debug(f"Calling LLM (prompt: {len(user_prompt)} chars)")
            response = self.llm.chat_with_messages(messages)
            
            # 4. Parse response (let JSON errors propagate to outer catch)
            analysis = self._parse_response(response)
            self._log_analysis_summary(target_function, analysis)
            return analysis
            
        except json.JSONDecodeError as e:
            # This means prompt is broken - log raw response for debugging
            logger.error(f"LLM returned invalid JSON: {e}")
            logger.debug(f"Raw LLM response: {response[:1000]}")
            return None
        except Exception as e:
            # Network errors, introspector failures, etc
            logger.error(f"LLM analysis failed: {e}", exc_info=True)
            return None
    
    def _gather_context(
        self,
        func_sig: str,
        max_xrefs: int,
        max_related: int
    ) -> Optional[Dict[str, Any]]:
        """Gather all relevant context from FuzzIntrospector."""
        # Get basic function info
        func_context = self.extractor.extract(func_sig)
        if not func_context:
            return None
        
        # Get function source
        func_source = introspector.query_introspector_function_source(
            self.project_name, func_sig
        )
        
        # Get cross-references (functions that call this one)
        xrefs = introspector.query_introspector_cross_references(
            self.project_name, func_sig
        )
        
        # Get sample xrefs (usage examples)
        sample_xrefs = introspector.query_introspector_sample_xrefs(
            self.project_name, func_sig
        )
        
        # Get call site metadata
        call_sites = introspector.query_introspector_call_sites_metadata(
            self.project_name, func_sig
        )
        
        # Build context
        context = {
            'parameters': func_context.get('parameters', []),
            'return_type': func_context.get('return_type', 'unknown'),
            'function_source': func_source or "// Source not available",
            'cross_references': xrefs[:max_xrefs] if xrefs else [],
            'sample_xrefs': sample_xrefs[:max_xrefs] if sample_xrefs else [],
            'related_functions': [
                f['name'] for f in func_context.get('related_functions', [])[:max_related]
            ],
            'call_sites': call_sites[:max_xrefs] if call_sites else []
        }
        
        logger.debug(
            f"Gathered context: {len(context['parameters'])} params, "
            f"{len(context['cross_references'])} xrefs, "
            f"{len(context['sample_xrefs'])} samples, "
            f"{len(context['related_functions'])} related funcs"
        )
        
        return context
    
    def _build_prompt(self, func_sig: str, context: Dict[str, Any]) -> str:
        """
        Build the user prompt from template and context.
        """
        # Format parameters
        params_text = self._format_parameters(context.get('parameters', []))
        
        # Format cross-references section
        xrefs = context.get('cross_references', [])
        if xrefs:
            xrefs_text = f"\n## Cross-References (Functions calling {func_sig})\n\n"
            xrefs_text += "These are real examples of how this function is used:\n\n"
            for i, xref in enumerate(xrefs[:3], 1):  # Limit to 3 to avoid token overflow
                xrefs_text += f"### Example {i}\n\n```c\n{xref}\n```\n\n"
        else:
            xrefs_text = "\n## Cross-References\n\nNo cross-references available.\n"
        
        # Format sample xrefs
        sample_xrefs = context.get('sample_xrefs', [])
        if sample_xrefs:
            samples_text = "\n## Sample Usage Code\n\n"
            for i, sample in enumerate(sample_xrefs[:3], 1):
                samples_text += f"### Sample {i}\n\n```c\n{sample}\n```\n\n"
        else:
            samples_text = ""
        
        # Format related functions
        related = context.get('related_functions', [])
        if related:
            related_text = f"\n## Related Functions\n\n"
            related_text += "Functions with similar naming or operating on similar types:\n\n"
            for func in related:
                related_text += f"- `{func}`\n"
        else:
            related_text = ""
        
        # Build final prompt
        prompt = self.user_prompt_template.format(
            function_signature=func_sig,
            project_name=self.project_name,
            parameters=params_text,
            function_source=context.get('function_source', '// Not available')[:2000],  # Truncate
            cross_references_section=xrefs_text,
            related_functions_section=related_text,
            sample_xrefs_section=samples_text
        )
        
        return prompt
    
    def _format_parameters(self, parameters: List[Dict]) -> str:
        """Format parameter list for prompt."""
        if not parameters:
            return "No parameter information available."
        
        lines = []
        for i, param in enumerate(parameters, 1):
            param_type = param.get('type', 'unknown')
            param_name = param.get('name', f'param{i}')
            lines.append(f"{i}. `{param_type} {param_name}`")
        
        return "\n".join(lines)
    
    def _parse_response(self, response: str) -> Optional[Dict[str, Any]]:
        """
        Parse LLM response. Expects valid JSON with all required fields.
        If format is wrong, that's a prompt problem - let it fail loudly.
        """
        json_text = response.strip()
        
        # Handle markdown wrapper (```json ... ```) - some LLMs ignore instructions
        if json_text.startswith("```"):
            lines = json_text.split("\n")
            json_text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        
        # Parse JSON - let it crash if invalid
        return json.loads(json_text)
    
    def _log_analysis_summary(self, func_sig: str, analysis: Dict[str, Any]):
        """Log a summary of the analysis results."""
        prereq_count = len(analysis.get('prerequisites', []))
        config_count = len(analysis.get('configuration', []))
        comp_count = len(analysis.get('complementary', []))
        cleanup_count = len(analysis.get('cleanup', []))
        data_dep_count = len(analysis.get('data_dependencies', []))
        
        logger.info(
            f"✅ LLM API analysis complete for {func_sig}:\n"
            f"  ├─ Prerequisites: {prereq_count}\n"
            f"  ├─ Configuration: {config_count}\n"
            f"  ├─ Complementary: {comp_count}\n"
            f"  ├─ Cleanup: {cleanup_count}\n"
            f"  └─ Data dependencies: {data_dep_count}"
        )
        
        # Log details at debug level
        if prereq_count > 0:
            prereqs = [p['function'] for p in analysis['prerequisites']]
            logger.debug(f"  Prerequisites: {', '.join(prereqs)}")
        
        if config_count > 0:
            configs = [c['function'] for c in analysis['configuration']]
            logger.debug(f"  Configuration: {', '.join(configs)}")
    
    def convert_to_legacy_format(self, llm_analysis: Dict[str, Any], target_function: str) -> Dict[str, Any]:
        """
        Convert LLM analysis to the legacy format expected by existing code.
        
        This maintains backward compatibility while using LLM-based analysis.
        
        Args:
            llm_analysis: Analysis result from LLM
            target_function: The target function being analyzed
            
        Returns:
            Dictionary in the old APIDependencyAnalyzer format
        """
        # Extract function names with confidence filtering (one-liner per category)
        def extract_funcs(key: str) -> List[str]:
            return [
                item['function'] for item in llm_analysis.get(key, [])
                if item.get('confidence', 'low') in ['high', 'medium']
            ]
        
        prerequisites = extract_funcs('prerequisites')
        configuration = extract_funcs('configuration')
        complementary = extract_funcs('complementary')
        cleanup = extract_funcs('cleanup')
        
        # Build call sequence: prerequisites -> config -> target -> complementary -> cleanup
        # Use dict.fromkeys() to dedupe while preserving order (simpler than set tracking)
        call_sequence = list(dict.fromkeys(
            prerequisites + configuration + [target_function] + complementary + cleanup
        ))
        
        # Convert data dependencies to tuples
        data_deps = [
            (dep['producer'], dep['consumer'])
            for dep in llm_analysis.get('data_dependencies', [])
        ]
        
        # Generate initialization code from call pattern example
        init_code_lines = []
        if llm_analysis.get('call_pattern_example'):
            init_code_lines.append("// API Usage Pattern (from LLM analysis)")
            init_code_lines.append("// " + "="*60)
            for line in llm_analysis['call_pattern_example'].split('\n'):
                init_code_lines.append(f"// {line}")
        
        return {
            'prerequisites': prerequisites,
            'data_dependencies': data_deps,
            'call_sequence': call_sequence,
            'initialization_code': init_code_lines,
            'llm_metadata': {
                'confidence_note': llm_analysis.get('confidence_note', ''),
                'has_call_pattern': bool(llm_analysis.get('call_pattern_example')),
                'configuration_functions': configuration,
                'complementary_functions': complementary,
                'cleanup_functions': cleanup
            }
        }


def load_prompts() -> tuple[str, str]:
    """
    Load system and user prompt templates from files.
    
    Returns:
        Tuple of (system_prompt, user_prompt_template)
    """
    import os
    
    prompts_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'prompts',
        'agent_graph'
    )
    
    system_prompt_path = os.path.join(prompts_dir, 'api_dependency_analyzer_system.txt')
    user_prompt_path = os.path.join(prompts_dir, 'api_dependency_analyzer_prompt.txt')
    
    try:
        with open(system_prompt_path, 'r') as f:
            system_prompt = f.read()
    except FileNotFoundError:
        logger.warning(f"System prompt not found at {system_prompt_path}, using default")
        system_prompt = "You are an API dependency analyzer. Analyze the given function and identify related API calls."
    
    try:
        with open(user_prompt_path, 'r') as f:
            user_prompt_template = f.read()
    except FileNotFoundError:
        logger.warning(f"User prompt template not found at {user_prompt_path}, using default")
        user_prompt_template = "Analyze: {function_signature}"
    
    return system_prompt, user_prompt_template


if __name__ == "__main__":
    # Simple test
    import sys
    import argparse
    
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("project", help="Project name")
    parser.add_argument("function", help="Function signature")
    parser.add_argument("--model", default="gpt-4o-mini", help="LLM model")
    parser.add_argument("--endpoint", default="http://0.0.0.0:8080/api", help="Introspector endpoint")
    
    args = parser.parse_args()
    
    # Setup
    from data_prep.introspector import set_introspector_endpoints
    set_introspector_endpoints(args.endpoint)
    
    # Create LLM
    llm = LLM(model=args.model)
    
    # Load prompts
    system_prompt, user_prompt_template = load_prompts()
    
    # Create analyzer
    analyzer = LLMAPIDependencyAnalyzer(
        project_name=args.project,
        llm=llm,
        system_prompt=system_prompt,
        user_prompt_template=user_prompt_template
    )
    
    # Analyze
    result = analyzer.analyze_dependencies(args.function)
    
    if result:
        print("\n" + "="*80)
        print("LLM API DEPENDENCY ANALYSIS")
        print("="*80)
        print(json.dumps(result, indent=2))
        
        print("\n" + "="*80)
        print("LEGACY FORMAT (for compatibility)")
        print("="*80)
        legacy = analyzer.convert_to_legacy_format(result, args.function)
        print(json.dumps(legacy, indent=2))
    else:
        print("Analysis failed")
        sys.exit(1)

