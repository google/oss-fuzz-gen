"""
LangGraphContextAnalyzer agent for LangGraph workflow.
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


class LangGraphContextAnalyzer(LangGraphAgent):
    """
    Context analyzer agent for LangGraph - analyzes crash feasibility.
    
    Uses OpenAI Function Calling with comprehensive FuzzIntrospector API tools.
    Provides 8+ tools for deep project analysis: functions, types, headers, tests, etc.
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
        self.fi_tool = None  # FuzzIntrospector tool
        self.project_name = None
    
    def _get_tool_definitions(self) -> list[dict]:
        """
        Define comprehensive FuzzIntrospector API tools for ContextAnalyzer.
        
        Provides 9 tools covering function analysis, types, headers, tests, and bash execution.
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "bash_execute",
                    "description": "Execute bash command in the project container to search files or examine source code",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Bash command (e.g., 'grep -rn pattern /src', 'cat /path/to/file.c')"
                            }
                        },
                        "required": ["command"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_implementation",
                    "description": "Get the full source code implementation of a function by its name",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function (e.g., 'sam_hrecs_remove_ref_altnames')"
                            }
                        },
                        "required": ["function_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_signature",
                    "description": "Get the full signature of a function (return type + name + parameters)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function"
                            }
                        },
                        "required": ["function_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_sample_cross_references",
                    "description": "Get sample code snippets showing how a function is called/used in the project",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_signature": {
                                "type": "string",
                                "description": "Full function signature (e.g., 'void func(int x)')"
                            }
                        },
                        "required": ["function_signature"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_type_definitions",
                    "description": "Get all type definitions (structs, enums, typedefs) in the project",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_headers_for_function",
                    "description": "Get the list of header files that need to be included to use a function",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_signature": {
                                "type": "string",
                                "description": "Full function signature"
                            }
                        },
                        "required": ["function_signature"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_tests_for_functions",
                    "description": "Get test code that uses specific functions, showing real-world usage examples",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_names": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of function names to search for in tests"
                            }
                        },
                        "required": ["function_names"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_debug_types",
                    "description": "Get detailed type information for function parameters (useful for understanding complex types)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_signature": {
                                "type": "string",
                                "description": "Full function signature"
                            }
                        },
                        "required": ["function_signature"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_functions_by_return_type",
                    "description": "Find functions that return a specific type (useful for finding constructors/factories)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "return_type": {
                                "type": "string",
                                "description": "Type to search for (e.g., 'sam_hrecs_t *', 'int')"
                            }
                        },
                        "required": ["return_type"]
                    }
                }
            }
        ]
    
    def _init_fi_tool(self, project_name: str):
        """Initialize FuzzIntrospector tool for the project."""
        if self.fi_tool is None or self.project_name != project_name:
            from data_prep.introspector import FuzzIntrospectorTool
            logger.info(f"Initializing FuzzIntrospector for project: {project_name}", trial=self.trial)
            self.fi_tool = FuzzIntrospectorTool(project_name)
            self.project_name = project_name
    
    def _execute_tool(self, tool_call: dict) -> str:
        """Execute a tool call and return the result."""
        tool_name = tool_call.get("name", "")
        arguments = tool_call.get("arguments", {})
        
        try:
            if tool_name == "bash_execute":
                command = arguments.get("command", "")
                if not command:
                    return "Error: bash_execute requires 'command' argument"
                
                result = self.inspect_tool.execute(command)
                return self._format_bash_result(result)
            
            elif tool_name == "get_function_implementation":
                function_name = arguments.get("function_name", "")
                if not function_name:
                    return "Error: get_function_implementation requires 'function_name' argument"
                
                impl = self.fi_tool.get_function_implementation(self.project_name, function_name)
                if impl:
                    return f"Function implementation for '{function_name}':\n```c\n{impl}\n```"
                return f"Error: Could not find implementation for function '{function_name}'"
            
            elif tool_name == "get_function_signature":
                function_name = arguments.get("function_name", "")
                if not function_name:
                    return "Error: get_function_signature requires 'function_name' argument"
                
                signature = self.fi_tool.get_function_signature(function_name)
                if signature:
                    return f"Function signature: {signature}"
                return f"Error: Could not find signature for function '{function_name}'"
            
            elif tool_name == "get_sample_cross_references":
                function_signature = arguments.get("function_signature", "")
                if not function_signature:
                    return "Error: get_sample_cross_references requires 'function_signature' argument"
                
                cross_refs = self.fi_tool.get_sample_cross_references(function_signature)
                if cross_refs:
                    result = f"Sample usage examples for '{function_signature}':\n\n"
                    for i, ref in enumerate(cross_refs[:5], 1):  # Limit to 5 examples
                        result += f"Example {i}:\n```c\n{ref}\n```\n\n"
                    return result
                return f"No cross-references found for '{function_signature}'"
            
            elif tool_name == "get_type_definitions":
                type_defs = self.fi_tool.get_type_definitions()
                if type_defs:
                    result = "Type definitions in project:\n\n"
                    for typedef in type_defs[:20]:  # Limit to 20 to avoid token overflow
                        name = typedef.get("name", "Unknown")
                        kind = typedef.get("kind", "Unknown")
                        defn = typedef.get("definition", "")
                        result += f"- {name} ({kind})\n"
                        if defn:
                            result += f"  ```c\n  {defn}\n  ```\n"
                    if len(type_defs) > 20:
                        result += f"\n... and {len(type_defs) - 20} more type definitions"
                    return result
                return "No type definitions found"
            
            elif tool_name == "get_headers_for_function":
                function_signature = arguments.get("function_signature", "")
                if not function_signature:
                    return "Error: get_headers_for_function requires 'function_signature' argument"
                
                headers = self.fi_tool.get_headers_for_function(function_signature)
                if headers:
                    result = f"Required headers for '{function_signature}':\n"
                    for header in headers:
                        result += f"  #include <{header}>\n"
                    return result
                return f"No header information found for '{function_signature}'"
            
            elif tool_name == "get_tests_for_functions":
                function_names = arguments.get("function_names", [])
                if not function_names:
                    return "Error: get_tests_for_functions requires 'function_names' array argument"
                
                tests = self.fi_tool.get_tests_for_functions(function_names)
                if tests:
                    result = f"Test examples for functions: {', '.join(function_names)}\n\n"
                    for func, test_code in tests.items():
                        if test_code:
                            result += f"Tests for '{func}':\n```c\n{test_code}\n```\n\n"
                    return result
                return f"No tests found for functions: {', '.join(function_names)}"
            
            elif tool_name == "get_function_debug_types":
                function_signature = arguments.get("function_signature", "")
                if not function_signature:
                    return "Error: get_function_debug_types requires 'function_signature' argument"
                
                debug_types = self.fi_tool.get_function_debug_types(function_signature)
                if debug_types:
                    result = f"Debug type information for '{function_signature}':\n"
                    for i, dtype in enumerate(debug_types, 1):
                        result += f"  Parameter {i}: {dtype}\n"
                    return result
                return f"No debug type information found for '{function_signature}'"
            
            elif tool_name == "get_functions_by_return_type":
                return_type = arguments.get("return_type", "")
                if not return_type:
                    return "Error: get_functions_by_return_type requires 'return_type' argument"
                
                functions = self.fi_tool.get_functions_by_return_type(return_type)
                if functions:
                    result = f"Functions returning '{return_type}':\n"
                    for func in functions[:10]:  # Limit to 10
                        func_name = func.get("function_name", "Unknown")
                        func_sig = func.get("function_signature", "")
                        result += f"  - {func_name}\n"
                        if func_sig:
                            result += f"    Signature: {func_sig}\n"
                    if len(functions) > 10:
                        result += f"\n... and {len(functions) - 10} more functions"
                    return result
                return f"No functions found returning '{return_type}'"
            
            else:
                return f"Error: Unknown tool '{tool_name}'"
                
        except Exception as e:
            logger.error(f"Error executing tool '{tool_name}': {e}", trial=self.trial)
            return f"Error executing {tool_name}: {str(e)}"
    
    def _format_bash_result(self, result: Any) -> str:
        """Format bash execution result."""
        if hasattr(result, 'stdout'):
            # Result is a subprocess.CompletedProcess-like object
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            
            # Limit output size
        max_output_len = 10000
        if len(stdout) > max_output_len:
            stdout = stdout[:max_output_len] + f'\n... (truncated {len(stdout) - max_output_len} chars)'
        if len(stderr) > max_output_len:
            stderr = stderr[:max_output_len] + f'\n... (truncated {len(stderr) - max_output_len} chars)'
        
            result_parts = [f"Command: {result.args}"]
            result_parts.append(f"Return code: {result.returncode}")
            
            if stdout:
                result_parts.append(f"STDOUT:\n{stdout}")
            if stderr:
                result_parts.append(f"STDERR:\n{stderr}")
            
            return "\n".join(result_parts)
        
        # Fallback for dict or other types
        return str(result)
    
    def _has_conclusion(self, text: str) -> bool:
        """Check if the response contains a final conclusion."""
        conclusion_markers = [
            "FEASIBLE:",
            "ANALYSIS:",
            "Final analysis:",
            "My conclusion:",
            "feasibility:",
        ]
        text_lower = text.lower()
        return any(marker.lower() in text_lower for marker in conclusion_markers)
    
    def _parse_conclusion(self, text: str) -> dict:
        """
        Parse conclusion from LLM text response.
        
        Expected format:
        FEASIBLE: true/false
        ANALYSIS: ...
        SOURCE_CODE_EVIDENCE: ...
        RECOMMENDATIONS: ...
        """
        result = {
            'feasible': False,
            'analysis': '',
            'source_code_evidence': '',
            'recommendations': '',
            'analyzed': True
        }
        
        lines = text.split('\n')
        current_section = None
        content_buffer = []
        
        for line in lines:
            line_lower = line.lower().strip()
            
            if 'feasible:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                
                # Extract true/false value
                if 'true' in line_lower or 'yes' in line_lower:
                    result['feasible'] = True
                elif 'false' in line_lower or 'no' in line_lower:
                    result['feasible'] = False
                current_section = None
                
            elif 'analysis:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                current_section = 'analysis'
                
            elif 'source_code_evidence:' in line_lower or 'evidence:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                current_section = 'source_code_evidence'
                
            elif 'recommendations:' in line_lower or 'suggestions:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                current_section = 'recommendations'
                
            elif current_section:
                content_buffer.append(line)
        
        # Save last section
        if content_buffer and current_section:
            result[current_section] = '\n'.join(content_buffer).strip()
        
        return result
    
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
        
        # Initialize inspect_tool for bash command execution
        self.inspect_tool = ProjectContainerTool(benchmark)
        self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
        
        # Initialize FuzzIntrospector tool for API calls
        self._init_fi_tool(benchmark.project)
        
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
        
        # Multi-round interaction with Function Calling
        context_result = None
        cur_round = 0
        max_round = self.args.max_round
        all_responses = []  # 收集所有响应，用于提取session_memory更新
        
        # Get tool definitions
        tools = self._get_tool_definitions()
        
        # Initialize conversation messages
        messages = get_agent_messages(state, self.name)
        messages.append({"role": "user", "content": user_prompt})
        
        try:
            while cur_round < max_round:
                # Call LLM with tools
                response_data = self.llm.chat_with_tools(
                    messages=messages,
                    tools=tools,
                    state=state
                )
                
                assistant_message = response_data["message"]
                text_response = assistant_message.get("content", "") or ""
                tool_calls = assistant_message.get("tool_calls", [])
                
                # Add assistant message to conversation
                messages.append(assistant_message)
                add_agent_message(state, self.name, assistant_message)
                
                # Collect text responses for session memory
                if text_response:
                    all_responses.append(text_response)
                
                # Log the round
                logger.info(
                    f'<CONTEXT ANALYZER ROUND {cur_round}>\n{text_response}\n</CONTEXT ANALYZER ROUND {cur_round}>',
                    trial=self.trial
                )
                
                # Check if we have a conclusion
                if text_response and self._has_conclusion(text_response):
                    logger.info(
                        f'----- ROUND {cur_round:02d} Received conclusion -----',
                        trial=self.trial
                    )
                    context_result = self._parse_conclusion(text_response)
                    break
                
                # Execute any tool calls
                if tool_calls:
                    for tool_call in tool_calls:
                        tool_result = self._execute_tool(tool_call)
                        
                        # Add tool result to conversation
                        tool_message = {
                            "role": "tool",
                            "tool_call_id": tool_call.get("id", ""),
                            "content": tool_result
                        }
                        messages.append(tool_message)
                        add_agent_message(state, self.name, tool_message)
                    
                    # Continue to next round with tool results
                    cur_round += 1
                    continue
                
                # If no tool calls and no conclusion, prompt for conclusion
                if not tool_calls and text_response:
                    messages.append({
                        "role": "user",
                        "content": "Please provide your final analysis with FEASIBLE, ANALYSIS, SOURCE_CODE_EVIDENCE, and RECOMMENDATIONS."
                    })
                
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

