"""
LangGraphCoverageAnalyzer agent for LangGraph workflow.
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


class LangGraphCoverageAnalyzer(LangGraphAgent):
    """
    Coverage analyzer agent for LangGraph.
    
    Uses OpenAI Function Calling to execute bash commands via bash_execute tool.
    Multi-round interaction until conclusion is detected in text response.
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
    
    def _get_tool_definitions(self) -> list[dict]:
        """Define tools available to CoverageAnalyzer."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "bash_execute",
                    "description": (
                        "Execute bash command in the project container to examine coverage data, "
                        "inspect source code, or analyze build artifacts. "
                        "Use this to investigate why coverage is low."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Bash command to execute (e.g., 'cat file.c', 'grep pattern *.c', 'llvm-cov report')"
                            }
                        },
                        "required": ["command"]
                    }
                }
            }
        ]
    
    def _execute_tool(self, tool_call: dict) -> str:
        """Execute a tool call and return the result."""
        tool_name = tool_call.get("name", "")
        arguments = tool_call.get("arguments", {})
        
        if tool_name == "bash_execute":
            command = arguments.get("command", "")
            if not command:
                return "Error: bash_execute requires 'command' argument"
            
            # Execute via ProjectContainerTool
            result = self.inspect_tool.execute(command)
            return self._format_bash_result(result)
        
        return f"Error: Unknown tool '{tool_name}'"
    
    def _format_bash_result(self, process) -> str:
        """Format bash execution result."""
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()
        
        # Limit output size to avoid token overflow
        max_output_len = 10000
        if len(stdout) > max_output_len:
            stdout = stdout[:max_output_len] + f'\n... (truncated {len(stdout) - max_output_len} chars)'
        if len(stderr) > max_output_len:
            stderr = stderr[:max_output_len] + f'\n... (truncated {len(stderr) - max_output_len} chars)'
        
        result_parts = [f"Command: {process.args}"]
        result_parts.append(f"Return code: {process.returncode}")
        
        if stdout:
            result_parts.append(f"STDOUT:\n{stdout}")
        if stderr:
            result_parts.append(f"STDERR:\n{stderr}")
        
        return "\n".join(result_parts)
    
    def _has_conclusion(self, text: str) -> bool:
        """Check if the response contains a conclusion."""
        # Look for conclusion markers in the text
        conclusion_markers = [
            "CONCLUSION:",
            "Final conclusion:",
            "My conclusion:",
            "In conclusion",
            "improve_required:",
            "Coverage improvement required:",
        ]
        text_lower = text.lower()
        return any(marker.lower() in text_lower for marker in conclusion_markers)
    
    def _parse_conclusion(self, text: str) -> dict:
        """
        Parse conclusion from LLM text response.
        
        Expected format (flexible):
        CONCLUSION: true/false
        INSIGHTS: ...
        SUGGESTIONS: ...
        """
        result = {
            'improve_required': False,
            'insights': '',
            'suggestions': '',
            'analyzed': True
        }
        
        # Simple parsing - look for key sections
        lines = text.split('\n')
        current_section = None
        content_buffer = []
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Check for section headers
            if 'conclusion:' in line_lower or 'improve_required:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                
                # Extract true/false value
                if 'true' in line_lower:
                    result['improve_required'] = True
                elif 'false' in line_lower:
                    result['improve_required'] = False
                current_section = None
                
            elif 'insights:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                current_section = 'insights'
                
            elif 'suggestions:' in line_lower or 'recommendations:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                current_section = 'suggestions'
                
            elif current_section:
                content_buffer.append(line)
        
        # Save last section
        if content_buffer and current_section:
            result[current_section] = '\n'.join(content_buffer).strip()
        
        return result
    
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
        
        # Multi-round interaction with Function Calling
        coverage_result = {}
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
                    f'<COVERAGE ANALYZER ROUND {cur_round}>\n{text_response}\n</COVERAGE ANALYZER ROUND {cur_round}>',
                    trial=self.trial
                )
                
                # Check if we have a conclusion
                if text_response and self._has_conclusion(text_response):
                    logger.info(
                        f'----- ROUND {cur_round:02d} Received conclusion -----',
                        trial=self.trial
                    )
                    coverage_result.update(self._parse_conclusion(text_response))
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
                
                # If no tool calls and no conclusion, we might be stuck
                if not tool_calls and not text_response:
                    logger.warning(
                        f"Round {cur_round}: No tool calls and no text response. Breaking.",
                        trial=self.trial
                    )
                    break
                
                # If we have text but no conclusion and no tool calls, prompt for conclusion
                if text_response and not tool_calls:
                    messages.append({
                        "role": "user",
                        "content": "Please provide your final conclusion with CONCLUSION, INSIGHTS, and SUGGESTIONS."
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
    
