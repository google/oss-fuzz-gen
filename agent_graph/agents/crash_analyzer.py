"""
LangGraphCrashAnalyzer agent for LangGraph workflow.
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
        
        # Define tool specifications for function calling
        tools = self._get_tool_definitions()
        
        # Initialize message list for tool calling
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": user_prompt}
        ]
        
        # Multi-round interaction
        crash_result = {
            "true_bug": None,
            "insight": "",
            "stacktrace": stack_trace
        }
        
        cur_round = 0
        max_round = self.args.max_round
        
        try:
            while cur_round < max_round:
                # Chat with LLM using tool calling
                response = self.llm.chat_with_tools(messages, tools)
                
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
                
                # Log the LLM response
                content = response.get("content", "")
                tool_calls = response.get("tool_calls", [])
                
                logger.info(
                    f'<CRASH ANALYZER ROUND {cur_round}>\n'
                    f'Content: {content}\n'
                    f'Tool calls: {len(tool_calls)}\n'
                    f'</CRASH ANALYZER ROUND {cur_round}>',
                    trial=self.trial
                )
                
                # Add assistant message to conversation
                messages.append({
                    "role": "assistant",
                    "content": content if content else "I will use tools to investigate."
                })
                
                # Check if LLM provided a conclusion
                if self._has_conclusion(content):
                    self._parse_conclusion(content, crash_result)
                    break
                
                # Execute tool calls if any
                if tool_calls:
                    for tool_call in tool_calls:
                        result = self._execute_tool(tool_call)
                        
                        # Add tool result to messages
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "content": result
                        })
                        
                        # Mark GDB as used if gdb_execute was called
                        if tool_call["name"] == "gdb_execute":
                            self.gdb_tool_used = True
                    
                    # Continue to next round with tool results
                    cur_round += 1
                    continue
                
                # If no tool calls and no conclusion, something is wrong
                if not tool_calls and not content:
                    logger.warning(
                        f'ROUND {cur_round} No tool calls or content from LLM',
                        trial=self.trial
                    )
                    break
                
                cur_round += 1
                    
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
    
    def _get_tool_definitions(self) -> list[dict]:
        """
        Get tool definitions for OpenAI function calling.
        
        Returns:
            List of tool definitions in OpenAI format
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "gdb_execute",
                    "description": (
                        "Execute a GDB command in the debugging session. "
                        "The fuzz target binary is already loaded. "
                        "Use this to investigate the crash."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": (
                                    "GDB command to execute. Examples: "
                                    "'run -runs=1 <artifact_path>' to reproduce crash, "
                                    "'bt' for backtrace, "
                                    "'frame N' to switch frames, "
                                    "'info locals' to see local variables, "
                                    "'print variable' to inspect values"
                                )
                            }
                        },
                        "required": ["command"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "bash_execute",
                    "description": (
                        "Execute a bash command in the project container. "
                        "Use this to examine source files, search for patterns, etc."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": (
                                    "Bash command to execute. Examples: "
                                    "'cat /src/file.c' to read files, "
                                    "'grep -r pattern /src' to search code, "
                                    "'find /src -name \"*.h\"' to find files"
                                )
                            }
                        },
                        "required": ["command"]
                    }
                }
            }
        ]
    
    def _execute_tool(self, tool_call: dict) -> str:
        """
        Execute a tool call from the LLM.
        
        Args:
            tool_call: Dictionary with 'name', 'arguments', and 'id' keys
        
        Returns:
            Tool execution result as string
        """
        tool_name = tool_call["name"]
        arguments = tool_call["arguments"]
        
        try:
            if tool_name == "gdb_execute":
                command = arguments.get("command", "")
                if not command:
                    return "Error: No command provided"
                
                # Execute GDB command
                process = self.gdb_tool.execute_in_screen(command)
                return self._format_gdb_result(command, process)
            
            elif tool_name == "bash_execute":
                command = arguments.get("command", "")
                if not command:
                    return "Error: No command provided"
                
                # Execute bash command
                process = self.bash_tool.execute(command)
                return self._format_bash_result(command, process)
            
            else:
                return f"Error: Unknown tool '{tool_name}'"
        
        except Exception as e:
            logger.error(f'Tool execution error: {e}', trial=self.trial)
            return f"Error executing {tool_name}: {str(e)}"
    
    def _format_gdb_result(self, command: str, process) -> str:
        """Format GDB execution result for LLM."""
        raw_lines = process.stdout.strip().splitlines()
        
        # Remove trailing (gdb) prompt
        if raw_lines and raw_lines[-1].strip().startswith("(gdb)"):
            raw_lines.pop()
        
        # Add (gdb) prefix to first line
        if raw_lines:
            raw_lines[0] = f'(gdb) {raw_lines[0].strip()}'
        
        stdout = '\n'.join(raw_lines)
        stderr = process.stderr.strip() if process.stderr else ""
        
        result = f"GDB Command: {command}\n\nOutput:\n{stdout}"
        if stderr:
            result += f"\n\nStderr:\n{stderr}"
        
        return result
    
    def _format_bash_result(self, command: str, process) -> str:
        """Format bash execution result for LLM."""
        stdout = process.stdout.strip() if process.stdout else ""
        stderr = process.stderr.strip() if process.stderr else ""
        returncode = process.returncode
        
        result = f"Bash Command: {command}\nReturn Code: {returncode}"
        if stdout:
            result += f"\n\nStdout:\n{stdout}"
        if stderr:
            result += f"\n\nStderr:\n{stderr}"
        
        return result
    
    def _has_conclusion(self, content: str) -> bool:
        """
        Check if LLM response contains a conclusion.
        
        Args:
            content: LLM response content
        
        Returns:
            True if conclusion is present
        """
        if not content:
            return False
        
        # Look for conclusion markers
        import re
        
        # Pattern 1: "Conclusion: True/False"
        if re.search(r'conclusion:\s*(true|false)', content, re.IGNORECASE):
            return True
        
        # Pattern 2: Structured conclusion with "True Bug:" or "False Positive:"
        if re.search(r'(true bug|false positive):', content, re.IGNORECASE):
            return True
        
        # Pattern 3: Final determination
        if re.search(r'(final (determination|analysis)|root cause):', content, re.IGNORECASE):
            return True
        
        return False
    
    def _parse_conclusion(self, content: str, crash_result: dict) -> None:
        """
        Parse conclusion from LLM response.
        
        Args:
            content: LLM response content
            crash_result: Dictionary to store parsed results
        """
        import re
        
        # Try to extract True/False determination
        conclusion_match = re.search(
            r'conclusion:\s*(true|false)',
            content,
            re.IGNORECASE
        )
        
        if conclusion_match:
            conclusion = conclusion_match.group(1).lower()
            crash_result['true_bug'] = (conclusion == 'true')
        else:
            # Try alternative patterns
            if re.search(r'true bug', content, re.IGNORECASE):
                crash_result['true_bug'] = True
            elif re.search(r'false positive', content, re.IGNORECASE):
                crash_result['true_bug'] = False
            else:
                logger.warning(
                    f'Could not determine true/false from conclusion',
                    trial=self.trial
                )
                crash_result['true_bug'] = None
        
        # Extract analysis/insight
        # Try to find analysis section
        analysis_match = re.search(
            r'(analysis and suggestion|root cause analysis|analysis):\s*(.+)',
            content,
            re.IGNORECASE | re.DOTALL
        )
        
        if analysis_match:
            crash_result['insight'] = analysis_match.group(2).strip()
        else:
            # Use the entire content as insight
            crash_result['insight'] = content
        
        logger.info(
            f'Conclusion parsed: true_bug={crash_result["true_bug"]}, '
            f'insight_length={len(crash_result.get("insight", ""))}',
            trial=self.trial
        )
    
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
    
    # All deprecated XML-based methods have been removed in favor of OpenAI Function Calling.
    # The agent now uses chat_with_tools() for all tool interactions.
    
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

