import os
import json
import asyncio
import logging
from typing import Optional

# Google ADK imports
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.models.lite_llm import LiteLlm
from google.adk.agents import LoopAgent, LlmAgent, SequentialAgent
from google.genai import types
from google.adk.tools.tool_context import ToolContext

# Import custom tools
from tool.fix_build_tools import (
    download_github_repo, force_clean_git_repo, checkout_oss_fuzz_commit,
    get_project_paths, read_file_content, run_command, run_fuzz_build_streaming,
    create_or_update_file, prompt_generate_tool, save_file_tree_shallow,
    find_and_append_file_details, append_string_to_file, apply_patch
)

import results as resultslib
from experiment import benchmark as benchmarklib

# 获取当前文件 (fix_build_agent.py) 的目录 -> oss-fuzz-gen/agent
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# 获取项目根目录 -> oss-fuzz-gen
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
# 拼接 prompt 目录 -> oss-fuzz-gen/prompts/fix
PROMPTS_DIR = os.path.join(PROJECT_ROOT, 'prompts', 'fix')

def load_instruction(filename: str) -> str:
    path = os.path.join(PROMPTS_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logging.warning(f"Instruction file filename not found at path.")
        return ""

# Define exit_loop tool function locally
def exit_loop(tool_context: ToolContext):
    tool_context.actions.escalate = True
    return {"status": "SUCCESS"}

class FixBuildAgent:
    """
    Wraps the Fix Build logic into an agent compatible with the OSS-Fuzz-Gen pipeline.
    """
    def __init__(self, trial: int, llm_model_name: str, api_key: str, args, benchmark: benchmarklib.Benchmark, work_dirs):
        self.trial = trial
        self.model_name = llm_model_name
        self.api_key = api_key
        self.args = args
        self.benchmark = benchmark
        self.work_dirs = work_dirs  # 保存 work_dirs，防止 status 报错
        self.name = "FixBuildAgent"
        
        self._init_agents()

    def _init_agents(self):
        # Initialize Models
        # 适配不同模型的 token 限制
        if "deepseek" in self.model_name:
            max_out_tokens = 8192
        else:
            max_out_tokens = 4096

        model = LiteLlm(model=self.model_name, api_key=self.api_key)
        long_ctx_model = LiteLlm(model=self.model_name, api_key=self.api_key, max_output_tokens=max_out_tokens)

        # 1. Initial Setup Agent
        self.initial_setup_agent = LlmAgent(
            name="initial_setup_agent",
            model=model,
            instruction="""
            You are an automated environment configuration expert. Strictly follow these steps:
            1. Parse "project_name" and "sha" from the input.
            2. Call `download_github_repo` for "oss-fuzz" to "./oss-fuzz".
            3. Call `force_clean_git_repo` on "./oss-fuzz".
            4. Call `checkout_oss_fuzz_commit` with the sha.
            5. Call `download_github_repo` for the project to "./process/project/project_name".
            6. Call `get_project_paths`.
            7. Output the result of `get_project_paths`.
            """,
            tools=[download_github_repo, force_clean_git_repo, checkout_oss_fuzz_commit, get_project_paths],
            output_key="basic_information",
        )

        # 2. Loop Agents
        self.run_fuzz_agent = LlmAgent(
            name="run_fuzz_and_collect_log_agent",
            model=model,
            instruction=load_instruction("run_fuzz_and_collect_log_instruction.txt"),
            tools=[read_file_content, run_command, run_fuzz_build_streaming, create_or_update_file],
            output_key="fuzz_build_log",
        )

        self.decision_agent = LlmAgent(
            name="decision_agent",
            model=model,
            instruction=load_instruction("decision_instruction.txt"),
            tools=[read_file_content, exit_loop],
        )

        self.prompt_gen_agent = LlmAgent(
            name="prompt_generate_agent",
            model=long_ctx_model,
            instruction=load_instruction("prompt_generate_instruction.txt"),
            tools=[prompt_generate_tool, save_file_tree_shallow, find_and_append_file_details, read_file_content, create_or_update_file, append_string_to_file],
            output_key="generated_prompt",
        )

        self.solver_agent = LlmAgent(
            name="fuzzing_solver_agent",
            model=long_ctx_model,
            instruction=load_instruction("fuzzing_solver_instruction.txt"),
            tools=[read_file_content, run_command, create_or_update_file],
            output_key="solution_plan",
        )

        self.applier_agent = LlmAgent(
            name="solution_applier_agent",
            model=model,
            instruction=load_instruction("solution_applier_instruction.txt"),
            tools=[apply_patch],
            output_key="patch_application_result",
        )

        # 3. Workflow Definitions
        self.loop_agent = LoopAgent(
            name="workflow_loop_agent",
            sub_agents=[self.run_fuzz_agent, self.decision_agent, self.prompt_gen_agent, self.solver_agent, self.applier_agent],
            max_iterations=10
        )

        self.subject_agent = SequentialAgent(
            name="fix_fuzz_agent",
            sub_agents=[self.initial_setup_agent, self.loop_agent]
        )

    async def _run_async(self) -> resultslib.FixBuildResult:
        session_service = InMemorySessionService()
        runner = Runner(agent=self.subject_agent, app_name="fix_build_app", session_service=session_service)
        
        # Construct input
        input_data = {
            "project_name": self.benchmark.project,
            "sha": self.benchmark.commit 
        }
        
        session_id = f"session_{self.benchmark.project}_{self.trial}"
        
        # 初始化 Session State，注入 project_name 以解决 KeyError
        initial_state = {
            "project_name": self.benchmark.project,
            "sha": self.benchmark.commit
        }

        # 创建 Session，必须包含 user_id 和 state
        await session_service.create_session(
            app_name="fix_build_app", 
            session_id=session_id, 
            user_id="user",
            state=initial_state
        )
        
        initial_message = types.Content(parts=[types.Part(text=json.dumps(input_data))], role='user')
        
        is_fixed = False
        
        print(f"--- [FixBuildAgent] Starting fix process for {self.benchmark.project} ---")
        
        try:
            async for event in runner.run_async(user_id="user", session_id=session_id, new_message=initial_message):
                if (event.actions and event.actions.escalate and
                    event.author == 'decision_agent'):
                    is_fixed = True
        except Exception as e:
            logging.error(f"Agent execution failed: {e}")
            import traceback
            traceback.print_exc()

        # 返回结果时传入 work_dirs，解决 AttributeError
        return resultslib.FixBuildResult(
            project_name=self.benchmark.project,
            is_fixed=is_fixed,
            solution_path="solution.txt",
            trial=self.trial,
            benchmark=self.benchmark,
            work_dirs=self.work_dirs
        )

    def execute(self, result_history: list[resultslib.Result]) -> resultslib.Result:
        """
        Entry point called by the Pipeline.
        """
        return asyncio.run(self._run_async())
