import os
import json
import asyncio
import time
import logging
from typing import Optional

# Google ADK imports
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.models.lite_llm import LiteLlm
# Try correct import path, usually Gemini is under google.adk.models
try:
    from google.adk.models import Gemini
except ImportError:
    try:
        from google.adk.models.vertex_ai import Gemini
    except ImportError:
        Gemini = None # Fallback

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

# Path configuration
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
PROMPTS_DIR = os.path.join(PROJECT_ROOT, 'prompts', 'fix')

def load_instruction(filename: str) -> str:
    path = os.path.join(PROMPTS_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logging.warning(f"Instruction file '{filename}' not found at {path}.")
        return ""

# --- Tool Definitions ---

def exit_loop(tool_context: ToolContext):
    """Called by DecisionAgent when build succeeds to terminate the loop."""
    print(f"[Tool Call] exit_loop triggered, task completed.")
    tool_context.actions.escalate = True
    return {"status": "SUCCESS"}

def delay() -> str:
    """
    Pauses execution for a fixed 15 seconds to avoid triggering API Rate Limits.
    """
    delay_seconds = 15
    print(f"  [Rate Limit Protection] delay tool called, pausing for {delay_seconds} seconds...")
    time.sleep(delay_seconds)
    print(f"  ...pause ended.")
    return f"Successfully delayed for {delay_seconds} seconds."

class FixBuildAgent:
    """
    Wraps the Fix Build logic into an agent compatible with the OSS-Fuzz-Gen pipeline.
    """
    def __init__(self, trial: int, model, args, benchmark: benchmarklib.Benchmark, work_dirs):
        self.trial = trial
        self.model = model  # The oss-fuzz-gen model object
        self.model_name = model.name
        self.args = args
        self.benchmark = benchmark
        self.work_dirs = work_dirs
        self.name = "FixBuildAgent"
        
        self._init_agents()

    def _init_agents(self):
        # --- Model Initialization ---
        use_native_gemini = False
        if "gemini" in self.model_name and Gemini is not None:
            use_native_gemini = True

        # Note: We rely on environment variables for API keys, which should be set by oss-fuzz-gen's setup
        if use_native_gemini:
            # --- Native Gemini Support ---
            clean_model_name = self.model_name.replace("gemini/", "")
            print(f"--- [FixBuildAgent] Initializing Native Gemini Model: {clean_model_name} ---")
            model = Gemini(model=clean_model_name)
            long_ctx_model = Gemini(model=clean_model_name)
        else:
            # --- LiteLLM Support (GPT, DeepSeek, or Gemini fallback) ---
            print(f"--- [FixBuildAgent] Initializing LiteLLM Model: {self.model_name} ---")
            if "deepseek" in self.model_name or "gemini" in self.model_name:
                max_out_tokens = 8192
            else:
                max_out_tokens = 4096
            
            model = LiteLlm(model=self.model_name)
            long_ctx_model = LiteLlm(model=self.model_name, max_output_tokens=max_out_tokens)

        # --- Agent Definitions (Integrated delay tool) ---

        # 1. Initial Setup Agent
        self.initial_setup_agent = LlmAgent(
            name="initial_setup_agent",
            model=model,
            instruction="""
            You are an automated environment configuration expert. Strictly follow these steps:
            1. Parse "project_name" and "sha" from the input.
            2. Call `download_github_repo` to download "oss-fuzz" to "./oss-fuzz".
            3. Call `force_clean_git_repo` to clean "./oss-fuzz".
            4. Call `checkout_oss_fuzz_commit` to switch to the specified sha.
            5. Call `download_github_repo` to download the current project to "./process/project/{project_name}".
            6. Call `get_project_paths` to get path information.
            7. **You MUST call the `delay` tool at the end**.
            8. Output the result of `get_project_paths` as your final answer.
            """,
            tools=[download_github_repo, force_clean_git_repo, checkout_oss_fuzz_commit, get_project_paths, delay],
            output_key="basic_information",
        )

        # 2. Run Fuzz Agent
        self.run_fuzz_agent = LlmAgent(
            name="run_fuzz_and_collect_log_agent",
            model=model,
            instruction=load_instruction("run_fuzz_and_collect_log_instruction.txt") + "\nAfter executing the build, you **MUST** call the `delay` tool.",
            tools=[read_file_content, run_command, run_fuzz_build_streaming, create_or_update_file, delay],
            output_key="fuzz_build_log",
        )

        # 3. Decision Agent
        self.decision_agent = LlmAgent(
            name="decision_agent",
            model=model,
            instruction="""
            You are a build process evaluator.
            1. Call `read_file_content` to read 'fuzz_build_log_file/fuzz_build_log.txt'.
            2. If the content contains "success" (case-insensitive):
               Call the `exit_loop` tool to terminate the process.
            3. If the build failed:
               Output "Build failed, continuing fix.".
            4. **Regardless of the result, you MUST call the `delay` tool at the end**.
            """,
            tools=[read_file_content, exit_loop, delay],
        )

        # 4. Prompt Generate Agent
        self.prompt_gen_agent = LlmAgent(
            name="prompt_generate_agent",
            model=long_ctx_model,
            instruction=load_instruction("prompt_generate_instruction.txt") + "\nAfter completion, you **MUST** call the `delay` tool.",
            tools=[prompt_generate_tool, save_file_tree_shallow, find_and_append_file_details, read_file_content, create_or_update_file, append_string_to_file, delay],
            output_key="generated_prompt",
        )

        # 5. Solver Agent
        self.solver_agent = LlmAgent(
            name="fuzzing_solver_agent",
            model=long_ctx_model,
            instruction=load_instruction("fuzzing_solver_instruction.txt") + "\nAfter completion, you **MUST** call the `delay` tool.",
            tools=[read_file_content, run_command, create_or_update_file, delay],
            output_key="solution_plan",
        )

        # 6. Applier Agent
        self.applier_agent = LlmAgent(
            name="solution_applier_agent",
            model=model,
            instruction=load_instruction("solution_applier_instruction.txt") + "\nAfter completion, you **MUST** call the `delay` tool.",
            tools=[apply_patch, delay],
            output_key="patch_application_result",
        )

        # --- Workflow Definition ---
        self.loop_agent = LoopAgent(
            name="workflow_loop_agent",
            sub_agents=[
                self.run_fuzz_agent,
                self.decision_agent,
                self.prompt_gen_agent,
                self.solver_agent,
                self.applier_agent
            ],
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
        
        # Initialize Session State
        initial_state = {
            "project_name": self.benchmark.project,
            "sha": self.benchmark.commit
        }

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

        return resultslib.FixBuildResult(
            project_name=self.benchmark.project,
            is_fixed=is_fixed,
            solution_path="solution.txt",
            trial=self.trial,
            benchmark=self.benchmark,
            work_dirs=self.work_dirs
        )

    def execute(self, result_history: list[resultslib.Result]) -> resultslib.Result:
        return asyncio.run(self._run_async())
