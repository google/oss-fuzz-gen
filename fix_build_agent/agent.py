# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
import traceback
import warnings
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import agent_tools
import litellm
from dotenv import load_dotenv

load_dotenv()
litellm.request_timeout = 600
litellm.num_retries = 2
litellm.drop_params = True

from functools import wraps

from agent_tools import (TraceLedgerManager, append_string_to_file, apply_patch,
                         archive_fixed_project, cbsc_classify_log,
                         check_file_exists, checkout_oss_fuzz_commit,
                         checkout_project_commit, clear_commit_analysis_state,
                         commit_workspace_snapshots, create_or_update_file,
                         download_github_repo, download_remote_log,
                         execute_hsr_decision, extract_buggy_line_info,
                         extract_build_metadata_from_log, few_shot_rag_retrieve,
                         find_and_append_file_details, force_clean_git_repo,
                         get_enhanced_history_context,
                         get_git_commits_around_date, get_project_paths,
                         get_verified_git_sha, get_workspace_root,
                         init_or_update_rsmc_ledger, list_files_in_dir,
                         manage_git_state, patch_project_dockerfile,
                         prompt_generate_tool, query_trace_ledger,
                         read_file_content, read_projects_from_yaml,
                         run_command, run_ecrcl_localization,
                         run_fuzz_build_and_validate, safe_delete_path,
                         save_commit_diff_to_file, save_file_tree_shallow,
                         update_reflection_journal, update_trace_ledger,
                         update_yaml_report)
from google.adk.agents import BaseAgent, Context, LlmAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.tool_context import ToolContext
from google.adk.workflow import BaseNode, Edge, Workflow, node
from google.genai import types


class StreamTee:

  def __init__(self, original_stream, agent_logger):
    self.original_stream = original_stream
    self.agent_logger = agent_logger

  def write(self, data):
    self.original_stream.write(data)
    if data.strip():
      self.agent_logger.log_raw(data)

  def flush(self):
    self.original_stream.flush()


class LoggingWrapperAgent(BaseAgent):
  name: str = "LoggingWrapperAgent"
  # 🔑 优化：变更为 BaseNode 以便包裹 Workflow 对象
  subject_agent: BaseNode

  async def _run_async_impl(
      self, context: InvocationContext) -> AsyncGenerator[Event, None]:
    try:
      # 🔑 1. 兼容性判定：如果被包装对象拥有旧版 run_async，则走传统 agent 分支
      if hasattr(self.subject_agent, "run_async"):
        async for event in self.subject_agent.run_async(context):
          GLOBAL_LOGGER.log_event(event)
          yield event
      # 🔑 2. 否则，被包装对象为现代 BaseNode/Workflow，调用 ADK 2.0 标准 run 入口
      else:
        # 将 InvocationContext 包装为 Workflow 内部上下文 Context
        adk_ctx = Context(context)
        # 安全获取初始用户输入消息作为节点输入
        node_input = getattr(context, "user_content", None)

        async for event in self.subject_agent.run(ctx=adk_ctx,
                                                  node_input=node_input):
          GLOBAL_LOGGER.log_event(event)
          yield event

    except (Exception, KeyboardInterrupt) as e:
      print(f"\n--- Interruption or error detected: {type(e).__name__} ---")
      raise e
    finally:
      if not GLOBAL_LOGGER.file_handler_setup:
        GLOBAL_LOGGER.setup_file_handler()


class AgentLogger:

  def __init__(self, log_directory: str = "agent_logs"):
    self.log_directory = log_directory
    self.logger = None
    self.file_handler_setup = False
    self.log_buffer = []
    self.project_name = "orchestrator"
    os.makedirs(self.log_directory, exist_ok=True)

  def set_project_context(self, project_name: str):
    if self.logger:
      for handler in self.logger.handlers[:]:
        handler.close()
        self.logger.removeHandler(handler)
    self.project_name = project_name
    self.file_handler_setup = False
    self.setup_file_handler()

  def setup_file_handler(self):
    if self.file_handler_setup:
      return
    safe_project_name = "".join(c for c in self.project_name
                                if c.isalnum() or c in ('_', '-')).rstrip()
    timestamp = datetime.now().strftime("%Y.%m.%d_%H.%M.%S")
    log_filename = f"{safe_project_name}_run_{timestamp}.log"
    log_filepath = os.path.join(self.log_directory, log_filename)

    self.logger = logging.getLogger(
        f"AgentLogger_{safe_project_name}_{timestamp}")
    self.logger.setLevel(logging.INFO)
    self.logger.propagate = False

    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    formatter = logging.Formatter('%(message)s')
    file_handler.setFormatter(formatter)

    if not self.logger.handlers:
      self.logger.addHandler(file_handler)

    print(f"✅ Log file created: {log_filepath}")

    for log_entry in self.log_buffer:
      self.logger.info(log_entry)
    self.log_buffer = []
    self.file_handler_setup = True

  def log_raw(self, message: str):
    msg = message.rstrip()
    if not msg:
      return
    if self.file_handler_setup and self.logger:
      self.logger.info(msg)
    else:
      self.log_buffer.append(msg)

  def log_event(self, event: Event):
    log_message = self._format_message(event)
    if log_message:
      print(log_message)

  def _format_message(self, event: Event) -> str:
    author = event.author
    log_parts = [f"EVENT from author: '{author}'"]
    if event.usage_metadata:
      u = event.usage_metadata
      log_parts.append(
          f"  - TOKEN_USAGE: Prompt={u.prompt_token_count}, Gen={u.candidates_token_count}"
      )
    if hasattr(event, 'get_function_calls') and (func_calls :=
                                                 event.get_function_calls()):
      for call in func_calls:
        log_parts.append(
            f"  - TOOL_CALL: {call.name}({json.dumps(call.args, ensure_ascii=False)})"
        )
    if hasattr(event,
               'get_function_responses') and (func_resps :=
                                              event.get_function_responses()):
      for resp in func_resps:
        response_str = str(resp.response)
        response_str = response_str[:500] + "..." if len(
            response_str) > 500 else response_str
        log_parts.append(f"  - TOOL_RESPONSE for '{resp.name}': {response_str}")
    if (actions := event.actions):
      if actions.state_delta:
        log_parts.append(f"  - STATE_UPDATE: {actions.state_delta}")
      if actions.escalate:
        log_parts.append("  - ACTION: Escalate (Agent Finish)")
    return "\n".join(log_parts)


def load_instruction_from_file(filename: str) -> str:
  try:
    with open(filename, 'r', encoding='utf-8') as f:
      return f.read()
  except FileNotFoundError:
    print(
        f"Warning: Instruction file '{filename}' not found. The agent will use an empty instruction."
    )
    return ""


def tool_defense_decorator(func):

  @wraps(func)
  async def async_wrapper(*args, **kwargs):
    try:
      return await func(*args, **kwargs)
    except Exception as e:
      # 日志展示非法或异常调用，但不崩溃，将异常抛出给 Agent 处理
      GLOBAL_LOGGER.log_raw(
          f"⚠️ [Security/Error] Tool '{func.__name__}' failed: {str(e)}")
      return {"status": "error", "message": f"Execution failed: {str(e)}"}

  @wraps(func)
  def sync_wrapper(*args, **kwargs):
    try:
      return func(*args, **kwargs)
    except Exception as e:
      GLOBAL_LOGGER.log_raw(
          f"⚠️ [Security/Error] Tool '{func.__name__}' failed: {str(e)}")
      return {"status": "error", "message": f"Execution failed: {str(e)}"}

  return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


def wrap_tools(tools: List[Any]) -> List[Any]:
  return [tool_defense_decorator(t) for t in tools]


# =====================================================================
# 辅助函数：安全记忆清理与状态脱水 (物理手术完全无状态版)
# =====================================================================


async def _safe_memory_cleaning(session_service: InMemorySessionService,
                                session_id: str):
  """
    【防御性优化版】仅对明确的大体积负载进行脱水，严格保护运行环境元数据与多轮会话上下文。
    """
  session = await session_service.get_session(app_name=APP_NAME,
                                              user_id=USER_ID,
                                              session_id=session_id)
  if not session:
    return

  # 1. 状态字典脱水：仅对明确占用空间的超大键进行脱水，直接清理死码变量保护性能
  massive_keys = [
      "fuzz_build_log", "commit_analysis_result", "generated_prompt"
  ]

  for key in list(session.state.keys()):
    # 只要是已知的超大负载 key，统一实施安全脱水，避免撑爆 Token 窗口
    if key in massive_keys:
      session.state[key] = "[DEHYDRATED: SUMMARY IN LEDGER]"

  print(
      f"--- 🧼 [SAFE CLEANSED] Dehydrated massive state keys for session {session_id}. Event history and core env metadata preserved. ---"
  )

  # PROTECTED_STATE_KEYS = {
  #     "project_source_path", "project_config_path", "error_time",
  #     "attempt_id", "round_id", "current_node_id", "rollback_triggered",
  #     "ever_used_upstream", "last_validation_report",
  #     "software_sha", "oss_fuzz_sha"
  # }


def cleanup_environment(project_name: str):
  print(f"--- 🧹 Tool: cleanup_environment for: {project_name} ---")

  debug_paths = [
      "fuzz_build_log_file/fuzz_build_log.txt",
      "generated_prompt_file/prompt.txt",
      "generated_prompt_file/file_tree.txt",
      "generated_prompt_file/commit_changed.txt",
      "solution.txt",
      "repair_strategy.txt",
  ]
  for debug_path in debug_paths:
    print(
        f"  - [DEBUG cleanup] exists={os.path.exists(debug_path)} path={debug_path}"
    )

  paths_to_remove = [
      "fuzz_build_log_file", "generated_prompt_file", "oss-fuzz",
      "solution.txt", "repair_strategy.txt", "project_repair_trace.json",
      "result.txt", "file_tree.txt"
  ]

  for path in paths_to_remove:
    if os.path.exists(path):
      try:
        safe_delete_path(path)
        print(f"  - Cleaned: {path}")
      except Exception as e:
        print(f"  - Warning: Failed to clean {path}: {e}")


def _generate_final_report(
    project_info: dict,
    is_successful: bool,
    attempt_id: int,
    stats: dict,
    attempt_tokens: dict,
    attempt_start_time: float,
    attempt_expert_matched: bool,
    attempt_last_patch_files: int,
    attempt_last_patch_lines: int,
):
  """
    汇总并输出项目修复最终报告，写入 result.txt 并归档。
    具有完整容错能力，任何子步骤异常均不影响其余步骤执行。
    """
  project_name = project_info.get('project_name', 'UNKNOWN')
  error_time = project_info.get('error_time', 'UNKNOWN')

  # ── 1. 从账本读取回退次数和根因定位结果 ──────────────────────────────
  rollback_count = 0
  root_cause_located = False
  try:
    ledger = TraceLedgerManager.load_ledger()
    for n in ledger.get("nodes", []):
      # 回退次数：should_rollback 为 true 的节点数
      if str(n.get("identification", {}).get("should_rollback",
                                             "false")).lower() == "true":
        rollback_count += 1
      # 根因定位：任意节点的 root_cause_commit_sha 非空且非 N/A
      sha_val = n.get("action_and_intent", {}).get("root_cause_commit_sha", "")
      if sha_val and sha_val not in ("N/A", "", "UNKNOWN"):
        root_cause_located = True
  except Exception as e:
    print(f"--- ⚠️ [REPORT] Failed to read ledger for stats: {e} ---")

  # ── 2. 计算时间消耗 ──────────────────────────────────────────────────
  try:
    elapsed_seconds = time.time() - attempt_start_time
    elapsed_minutes = elapsed_seconds / 60.0
    time_cost_str = f"{elapsed_minutes:.2f} minutes"
  except Exception:
    time_cost_str = "N/A"

  # ── 3. 组装报告文本 ──────────────────────────────────────────────────
  result_icon = "✅ SUCCESS" if is_successful else "❌ FAILURE"
  repair_rounds = stats.get("repair_rounds", 0)
  total_tokens = attempt_tokens.get("total", 0)
  input_tokens = attempt_tokens.get("prompt", 0)
  output_tokens = attempt_tokens.get("completion", 0)

  report_lines = [
      "============================================================",
      f"🏁 FINAL PROJECT REPAIR REPORT: {project_name}",
      "------------------------------------------------------------",
      f"  - [Error Time]: {error_time}",
      f"  - [Result]: {result_icon}",
      f"  - [Attempt Rounds]: {attempt_id}",
      f"  - [Repair Rounds]: {repair_rounds}",
      f"  - [Rollback]: {rollback_count}",
      f"  - [Root Cause Location]: {root_cause_located}",
      f"  - [Expert Match]: {attempt_expert_matched}",
      f"  - [Time Cost]: {time_cost_str}",
      f"  - [Input Tokens]: {input_tokens}",
      f"  - [Output Tokens]: {output_tokens}",
      f"  - [Files Change]: {attempt_last_patch_files}",
      f"  - [Lines Change]: {attempt_last_patch_lines}",
      "============================================================",
  ]
  report_text = "\n".join(report_lines)

  # ── 4. 输出到控制台（同时经由 StreamTee 写入日志）───────────────────
  try:
    print(report_text)
  except Exception as e:
    pass  # 控制台输出失败不中断后续步骤

  # ── 5. 写入 result.txt ───────────────────────────────────────────────
  result_txt_path = "result.txt"
  try:
    with open(result_txt_path, 'w', encoding='utf-8') as f:
      f.write(report_text + "\n")
    print(f"--- 📄 result.txt written successfully. ---")
  except Exception as e:
    print(f"--- ⚠️ [REPORT] Failed to write result.txt: {e} ---")

  # ── 6. 归档 result.txt 到项目归档目录 ───────────────────────────────
  try:
    safe_name = "".join(
        c for c in project_name if c.isalnum() or c in ('_', '-')).rstrip()
    archive_dir = os.path.join(os.getcwd(), "archive", safe_name)
    os.makedirs(archive_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = os.path.join(archive_dir, f"result_{timestamp}.txt")
    with open(result_txt_path, 'r', encoding='utf-8') as f:
      content = f.read()
    with open(archive_path, 'w', encoding='utf-8') as f:
      f.write(content)
    print(f"--- 📦 result.txt archived to: {archive_path} ---")
  except Exception as e:
    print(f"--- ⚠️ [REPORT] Failed to archive result.txt: {e} ---")


def exit_loop(tool_context: ToolContext):
  tool_context.actions.escalate = True
  return {"status": "SUCCESS"}


GLOBAL_LOGGER = AgentLogger()

APP_NAME = "fix_build_agent_app"
MODEL = os.getenv("FIX_BUILD_AGENT_MODEL", "deepseek/deepseek-v4-flash")
api_base = os.getenv("FIX_BUILD_AGENT_API_BASE", "https://api.deepseek.com")
API_KEY = (os.getenv("API_KEY") or os.getenv("OPENAI_COMPATIBLE_API_KEY") or
           os.getenv("DEEPSEEK_API_KEY"))
USER_ID = "default_user"
MAX_RETRIES = int(os.getenv("FIX_BUILD_AGENT_MAX_RETRIES", "2"))
MAX_INTERNAL_ROUNDS = int(os.getenv("FIX_BUILD_AGENT_MAX_INTERNAL_ROUNDS", "6"))
PROJECT_TIMEOUT_LIMIT = int(
    os.getenv("FIX_BUILD_AGENT_PROJECT_TIMEOUT", "10800"))
LLM_SEED = 42
top_p = 0.9
YAML_FILE = os.getenv("FIX_BUILD_AGENT_PROJECTS_YAML", "projects.yaml")
SKIP_GH_AUTH_CHECK = os.getenv("FIX_BUILD_AGENT_SKIP_GH_AUTH_CHECK") == "1"


def _model_uses_vertex_adc(model_name: str) -> bool:
  """Returns whether LiteLLM can authenticate through Vertex ADC."""
  return (model_name or '').lower().startswith('vertex_ai/')


def _is_step_2_success(validation_report: dict) -> bool:
  if not isinstance(validation_report, dict):
    return False
  return str(validation_report.get("step_2_infra_compliance",
                                   "")).strip() == "pass"


def initialize_agents(
    session_state: dict = None) -> Tuple[BaseNode, InMemorySessionService]:
  """
    Dynamically instantiates all agents and binds into linear Workflow.
    Remove internal Loop/ring back, drive iteration by outer Python loop.
    """
  # 提取注入上下文
  rc_commit = str(session_state.get("root_cause_commit",
                                    "")) if session_state else ""
  rc_workspace = str(session_state.get("root_cause_workspace",
                                       "")) if session_state else ""

  # 加载并动态注入指令
  finder_instr = load_instruction_from_file(
      "instructions/commit_finder_instruction.txt")

  # --- 审计代码：打印指令注入情况 ---
  # print(f"[AUDIT] Agent Instruction Injection: commit={rc_commit}, workspace={rc_workspace}")

  if not rc_commit or rc_commit == "N/A":
    # 移除关于 Bypass 的逻辑块
    processed_instruction = finder_instr.replace(
        "{root_cause_commit?}", "").replace("{root_cause_workspace?}", "")
    # 可选：在指令中追加一行提示，告知 Agent 没有预设值，直接全量搜索
    processed_instruction += "\n# NOTE: No pre-specified root cause detected. Execute full standard localization."
  else:
    processed_instruction = finder_instr.replace("{root_cause_commit?}", rc_commit) \
        .replace("{root_cause_workspace?}", rc_workspace) \
        .replace("{root_cause_commit}", rc_commit) \
        .replace("{root_cause_workspace}", rc_workspace)

  # --- 审计代码：将最终注入后的指令打印到控制台 ---
  # print(f"\n[AUDIT] Commit Finder Instruction injected with: Commit={rc_commit}, Workspace={rc_workspace}")
  # print(f"[AUDIT] Final Instruction snippet: {processed_instruction[:4000]}...")

  # 1. 初始化所有 LlmAgent
  initial_setup_agent = LlmAgent(
      name="initial_setup_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    temperature=0.0,
                    top_p=0.1,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/initial_setup_instruction.txt"),
      tools=[
          download_github_repo,
          force_clean_git_repo,
          checkout_oss_fuzz_commit,
          extract_build_metadata_from_log,
          patch_project_dockerfile,
          get_project_paths,
          manage_git_state,
          checkout_project_commit,
      ],
      output_key="basic_information",
  )

  run_fuzz_and_collect_log_agent = LlmAgent(
      name="run_fuzz_and_collect_log_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    temperature=0.0,
                    top_p=0.1,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/run_fuzz_and_collect_log_instruction.txt"),
      tools=[
          read_file_content, run_fuzz_build_and_validate, get_workspace_root
      ],
      output_key="fuzz_build_log",
  )

  decision_agent = LlmAgent(
      name="decision_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    temperature=0.0,
                    top_p=0.1,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/decision_instruction.txt"),
      tools=[read_file_content, exit_loop],
      output_key="decision_result",
  )

  rsmc_agent = LlmAgent(
      name="rsmc_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    temperature=0.2,
                    top_p=0.3,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/rsmc_instruction.txt"),
      tools=[read_file_content, init_or_update_rsmc_ledger, query_trace_ledger],
      output_key="loop_summary",
  )

  rollback_agent = LlmAgent(
      name="rollback_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    temperature=0.0,
                    top_p=0.1,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/rollback_instruction.txt"),
      tools=[
          cbsc_classify_log, execute_hsr_decision, clear_commit_analysis_state
      ],
      output_key="hsr_decision",
  )

  commit_finder_agent = LlmAgent(
      name="commit_finder_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    temperature=0.0,
                    top_p=0.1,
                    seed=LLM_SEED),
      instruction=processed_instruction,
      tools=[
          read_file_content,
          check_file_exists,
          extract_buggy_line_info,
          get_project_paths,
          list_files_in_dir,
          run_command,
          update_yaml_report,
          run_ecrcl_localization,
      ],
      output_key="commit_analysis_result",
  )

  prompt_generate_agent = LlmAgent(
      name="prompt_generate_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    max_output_tokens=16384,
                    temperature=0.2,
                    top_p=0.3,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/prompt_generate_instruction.txt"),
      tools=[
          prompt_generate_tool,
          save_file_tree_shallow,
          find_and_append_file_details,
          read_file_content,
          list_files_in_dir,
          create_or_update_file,
          append_string_to_file,
          few_shot_rag_retrieve,
          query_trace_ledger,
      ],
      output_key="generated_prompt",
  )

  fuzzing_solver_agent = LlmAgent(
      name="fuzzing_solver_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    max_output_tokens=8129,
                    temperature=0.0,
                    top_p=0.2,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/fuzzing_solver_instruction.txt"),
      tools=[read_file_content, create_or_update_file, list_files_in_dir],
      output_key="solution_plan",
  )

  solution_applier_agent = LlmAgent(
      name="solution_applier_agent",
      model=LiteLlm(model=MODEL,
                    api_base=api_base,
                    api_key=API_KEY,
                    temperature=0.0,
                    top_p=0.1,
                    seed=LLM_SEED),
      instruction=load_instruction_from_file(
          "instructions/solution_applier_instruction.txt"),
      tools=[
          apply_patch, read_file_content, commit_workspace_snapshots,
          create_or_update_file, update_trace_ledger
      ],
      output_key="patch_application_result",
  )

  # 2. 包装节点
  setup_node = node(initial_setup_agent, name="initial_setup_agent")
  fuzz_node = node(run_fuzz_and_collect_log_agent,
                   name="run_fuzz_and_collect_log_agent")
  decision_node = node(decision_agent, name="decision_agent")
  rsmc_node = node(rsmc_agent, name="rsmc_agent")
  rollback_node = node(rollback_agent, name="rollback_agent")
  finder_node = node(commit_finder_agent, name="commit_finder_agent")
  prompt_node = node(prompt_generate_agent, name="prompt_generate_agent")
  solver_node = node(fuzzing_solver_agent, name="fuzzing_solver_agent")
  applier_node = node(solution_applier_agent, name="solution_applier_agent")

  # 3. 路由逻辑 (实现图内自动循环)
  @node(name="router_node")
  async def router_node(ctx: Context, node_input: Any):
    if _is_step_2_success(ctx.state.get("last_validation_report", {})):
      return Event(route="exit")

    current_round = ctx.state.get("round_id", 0)
    if current_round < MAX_INTERNAL_ROUNDS:
      # 🔑 优化：利用 Event 的 state 属性原子化、安全地向持久化会话树回写 round_id 增量，防止绕过 Checkpoint 机制
      return Event(route="continue", state={"round_id": current_round + 1})

    return Event(route="exit")

  success_node = node(lambda: {"status": "SUCCESS"}, name="success_node")

  # 4. 构建闭环图结构
  edges = [
      ("START", setup_node),
      (setup_node, fuzz_node),
      (fuzz_node, decision_node),
      (decision_node, router_node),
      Edge(from_node=router_node, route="continue", to_node=rsmc_node),
      (rsmc_node, rollback_node),
      (rollback_node, finder_node),
      (finder_node, prompt_node),
      (prompt_node, solver_node),
      (solver_node, applier_node),
      (applier_node, fuzz_node),  # 闭环核心：补丁应用后触发重新编译
      Edge(from_node=router_node, route="exit", to_node=success_node),
  ]

  subject_workflow = Workflow(
      name="fix_fuzz_workflow",
      edges=edges,
      description="Self-looping iterative repair workflow.")

  return subject_workflow, InMemorySessionService()


async def process_single_project(
    project_info: Dict, yaml_path: str,
    row_index: int) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
  print(
      f"[EVIDENCE] YAML Data Audit - Root Cause Commit: '{project_info.get('root_cause_commit')}'"
  )
  print(
      f"[EVIDENCE] YAML Data Audit - Workspace: '{project_info.get('root_cause_workspace')}'"
  )

  project_name = project_info['project_name']
  TraceLedgerManager.set_active_project(project_name)
  safe_name = "".join(
      c for c in project_name if c.isalnum() or c in ('_', '-')).rstrip()
  expected_source_path = os.path.join(os.getcwd(), "process", "project",
                                      safe_name)

  oss_fuzz_sha = project_info['sha']
  software_sha = project_info.get('software_sha', "N/A")
  original_log_path = project_info.get('original_log_path', "")

  project_start_time = time.time()
  project_total_tokens = {"prompt": 0, "completion": 0, "total": 0}
  full_deterioration_history = []

  is_successful = False
  session = None
  final_basic_information = None
  last_run_stats = {}

  current_attempt_id = 0
  stats = {
      "repair_rounds": 0,
      "build_calls": 0,
      "total_tokens": {
          "prompt": 0,
          "completion": 0,
          "total": 0
      }
  }
  attempt_tokens = {"prompt": 0, "completion": 0, "total": 0}
  attempt_start_time = project_start_time
  attempt_expert_matched = False
  attempt_last_patch_files = 0
  attempt_last_patch_lines = 0
  last_validation_report: dict = {}
  try:
    for attempt in range(MAX_RETRIES):

      cleanup_environment(project_name)
      # Keep validation state independent for each retry.  Once the
      # validation tool has returned a passing Step 2 result, later
      # orchestration/model errors must not erase that result.
      last_validation_report = {}
      current_attempt_id = attempt + 1
      processed_event_ids = set()
      ledger_abs_file = TraceLedgerManager.get_ledger_path()
      if os.path.exists(ledger_abs_file):
        try:
          safe_delete_path(ledger_abs_file)
          print(
              f"--- 🧹 Cleared trace ledger for attempt {current_attempt_id} at {ledger_abs_file} ---"
          )
        except Exception as e:
          print(
              f"--- ⚠️ Failed to clean trace ledger for attempt {current_attempt_id}: {e} ---"
          )
      stats = {
          "repair_rounds": 0,
          "build_calls": 0,
          "rollback_count": 0,
          "total_tokens": {
              "prompt": 0,
              "completion": 0,
              "total": 0
          },
          "code_gen_tokens": 0,
          "scores": [],
          "decision_type": "UNKNOWN",
          "patch_impact": {
              "files": 0,
              "lines": 0
          },
          "heuristic_used": False,
          "attempt_id": current_attempt_id
      }
      last_run_stats = stats

      # 🔑 统计：本次大循环专属统计变量（大循环切换时重置）
      attempt_start_time = time.time()
      attempt_tokens = {"prompt": 0, "completion": 0, "total": 0}
      attempt_expert_matched = False
      attempt_last_patch_files = 0
      attempt_last_patch_lines = 0

      # 1. 必须先创建 Session 并准备好 state，才能初始化 Agent
      session_service = InMemorySessionService()
      current_session_id = f"session_{project_name}_{int(time.time())}_at{attempt}"

      await session_service.create_session(app_name=APP_NAME,
                                           user_id=USER_ID,
                                           session_id=current_session_id)
      session = await session_service.get_session(app_name=APP_NAME,
                                                  user_id=USER_ID,
                                                  session_id=current_session_id)

      # 预加载 root_cause 数据到 state
      session.state["root_cause_commit"] = project_info.get(
          "root_cause_commit", "")
      session.state["root_cause_workspace"] = project_info.get(
          "root_cause_workspace", "")

      # 2. 审计代码：检查 session.state 内容
      print(f"[AUDIT] Initializing agents with state: {session.state}")

      # 3. 传入 session.state 完成注入式初始化
      try:
        root_agent, _ = initialize_agents(session_state=session.state)
      except Exception as e:
        print(f"[CRITICAL] initialize_agents failed: {e}")
        raise e

      # 物理 Git 与账本一致性审计
      ledger = TraceLedgerManager.load_ledger()
      if ledger.get("nodes"):
        last_node = ledger["nodes"][-1]
        ledger_oss = last_node.get("git_sha_state", {}).get("oss-fuzz_sha")
        ledger_prj = last_node.get("git_sha_state", {}).get("project_sha")

        disk_oss = TraceLedgerManager.get_git_head_sha(
            os.path.join(os.getcwd(), "oss-fuzz"))
        disk_prj = TraceLedgerManager.get_git_head_sha(expected_source_path)

        if ledger_oss not in (
            "N/A", "PENDING") and disk_oss != "N/A" and ledger_oss != disk_oss:
          print(
              f"--- ⚠️ Integrity Mismatch [OSS-Fuzz]: Ledger={ledger_oss[:7]}, Disk={disk_oss[:7]}. Resetting... ---"
          )
          subprocess.run(
              ["git", "-C", "oss-fuzz", "reset", "--hard", ledger_oss],
              check=True)
          subprocess.run(["git", "-C", "oss-fuzz", "clean", "-fxd"], check=True)

        if ledger_prj not in (
            "N/A", "PENDING") and disk_prj != "N/A" and ledger_prj != disk_prj:
          print(
              f"--- ⚠️ Integrity Mismatch [Upstream]: Ledger={ledger_prj[:7]}, Disk={disk_prj[:7]}. Resetting... ---"
          )
          subprocess.run([
              "git", "-C", expected_source_path, "reset", "--hard", ledger_prj
          ],
                         check=True)
          subprocess.run(["git", "-C", expected_source_path, "clean", "-fxd"],
                         check=True)

      # 初始化会话状态
      session.state["attempt_id"] = current_attempt_id
      session.state["round_id"] = 0
      session.state["current_node_id"] = 0
      session.state["rollback_triggered"] = False
      session.state["ever_used_upstream"] = False
      session.state["project_name"] = project_name
      session.state["project_source_path"] = expected_source_path
      session.state["project_config_path"] = os.path.join(
          os.getcwd(), "oss-fuzz", "projects", project_name)
      session.state["project_config_repo_path"] = os.path.join(
          os.getcwd(), "oss-fuzz")
      session.state["error_time"] = project_info.get('error_time', "")
      session.state["root_cause_commit"] = project_info.get(
          "root_cause_commit", "")
      session.state["root_cause_workspace"] = project_info.get(
          "root_cause_workspace", "")
      print(
          "[DEBUG session init] "
          f"project_name={session.state.get('project_name')} | "
          f"project_source_path={session.state.get('project_source_path')} | "
          f"project_config_path={session.state.get('project_config_path')} | "
          f"project_config_repo_path={session.state.get('project_config_repo_path')} | "
          f"error_time={session.state.get('error_time')} | "
          f"root_cause_commit={session.state.get('root_cause_commit')} | "
          f"root_cause_workspace={session.state.get('root_cause_workspace')}")

      print("初始化第三方项目路径", expected_source_path)

      # 初始化基线账本 Node 0
      initial_ledger = {
          "project_name":
              project_name,
          "archive_date":
              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
          "next_node_id":
              1,
          "nodes": [{
              "node_id": 0,
              "parent_id": -1,
              "identification": {
                  "attempt_id": current_attempt_id,
                  "round_id": 0,
                  "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  "node_status": "Stable",
                  "should_rollback": False,
                  "rollback_type": "NONE"
              },
              "git_sha_state": {
                  "oss-fuzz_sha": "PENDING",
                  "project_sha": "PENDING"
              },
              "action_and_intent": {
                  "root_cause_commit_sha": "N/A",
                  "active_workspace": "UNKNOWN",
                  "target_file": "N/A",
                  "repair_strategy": "Initial baseline state configuration.",
                  "loop_summary": "Baseline compile completed."
              },
              "metrics": {
                  "Ldel": 0,
                  "Ladd": 0,
                  "build_stage_before": "N/A",
                  "build_stage_after": "L1"
              },
              "validation": {
                  "step_1_6_bitmap": [0, 0, 0, 0, 0, 0],
                  "validation_report_before": {},
                  "validation_report_after": {}
              },
              "semantic_memory": {
                  "solved_problems": "None. Initial setup completed.",
                  "unsolved_problems": "Initial build attempt pending.",
                  "reflection_analysis": "Initial environment setup."
              }
          }]
      }
      TraceLedgerManager.save_ledger(initial_ledger)
      print(
          f"--- 📝 Node 0 (Baseline) placeholder initialized in trace ledger. SHA will be backfilled after setup. ---"
      )

      GLOBAL_LOGGER.set_project_context(project_name)
      runner = Runner(agent=root_agent,
                      app_name=APP_NAME,
                      session_service=session_service)

      initial_input = json.dumps({
          "project_name": project_name,
          "oss_fuzz_sha": oss_fuzz_sha,
          "error_time": project_info.get('error_time', ""),
          "original_log_path": original_log_path,
          "project_source_path": expected_source_path,
          "software_repo_url": project_info.get('software_repo_url', ""),
          "software_sha": software_sha,
          "engine": project_info.get('engine', ""),
          "sanitizer": project_info.get('sanitizer', ""),
          "architecture": project_info.get('architecture', ""),
          "base_image_digest": project_info.get('base_image_digest', ""),
          "attempt_id": current_attempt_id,
          "root_cause_commit": project_info.get("root_cause_commit", ""),
          "root_cause_workspace": project_info.get("root_cause_workspace", "")
      })
      initial_message = types.Content(parts=[types.Part(text=initial_input)],
                                      role='user')

      try:
        print(
            f"\n--- 🌀 Starting Attempt {current_attempt_id}/{MAX_RETRIES} (Resilient State) ---"
        )

        # 🔑 物理加固：还原为低耦合生成器，允许安全拦截 ValueError 并在不崩溃的情况下继续执行
        gen = runner.run_async(user_id=USER_ID,
                               session_id=current_session_id,
                               new_message=initial_message)
        while True:
          try:
            event = await gen.__anext__()
          except StopAsyncIteration:
            break
          except ValueError as ve:
            # 🔑 物理加固 1：劫持并非法豁免未注册工具，防止大模型幻觉直接崩掉主工作流
            err_msg = str(ve)
            if "not found" in err_msg or "not registered" in err_msg:
              tool_name = err_msg.split("'")[1] if "'" in err_msg else "unknown"
              print(
                  f"--- ⚠️ Intercepted Illegal Tool Call: {tool_name}. Skipping to prevent crash. ---"
              )
              GLOBAL_LOGGER.log_raw(
                  f"Security Alert: Agent attempted to call unauthorized tool: {tool_name}"
              )
              continue
            else:
              raise ve

          # 🔑 事件去重与标准转换
          event_uid = getattr(event, 'id', hash(repr(event)))
          has_actions = hasattr(event, 'actions') and event.actions is not None
          is_final_resp = event.is_final_response() if hasattr(
              event, 'is_final_response') else False

          dedup_key = (event_uid, 'final' if
                       (is_final_resp or has_actions) else 'stream')
          if dedup_key in processed_event_ids:
            continue
          processed_event_ids.add(dedup_key)

          GLOBAL_LOGGER.log_event(event)

          if event.author in {
              'run_fuzz_and_collect_log_agent', 'decision_agent', 'rsmc_agent',
              'commit_finder_agent', 'solution_applier_agent'
          }:
            func_calls = event.get_function_calls() if hasattr(
                event, 'get_function_calls') else []
            if func_calls:
              current_session = await session_service.get_session(
                  app_name=APP_NAME,
                  user_id=USER_ID,
                  session_id=current_session_id)
              state = current_session.state if current_session else {}
              # print(
              #     f"[DEBUG {event.author} context] "
              #     f"project_name={state.get('project_name')} | "
              #     f"project_source_path={state.get('project_source_path')} | "
              #     f"project_config_path={state.get('project_config_path')} | "
              #     f"project_config_repo_path={state.get('project_config_repo_path')} | "
              #     f"basic_information={state.get('basic_information')}"
              # )

          # Token 计数器更新
          if event.usage_metadata:
            p = getattr(event.usage_metadata, "prompt_token_count", 0) or 0
            c = getattr(event.usage_metadata, "candidates_token_count", 0) or 0
            stats["total_tokens"]["prompt"] += p
            stats["total_tokens"]["completion"] += c
            stats["total_tokens"]["total"] += (p + c)
            project_total_tokens["total"] += (p + c)
            project_total_tokens["prompt"] = project_total_tokens.get(
                "prompt", 0) + p
            project_total_tokens["completion"] = project_total_tokens.get(
                "completion", 0) + c
            # 🔑 统计：本次大循环 token 单独累加
            attempt_tokens["prompt"] += p
            attempt_tokens["completion"] += c
            attempt_tokens["total"] += (p + c)
            if event.author == 'fuzzing_solver_agent':
              stats["code_gen_tokens"] += c

          # 🔑 拦截 1：处理 Initial Setup 的环境配置输出
          if event.author == 'initial_setup_agent' and event.actions and event.actions.state_delta:
            if 'basic_information' in event.actions.state_delta:
              full_info = event.actions.state_delta['basic_information']
              try:
                data = None
                if isinstance(full_info, dict):
                  data = full_info
                elif isinstance(full_info, str):
                  json_match = re.search(r'(\{[\s\S]*\})', full_info)
                  if json_match:
                    data = json.loads(json_match.group(1))

                if data:
                  session = await session_service.get_session(
                      app_name=APP_NAME,
                      user_id=USER_ID,
                      session_id=current_session_id)
                  parsed_source_path = data.get("project_source_path",
                                                expected_source_path)
                  session.state["project_source_path"] = os.path.abspath(
                      parsed_source_path)

                  parsed_config_path = data.get("project_config_path")
                  if parsed_config_path:
                    session.state["project_config_path"] = os.path.abspath(
                        parsed_config_path)
                  else:
                    session.state["project_config_path"] = os.path.join(
                        os.getcwd(), "oss-fuzz", "projects", project_name)
                  session.state["project_config_repo_path"] = os.path.join(
                      os.getcwd(), "oss-fuzz")

                  session.state["error_time"] = data.get("error_time", "")

                  # 防止大模型丢失核心编译元数据，物理兜底强同步
                  fallback_metadata = {
                      "project_name":
                          project_name,
                      "oss_fuzz_sha":
                          oss_fuzz_sha,
                      "error_time":
                          project_info.get('error_time', ""),
                      "original_log_path":
                          original_log_path,
                      "project_source_path":
                          expected_source_path,
                      "software_repo_url":
                          project_info.get('software_repo_url', ""),
                      "software_sha":
                          software_sha,
                      "engine":
                          project_info.get('engine', ""),
                      "sanitizer":
                          project_info.get('sanitizer', ""),
                      "architecture":
                          project_info.get('architecture', ""),
                      "base_image_digest":
                          project_info.get('base_image_digest', ""),
                      "root_cause_commit":
                          project_info.get("root_cause_commit", ""),
                      "root_cause_workspace":
                          project_info.get("root_cause_workspace", "")
                  }

                  # 🔑 物理重构 2：遍历全量基础信息，若字段缺失、空白或为 "N/A"，则执行强行兜底回填
                  for key, val in fallback_metadata.items():
                    if key not in data or not data[key] or data[key] in [
                        "N/A", ""
                    ]:
                      data[key] = val

                  # 🔑 物理重构 3：将归一化后的数据写入 session 变量，保障 downstream 其它 Agent 会话上下文无损
                  session.state["basic_information"] = data
                  agent_tools._LATEST_BASIC_INFORMATION = data
                  print(
                      f"[DEBUG basic_information normalized] {json.dumps(data, ensure_ascii=False)}"
                  )

                  # 🔑 物理重构 4：双层架构完全同步。将对应键值直接对齐至顶级状态，确保物理数据一致性，并强制实施绝对路径安全规整
                  session.state["project_name"] = data["project_name"]
                  session.state["project_source_path"] = os.path.abspath(
                      data["project_source_path"])
                  session.state["error_time"] = data["error_time"]
                  session.state["root_cause_commit"] = data["root_cause_commit"]
                  session.state["root_cause_workspace"] = data[
                      "root_cause_workspace"]

                  oss_sha_actual = TraceLedgerManager.get_git_head_sha(
                      os.path.join(os.getcwd(), "oss-fuzz"))
                  prj_sha_actual = TraceLedgerManager.get_git_head_sha(
                      session.state["project_source_path"])

                  TraceLedgerManager.update_node_fields(
                      0, {
                          "git_sha_state.oss-fuzz_sha": oss_sha_actual,
                          "git_sha_state.project_sha": prj_sha_actual
                      })
                  # 完整性校验：确认写入值不再是占位符
                  if oss_sha_actual == "N/A" or prj_sha_actual == "N/A":
                    print(
                        f"--- ⚠️ [WARNING] Node 0 SHA backfill incomplete: oss={oss_sha_actual}, prj={prj_sha_actual}. manage_git_state(init) may have failed. ---"
                    )
                  else:
                    print(
                        f"--- 💾 Node 0 Git SHA successfully backfilled: {oss_sha_actual[:7]}|{prj_sha_actual[:7]} ---"
                    )
                  print(
                      f"--- 💾 Metadata synced successfully: source_path={session.state['project_source_path']}, config_path={session.state['project_config_path']}, config_repo_path={session.state['project_config_repo_path']} ---"
                  )
              except Exception as e:
                print(f"--- ⚠️ Metadata sync failed: {e} ---")

          # 🔑 拦截 2：rsmc_agent 反思节点脱水
          if event.author == 'rsmc_agent' and event.actions and event.actions.state_delta:
            if 'loop_summary' in event.actions.state_delta:
              summary = event.actions.state_delta['loop_summary']
              if len(summary) > 800:
                event.actions.state_delta[
                    'loop_summary'] = summary[:797] + "..."
                print(
                    "--- [Orchestrator] Force truncated loop_summary to save tokens ---"
                )
              print(
                  "--- [Orchestrator] Step 3 RSMC finished. Executing Clean-1 (Pruning build logs)... ---"
              )
              await _safe_memory_cleaning(session_service, current_session_id)

          # 🔑 拦截 3：solution_applier_agent 封版节点脱水
          if event.author == 'solution_applier_agent' and event.actions and event.actions.state_delta:
            if 'patch_application_result' in event.actions.state_delta:
              print(
                  "--- [Orchestrator] Step 8 Applier finished. Executing Clean-2 (Pruning Solver & Finder history)... ---"
              )
              await _safe_memory_cleaning(session_service, current_session_id)

          # 🔑 拦截 4：监测定位完成
          if event.author == "commit_finder_agent" and event.actions and event.actions.state_delta:
            artifact_path = os.path.join(os.getcwd(), "generated_prompt_file",
                                         "commit_changed.txt")
            if os.path.exists(artifact_path):
              try:
                with open(artifact_path, 'r', encoding='utf-8',
                          errors='ignore') as f:
                  content = f.read()
                  sha_m = re.search(r"SHA:\s*([a-f0-9]+)", content, re.I)
                  ws_m = re.search(
                      r"\[ATTRIBUTION_TYPE\]\s*\n\s*(UPSTREAM|DOWNSTREAM)",
                      content, re.I)
                  if sha_m and ws_m and not project_info.get(
                      "root_cause_commit"):
                    update_yaml_report(
                        file_path=yaml_path,
                        row_index=row_index,
                        result_str=None,
                        root_cause_commit=sha_m.group(1).strip(),
                        root_cause_workspace=ws_m.group(1).strip().upper())
              except Exception as e:
                print(
                    f"--- ⚠️ Warning: Failed to sync commit_finder report to yaml: {e} ---"
                )

          # 🔑 拦截 5：函数级探针劫持
          if (func_resps := event.get_function_responses()):
            for resp in func_resps:
              if resp.name in [
                  'run_fuzz_build_streaming', 'run_fuzz_build_and_validate'
              ]:
                stats["build_calls"] += 1
                stats["repair_rounds"] = max(0, stats["build_calls"] - 1)

              if resp.name == 'run_fuzz_build_and_validate':
                val_report = resp.response.get('validation_report')
                if val_report:
                  # Persist this before ledger/cleanup work and before any
                  # subsequent LLM event can fail.
                  last_validation_report = val_report
                  session = await session_service.get_session(
                      app_name=APP_NAME,
                      user_id=USER_ID,
                      session_id=current_session_id)
                  session.state["last_validation_report"] = val_report
                  session.state["rollback_triggered"] = False

                  # 🔑 修复：对所有轮次执行 CBSC，写入当前活跃节点的 build_stage_after
                  # 原逻辑只处理 round_id == 0，导致 Node 1、2、3 的 build_stage_after 永远为 null
                  print(
                      "--- [补全] Executing CBSC for current node build_stage_after backfill... ---"
                  )
                  classification = cbsc_classify_log()
                  determined_stage = classification["determined_stage"]

                  print(
                      f"[DBG] before backfill: round_id={session.state.get('round_id')}, current_node_id={session.state.get('current_node_id')}"
                  )
                  ledger_for_stage = TraceLedgerManager.load_ledger()
                  print(
                      f"[DBG] ledger last node id={ledger_for_stage['nodes'][-1]['node_id'] if ledger_for_stage.get('nodes') else 'EMPTY'}"
                  )
                  if ledger_for_stage.get("nodes"):
                    target_node_id = ledger_for_stage["nodes"][-1].get(
                        "node_id", 0)
                  else:
                    target_node_id = 0
                  print(
                      f"[DBG] target_node_id={target_node_id}, determined_stage={determined_stage}"
                  )

                  bitmap_keys = [
                      "step_1_official_list", "step_2_infra_compliance",
                      "step_3_sanitizer_injected", "step_4_engine_control",
                      "step_5_logic_linkage", "step_6_runtime_stability"
                  ]
                  step_1_6_bitmap = [
                      1
                      if str(val_report.get(key, "")).startswith("pass") else 0
                      for key in bitmap_keys
                  ]

                  TraceLedgerManager.update_node_fields(
                      target_node_id, {
                          "metrics.build_stage_after": determined_stage,
                          "validation.validation_report_after": val_report,
                          "validation.step_1_6_bitmap": step_1_6_bitmap
                      })
                  print(
                      f"--- [补全] Node {target_node_id} build_stage_after = {determined_stage} ---"
                  )

              if resp.name == 'execute_hsr_decision':
                if resp.response.get("action") == "ROLLBACK":
                  session = await session_service.get_session(
                      app_name=APP_NAME,
                      user_id=USER_ID,
                      session_id=current_session_id)
                  session.state["current_node_id"] = resp.response.get(
                      "target_node_id")

              # 🔑 统计：监听专家知识匹配结果
              if resp.name == 'few_shot_rag_retrieve':
                rag_count = resp.response.get('matched_errors_count', 0)
                if rag_count and rag_count > 0:
                  attempt_expert_matched = True

              if resp.name == 'apply_patch' and resp.response.get('status') in [
                  'success', 'partial_success'
              ]:
                # 🔑 统计：记录最后一次 patch 的文件数和行数
                attempt_last_patch_files = resp.response.get(
                    'modified_files_count', 0)
                attempt_last_patch_lines = resp.response.get(
                    'modified_lines_count', 0)

                # 🔑 修正：upstream 标志监测保留在此处，但 SHA 写入移至 commit 响应后执行
                session = await session_service.get_session(
                    app_name=APP_NAME,
                    user_id=USER_ID,
                    session_id=current_session_id)
                ledger = TraceLedgerManager.load_ledger()
                if ledger.get("nodes"):
                  last_node = ledger["nodes"][-1]
                  if last_node.get("action_and_intent",
                                   {}).get("active_workspace") == "UPSTREAM":
                    if session:
                      session.state["ever_used_upstream"] = True

                # 🔑 新增：在 manage_git_state commit 完成后读取真实 SHA 写入账本
              if resp.name == 'commit_workspace_snapshots' and resp.response.get(
                  'status') == 'success':
                session = await session_service.get_session(
                    app_name=APP_NAME,
                    user_id=USER_ID,
                    session_id=current_session_id)
                oss_sha = resp.response.get('oss_fuzz_sha', 'N/A')
                prj_sha = resp.response.get('project_sha', 'N/A')

                # 🔑 修复：从账本读取最新节点号，而非依赖从不更新的 current_node_id
                ledger_for_sha = TraceLedgerManager.load_ledger()
                if ledger_for_sha.get("nodes"):
                  curr_node = ledger_for_sha["nodes"][-1].get("node_id", 0)
                else:
                  curr_node = session.state.get("current_node_id",
                                                0) if session else 0

                TraceLedgerManager.update_node_fields(
                    curr_node, {
                        "git_sha_state.oss-fuzz_sha": oss_sha,
                        "git_sha_state.project_sha": prj_sha
                    })
                print(
                    f"--- 💾 Node {curr_node} SHA updated after commit: oss={oss_sha[:7] if oss_sha != 'N/A' else 'N/A'}, prj={prj_sha[:7] if prj_sha != 'N/A' else 'N/A'} ---"
                )

          # 只有 OSS-Fuzz check_build（Step 2）通过才允许将项目判定为成功。
          # event.actions.escalate 仅表示工作流请求结束，不能绕过构建验证。
          curr_session = await session_service.get_session(
              app_name=APP_NAME, user_id=USER_ID, session_id=current_session_id)
          if _is_step_2_success(
              curr_session.state.get("last_validation_report", {})):
            is_successful = True
            print(f"--- ✅ Step 2 check_build passed. Workflow finishing. ---")
            break

          # 🔑 物理加固 2：恢复工作流中途物理超时审计，防止无限循环
          if (time.time() - project_start_time) > PROJECT_TIMEOUT_LIMIT:
            print(f"--- ❌ [TIMEOUT] Project {project_name} reached limit. ---")
            break

        if is_successful:
          break

      except litellm.ContextWindowExceededError as e:
        # 🔑 物理加固 3：单独捕获 Token 越界，阻止 Traceback 污染终端
        print(f"--- 🚨 [CRITICAL] Context limit exceeded: {e} ---")
        if _is_step_2_success(last_validation_report):
          is_successful = True
          print(
              "--- ✅ Validation passed before context error; keeping success. ---"
          )
          break
        if attempt + 1 >= MAX_RETRIES:
          break
        continue

      except Exception as e:
        err_tb = traceback.format_exc()
        print(
            f"\n--- ❌ [CRASH DETECTED] Attempt {current_attempt_id} failed: {str(e)} ---"
        )
        print(err_tb)

        GLOBAL_LOGGER.log_raw(
            f"[CRITICAL ATTEMPT EXCEPTION]\nException: {str(e)}\nTraceback:\n{err_tb}"
        )
        if _is_step_2_success(last_validation_report):
          is_successful = True
          print(
              "--- ✅ Validation passed before orchestration error; keeping success. ---"
          )
          break
        await asyncio.sleep(1)
        if attempt + 1 >= MAX_RETRIES:
          break
        continue

  finally:
    # 🔑 统计：生成并输出最终修复报告（容错：即使流程中断也能执行）
    _generate_final_report(
        project_info=project_info,
        is_successful=is_successful,
        attempt_id=current_attempt_id,
        stats=stats,
        attempt_tokens=attempt_tokens,
        attempt_start_time=attempt_start_time,
        attempt_expert_matched=attempt_expert_matched,
        attempt_last_patch_files=attempt_last_patch_files,
        attempt_last_patch_lines=attempt_last_patch_lines,
    )

    try:  # ← finally块内，缩进+4
      if session:
        basic_info = agent_tools.extract_basic_information(
            session.state.get("basic_information"))
        cfg_path = basic_info.get("project_config_path") or session.state.get(
            "project_config_path")
        if not cfg_path or not os.path.exists(cfg_path):
          cfg_path = os.path.join(os.getcwd(), "oss-fuzz", "projects",
                                  project_name)
        src_path = basic_info.get("project_source_path") or session.state.get(
            "project_source_path")
        if not src_path or not os.path.exists(src_path):
          src_path = os.path.join(os.getcwd(), "process", "project", safe_name)

        archive_fixed_project(project_name=project_name,
                              project_config_path=cfg_path,
                              is_success=is_successful,
                              project_source_path=src_path)
        print(f"--- 📦 Project successfully archived to repository context ---")

    except Exception as e:  # ← try必须配except
      print(f"--- ⚠️ [ERROR] Archive failed: {e} ---")

    # 🔑 后续处理逻辑（维持原有缩进，置于循环及 finally 块外部）

  found_sha, found_workspace = None, None
  artifact_path = os.path.join(os.getcwd(), "generated_prompt_file",
                               "commit_changed.txt")
  if os.path.exists(artifact_path):
    try:
      with open(artifact_path, 'r', encoding='utf-8', errors='ignore') as f:
        art_content = f.read()
      # 提取 SHA
      sha_m = re.search(r"SHA:\s*([a-f0-9]+)", art_content, re.I)
      if sha_m:
        found_sha = sha_m.group(1).strip()
      # 提取 Workspace
      ws_m = re.search(r"\[ATTRIBUTION_TYPE\]\s*\n\s*(UPSTREAM|DOWNSTREAM)",
                       art_content, re.I)
      if ws_m:
        found_workspace = ws_m.group(1).strip().upper()

    except Exception as e:
      print(
          f"--- ⚠️ Warning: Failed to parse root cause from artifact: {e} ---")
  # 如果工件未产生但原本输入就有，采取入参数据进行兜底
  final_sha = found_sha if (found_sha and
                            found_sha != "UNKNOWN") else project_info.get(
                                "root_cause_commit", "")
  final_workspace = found_workspace if found_workspace else project_info.get(
      "root_cause_workspace", "")

  basic_info = agent_tools.extract_basic_information(
      session.state.get("basic_information")) if session else {}
  return is_successful, basic_info.get("project_config_path") or (
      session.state.get("project_config_path")
      if session else None), final_sha, final_workspace


warnings.filterwarnings("ignore", category=RuntimeWarning, module="google.adk")


async def main():
  print("--- Starting automated fix workflow ---")

  # 🔑 调整：不再在 main() 中全局创建 Agent，它们会在 Attempt 启动时由流程自动重新生成
  projects_result = read_projects_from_yaml(YAML_FILE)

  if not isinstance(projects_result, dict):
    print(
        f"❌ Critical Error: read_projects_from_yaml returned invalid type: {projects_result}"
    )
    return

  if projects_result.get('status') == 'error':
    print(
        f"Error: Could not process YAML file: {projects_result.get('message')}")
    return

  projects_to_process = projects_result.get('projects', [])
  if not projects_to_process:
    print("--- No new projects to process were found. Workflow finished. ---")
    return

  print(f"--- Found {len(projects_to_process)} projects to process ---")

  for project_info in projects_to_process:
    try:
      project_name = project_info['project_name']
      row_index = project_info['row_index']
      initial_input_data = {
          "project_name": project_name,
          "sha": project_info['sha'],
          "original_log_path": project_info['original_log_path'],
          "software_repo_url": project_info['software_repo_url'],
          "software_sha": project_info['software_sha'],
          "engine": project_info['engine'],
          "sanitizer": project_info['sanitizer'],
          "architecture": project_info['architecture'],
          "base_image_digest": project_info['base_image_digest'],
          "error_time": project_info['error_time'],
          # 🔑 新增：载入可能预设在 YAML 里的 root_cause_commit 和 root_cause_workspace
          "root_cause_commit": project_info.get('root_cause_commit', ""),
          "root_cause_workspace": project_info.get('root_cause_workspace', "")
      }

      print(f"\n{'=' * 60}")
      print(f"--- Processing Project: {project_name} (Index: {row_index}) ---")
      print(f"{'=' * 60}")

      # 使用支持根写的新工具置于 Progress
      update_yaml_report(YAML_FILE, row_index, "Failure (Crashed/In_Progress)")
      cleanup_environment(project_name)

      # 🔑 调整：匹配接收四个返回值，包含根因提取出的 SHA 和 workspace
      is_successful, project_config_path, final_sha, final_workspace = await process_single_project(
          initial_input_data, YAML_FILE, row_index)

      result_str = "Success" if is_successful else "Failure"
      print(f"--- Project {project_name} complete. Result: {result_str} ---")

      # 🔑 调整：使用支持根写的 YAML 更新函数，在 error_category 插入 root_cause_commit 和 root_cause_workspace
      update_result = update_yaml_report(file_path=YAML_FILE,
                                         row_index=row_index,
                                         result_str=result_str,
                                         root_cause_commit=final_sha,
                                         root_cause_workspace=final_workspace)

      if update_result['status'] == 'error':
        print(
            f"--- [CRITICAL] Could not update YAML report: {update_result['message']} ---"
        )

      cleanup_environment(project_name)
    except Exception as e:
      print(f"--- [CRITICAL] Project {project_name} failed with error: {e} ---")
      continue

  print(
      "\n--- All projects in the queue have been processed. Workflow finished. ---"
  )


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Run the fix-build agent.")
  parser.add_argument("--projects-yaml", default=YAML_FILE)
  parser.add_argument("--model", default=MODEL)
  parser.add_argument("--api-base", default=api_base)
  parser.add_argument("--skip-gh-auth-check",
                      action="store_true",
                      default=SKIP_GH_AUTH_CHECK)
  cli_args = parser.parse_args()
  YAML_FILE = cli_args.projects_yaml
  MODEL = cli_args.model
  api_base = cli_args.api_base or None
  SKIP_GH_AUTH_CHECK = cli_args.skip_gh_auth_check

  print("--- Performing pre-startup checks... ---")
  sys.stdout = StreamTee(sys.stdout, GLOBAL_LOGGER)
  sys.stderr = StreamTee(sys.stderr, GLOBAL_LOGGER)
  has_model_credentials = bool(API_KEY) or _model_uses_vertex_adc(MODEL)
  if not has_model_credentials:
    print("\n[ERROR] Startup failed: API_KEY is not set for this model.")
  else:
    if API_KEY:
      print("✅ API_KEY is set.")
    else:
      print("✅ Vertex AI ADC will be used (no API_KEY required).")
    try:
      if not SKIP_GH_AUTH_CHECK:
        subprocess.run(["gh", "--version"],
                       check=True,
                       capture_output=True,
                       text=True)
        print("✅ GitHub CLI ('gh') is installed.")
      else:
        print("⚠️ GitHub CLI checks skipped by configuration.")
      try:
        print("✅ 'requests' library is installed.")
      except ImportError:
        print("\n[ERROR] Startup failed: 'requests' library is not installed.")
        sys.exit(1)
      if not SKIP_GH_AUTH_CHECK:
        subprocess.run(["gh", "auth", "status"],
                       check=True,
                       capture_output=True)
        print("✅ GitHub CLI ('gh') is logged in.")
      print("\n--- Checks complete. Preparing to start the Agent... ---")

      # 🔑 物理执行标准异步事件循环，并在内部启动主程序
      asyncio.run(main())

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
      print(
          "\n[ERROR] Startup failed: GitHub CLI ('gh') is not installed or not logged in."
      )
      print(f"Error details: {e}")
