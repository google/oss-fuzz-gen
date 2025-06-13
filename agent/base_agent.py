# Copyright 2025 Google LLC
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
"""The abstract base class for LLM agents in stages."""
import argparse
import asyncio
import os
import random
import re
import shutil
import subprocess as sp
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

import requests
from google.adk import agents, runners, sessions
from google.genai import errors, types

import logger
import utils
from data_prep import introspector
from experiment import benchmark as benchmarklib
from llm_toolkit.models import LLM, VertexAIModel
from llm_toolkit.prompts import Prompt
from results import Result
from tool.base_tool import BaseTool


class BaseAgent(ABC):
  """The abstract base class for LLM agents in stages."""

  def __init__(self,
               trial: int,
               llm: LLM,
               args: argparse.Namespace,
               tools: Optional[list[BaseTool]] = None,
               name: str = ''):
    self.trial: int = trial
    self.llm: LLM = llm
    self.tools: list[BaseTool] = tools or []
    self.args = args
    self.name: str = name or self.__class__.__name__
    self.chat_history: str = ''  # Communication history between LLM and tool.
    self.max_round = self.args.max_round

  def __repr__(self) -> str:
    return self.__class__.__name__

  def get_tool(self, tool_name: str) -> Optional[BaseTool]:
    """Gets a tool of the agent by name."""
    for tool in self.tools:
      if tool.name == tool_name:
        return tool
    return None

  def chat_llm_with_tools(self, client: Any, prompt: Optional[Prompt], tools,
                          trial) -> Any:
    """Chat with LLM with tools."""
    logger.info(
        '<CHAT WITH TOOLS PROMPT:ROUND %02d>%s</CHAT PROMPT:ROUND %02d>',
        trial,
        prompt.get() if prompt else '',
        trial,
        trial=trial)
    response = self.llm.chat_llm_with_tools(client=client,
                                            prompt=prompt,
                                            tools=tools)
    logger.info(
        '<CHAT WITH TOOLS RESPONSE:ROUND %02d>%s</CHAT RESPONSE:ROUND %02d>',
        trial,
        response,
        trial,
        trial=trial)
    return response

  def chat_llm(self, cur_round: int, client: Any, prompt: Prompt,
               trial: int) -> str:
    """Chat with LLM."""
    logger.info('<CHAT PROMPT:ROUND %02d>%s</CHAT PROMPT:ROUND %02d>',
                cur_round,
                prompt.gettext(),
                cur_round,
                trial=trial)
    response = self.llm.chat_llm(client=client, prompt=prompt)
    logger.info('<CHAT RESPONSE:ROUND %02d>%s</CHAT RESPONSE:ROUND %02d>',
                cur_round,
                response,
                cur_round,
                trial=trial)
    return response

  def ask_llm(self, cur_round: int, prompt: Prompt, trial: int) -> str:
    """Ask LLM."""
    logger.info('<ASK PROMPT:ROUND %02d>%s</ASK PROMPT:ROUND %02d>',
                cur_round,
                prompt.gettext(),
                cur_round,
                trial=trial)
    response = self.llm.ask_llm(prompt=prompt)
    logger.info('<ASK RESPONSE:ROUND %02d>%s</ASK RESPONSE:ROUND %02d>',
                cur_round,
                response,
                cur_round,
                trial=trial)
    return response

  def _parse_tag(self, response: str, tag: str) -> str:
    """Parses the XML-style tags from LLM response."""
    match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return match.group(1).strip() if match else ''

  def _parse_tags(self, response: str, tag: str) -> list[str]:
    """Parses the XML-style tags from LLM response."""
    matches = re.findall(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return [content.strip() for content in matches]

  def _filter_code(self, raw_code_block: str) -> str:
    """Filters out irrelevant lines from |raw_code_block|."""
    # TODO(dongge): Move this function to a separate module.
    # Remove markdown-style code block symbols.
    filtered_lines = [
        line for line in raw_code_block.splitlines()
        if not line.strip().startswith('```')
    ]
    # Sometimes LLM returns a build script containing only comments.
    if all(line.strip().startswith('#') for line in filtered_lines):
      return ''
    filtered_code_block = '\n'.join(filtered_lines)
    return filtered_code_block

  def _format_bash_execution_result(
      self,
      process: sp.CompletedProcess,
      previous_prompt: Optional[Prompt] = None) -> str:
    """Formats a prompt based on bash execution result."""
    if previous_prompt:
      previous_prompt_text = previous_prompt.gettext()
    else:
      previous_prompt_text = ''
    stdout = self.llm.truncate_prompt(process.stdout,
                                      previous_prompt_text).strip()
    stderr = self.llm.truncate_prompt(process.stderr,
                                      stdout + previous_prompt_text).strip()
    return (f'<bash>\n{process.args}\n</bash>\n'
            f'<return code>\n{process.returncode}\n</return code>\n'
            f'<stdout>\n{stdout}\n</stdout>\n'
            f'<stderr>\n{stderr}\n</stderr>\n')

  def _container_handle_bash_command(self, response: str, tool: BaseTool,
                                     prompt: Prompt) -> Prompt:
    """Handles the command from LLM with container |tool|."""
    prompt_text = ''
    for command in self._parse_tags(response, 'bash'):
      prompt_text += self._format_bash_execution_result(
          tool.execute(command), previous_prompt=prompt) + '\n'
      prompt.append(prompt_text)
    return prompt

  def _container_handle_invalid_tool_usage(self, tool: BaseTool, cur_round: int,
                                           response: str,
                                           prompt: Prompt) -> Prompt:
    """Formats a prompt to re-teach LLM how to use the |tool|."""
    logger.warning('ROUND %02d Invalid response from LLM: %s',
                   cur_round,
                   response,
                   trial=self.trial)
    prompt_text = (f'No valid instruction received, Please follow the '
                   f'interaction protocols:\n{tool.tutorial()}')
    prompt.append(prompt_text)
    return prompt

  def _container_handle_bash_commands(self, response: str, tool: BaseTool,
                                      prompt: Prompt) -> Prompt:
    """Handles the command from LLM with container |tool|."""
    prompt_text = ''
    for command in self._parse_tags(response, 'bash'):
      prompt_text += self._format_bash_execution_result(
          tool.execute(command), previous_prompt=prompt) + '\n'
      prompt.append(prompt_text)
    return prompt

  def _sleep_random_duration(
      self,
      trial: int,
      min_sec: int = 1,
      max_sec: int = 60,
  ) -> None:
    """Sleeps for a random duration between min_sec and max_sec. Agents uses
    this to avoid exceeding quota limit (e.g., LLM query frequency)."""
    duration = random.randint(min_sec, max_sec)
    logger.debug('Sleeping for %d before the next query', duration, trial=trial)
    time.sleep(duration)

  @classmethod
  def _parse_args(cls) -> argparse.Namespace:
    """Parses command line args."""
    parser = argparse.ArgumentParser(
        description='Execute agent in cloud with dill files.')
    parser.add_argument('-a',
                        '--agent',
                        help='The dill file path for the agent to execute.')
    parser.add_argument(
        '-rh',
        '--result-history',
        help='The dill file path for the agent input result history.')
    parser.add_argument(
        '-rn',
        '--result-new',
        help='The dill file path to store the agent output new result.')
    return parser.parse_args()

  @classmethod
  def _preprocess_fi_setup(cls) -> None:
    """Logic for starting a custom Fuzz Introspector used on cloud builds"""
    logger.info('Checkign if we should use local FI', trial=0)
    if not os.path.isdir('/workspace/data-dir'):
      logger.info('This does not require a local FI.', trial=0)
      return
    logger.info('We should use local FI.', trial=0)

    # Clone Fuzz Introspector
    introspector_repo = 'https://github.com/ossf/fuzz-introspector'
    introspector_dst = '/workspace/fuzz-introspector'
    sp.check_call(f'git clone {introspector_repo} {introspector_dst}',
                  shell=True)
    fi_web_dir = '/workspace/fuzz-introspector/tools/web-fuzzing-introspection'
    # Install reqs
    sp.check_call(
        'python3.11 -m pip install --ignore-installed -r requirements.txt',
        cwd=fi_web_dir,
        shell=True)

    # Copy over the DB
    shutil.rmtree(os.path.join(fi_web_dir, 'app/static/assets/db/'))
    shutil.copytree('/workspace/data-dir/fuzz_introspector_db',
                    os.path.join(fi_web_dir, 'app/static/assets/db/'))

    # Launch webapp
    fi_environ = os.environ
    fi_environ['FUZZ_INTROSPECTOR_SHUTDOWN'] = '1'
    fi_environ[
        'FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ'] = '/workspace/data-dir/oss-fuzz2'
    sp.check_call('python3.11 main.py >> /dev/null &',
                  shell=True,
                  env=fi_environ,
                  cwd=os.path.join(fi_web_dir, 'app'))

    logger.info('Waiting for the webapp to start', trial=0)

    sec_to_wait = 10
    max_wait_iterations = 10
    for idx in range(max_wait_iterations):
      time.sleep(sec_to_wait)

      resp = requests.get('http://127.0.0.1:8080', timeout=10)
      if 'Fuzzing' in resp.text:
        break
      if idx == max_wait_iterations - 1:
        # Launching FI failed. We can still continue, although context
        # will be missing from runs.
        logger.info('Failed to start webapp', trial=10)

    introspector.set_introspector_endpoints('http://127.0.0.1:8080/api')

  def get_function_requirements(self) -> str:
    """Gets the function requirements from the result."""

    requirements_path = self.args.work_dirs.requirements_file_path(self.trial)
    if os.path.isfile(requirements_path):
      with open(requirements_path, 'r') as file:
        function_requirements = file.read()
    else:
      function_requirements = ''

    return function_requirements

  @classmethod
  def cloud_main(cls) -> None:
    """Executes agent using dill files. This is for cloud experiments launched
    by cloud_builder.py. It runs `new_result = agent.execute(result_history)` in
    the same way as local experiments, except `agent` and `result_history` are
    deserialized from dill files and new_result will be serialized to share data
    with the cloud experiment requester."""
    args = cls._parse_args()

    cls._preprocess_fi_setup()

    agent = utils.deserialize_from_dill(args.agent)
    agent.llm.cloud_setup()
    result_history = utils.deserialize_from_dill(args.result_history)
    result = agent.execute(result_history)
    utils.serialize_to_dill(result, args.result_new)

  @abstractmethod
  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """The initial prompt of the agent."""

  @abstractmethod
  def execute(self, result_history: list[Result]) -> Result:
    """Executes the agent based on previous result."""


class ADKBaseAgent(BaseAgent):
  """The abstract base class for agents created using the ADK library."""

  def __init__(self,
               trial: int,
               llm: LLM,
               args: argparse.Namespace,
               benchmark: benchmarklib.Benchmark,
               description: str = '',
               instruction: str = '',
               tools: Optional[list] = None,
               name: str = ''):

    super().__init__(trial, llm, args, tools, name)

    self.benchmark = benchmark

    # For now, ADKBaseAgents only support the Vertex AI Models.
    if not isinstance(llm, VertexAIModel):
      raise ValueError(f'{self.name} only supports Vertex AI models.')

    # Create the agent using the ADK library
    adk_agent = agents.LlmAgent(
        name=self.name,
        model=llm._vertex_ai_model,
        description=description,
        instruction=instruction,
        tools=tools or [],
    )

    # Create the session service
    session_service = sessions.InMemorySessionService()
    session_service.create_session(
        app_name=self.name,
        user_id=benchmark.id,
        session_id=f"session_{self.trial}",
    )

    # Create the runner
    self.runner = runners.Runner(
        agent=adk_agent,
        app_name=self.name,
        session_service=session_service,
    )

    self.round = 0

    logger.info("ADK Agent %s created.", self.name, trial=self.trial)

  def chat_llm(self, cur_round: int, client: Any, prompt: Prompt,
               trial: int) -> str:
    """Call the agent with the given prompt, running async code in sync."""

    self.round = cur_round

    self.log_llm_prompt(prompt.get())

    async def _call():
      user_id = self.benchmark.id
      session_id = f"session_{self.trial}"
      content = types.Content(role='user',
                              parts=[types.Part(text=prompt.get())])

      final_response_text = ''

      async for event in self.runner.run_async(
          user_id=user_id,
          session_id=session_id,
          new_message=content,
      ):
        if event.is_final_response():
          if (event.content and event.content.parts and
              event.content.parts[0].text):
            final_response_text = event.content.parts[0].text
          elif event.actions and event.actions.escalate:
            error_message = event.error_message
            logger.error("Agent escalated: %s", error_message, trial=self.trial)

      self.log_llm_response(final_response_text)

      return final_response_text

    return self.llm.with_retry_on_error(lambda: asyncio.run(_call()),
                                        [errors.ClientError])

  def log_llm_prompt(self, promt: str) -> None:
    self.round += 1
    logger.info('<CHAT PROMPT:ROUND %02d>%s</CHAT PROMPT:ROUND %02d>',
                self.round,
                promt,
                self.round,
                trial=self.trial)

  def log_llm_response(self, response: str) -> None:
    logger.info('<CHAT RESPONSE:ROUND %02d>%s</CHAT RESPONSE:ROUND %02d>',
                self.round,
                response,
                self.round,
                trial=self.trial)


if __name__ == "__main__":
  # For cloud experiments.
  BaseAgent.cloud_main()
