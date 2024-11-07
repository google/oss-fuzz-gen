"""An LLM agent to analyze and provide insight of a fuzz target's runtime crash.
Use it as a usual module locally, or as script in cloud builds.
"""
import os
import logger
import shutil
import time
import random
import subprocess as sp

from typing import Optional
from experiment import evaluator as evaluator_lib
from experiment import oss_fuzz_checkout
from agent.base_agent import BaseAgent
from llm_toolkit.prompt_builder import DefaultTemplateBuilder
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result, RunResult, CrashResult
from tool.lldb_tool import LLDBTool

MAX_ROUND = 100


class CrashAnalyzer(BaseAgent):
  """The Agent to analyze a runtime crash and provide insight to fuzz target."""

  def _initial_prompt(self, run_result: Result) -> Prompt:
    """Constructs initial prompt of the agent."""

    default_prompt_builder = DefaultTemplateBuilder(model=self.llm,
                                                    benchmark=run_result.benchmark)
    prompt = default_prompt_builder.build_triager_prompt(run_result.fuzz_target_source, 
                                                         run_result.run_error, 
                                                         run_result.crash_func)
    return prompt
  
  def _create_ossfuzz_project_with_lldb(self, 
                                        name: str, 
                                        target_file: str, 
                                        build_script_path: str) -> str:
    """Creates an OSS-Fuzz project with new dockerfile. The new project
    will replicate an existing project |name| but modify its dockerfile."""
    logger.info('target file: %s', target_file)
    generated_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                          'projects', name)
    if os.path.exists(generated_project_path):
      logger.info('Project %s already exists.', generated_project_path)
      return name

    existing_project_path = os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR,
                                         'projects', self.benchmark.project)

    shutil.copytree(existing_project_path, generated_project_path)

    # Copy generated fuzzers to generated_project_path
    shutil.copyfile(
        target_file,
        os.path.join(generated_project_path, os.path.basename(target_file)))

    if os.path.getsize(build_script_path) == 0:
      # Add additional statement in dockerfile to enable -g and install lldb.
      with open(os.path.join(generated_project_path, 'Dockerfile'), 'a') as f:
        f.write(
          '\nENV FUZZING_LANGUAGE=c++\n'
          '\nRUN sed -i.bak "1s|^|export CFLAGS=${CFLAGS} -g" "/src/build.sh"\n'
          '\nRUN apt-get update && apt-get install -y lldb\n'
        )
      return name

    # Copy generated build script to generated_project_path
    shutil.copyfile(
        build_script_path,
        os.path.join(generated_project_path,
                     os.path.basename('agent-build.sh')))

    # Add additional statement in dockerfile to overwrite with generated fuzzer, \
    # enable -g and install lldb
    with open(os.path.join(generated_project_path, 'Dockerfile'), 'a') as f:
      f.write('\nCOPY agent-build.sh /src/build.sh\n'
              '\nENV FUZZING_LANGUAGE=c++\n'
              '\nRUN sed -i.bak "1s|^|export CFLAGS=${CFLAGS} -g" "/src/build.sh"\n'
              '\nRUN apt-get update && apt-get install -y lldb\n'        
      )

    return name
  
  def _sleep_random_duration(self, min_sec: int = 1, max_sec: int = 60) -> None:
    """Sleeps for a random duration between min_sec and max_sec. Agents uses
    this to avoid exceeding quota limit (e.g., LLM query frequency)."""
    duration = random.randint(min_sec, max_sec)
    logger.debug('Sleeping for %d before the next query', duration)
    time.sleep(duration)

  def _handle_conclusion(
      self, cur_round: int, response: str,
      crash_result: CrashResult):
    """Parses LLM conclusion, analysis and suggestion."""
    logger.info('----- ROUND %02d Received conclusion -----', cur_round)

    conclusion = self._parse_tag(response, 'conclusion')
    if conclusion == 'Crash is caused by bug in fuzz driver':
      crash_result.true_bug = False
    elif conclusion == 'Crash is caused by bug in project':
      crash_result.true_bug = True
    else:
      logger.error('***** Failed to match conclusion in %02d rounds *****', cur_round)

    crash_result.insight = self._parse_tag(response, 'analysis and suggestion')
    if not crash_result.insight:
      logger.error('Round %02d No analysis and suggestion in conclusion: %s', 
                  cur_round, response)

  def _container_tool_reaction(self, cur_round: int, response: str,
                               crash_result: CrashResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    if self._parse_tag(response, 'conclusion'):
      return self._handle_conclusion(cur_round, response,
                                               crash_result) # if build success, return none <=> exit chat
    return self._container_handle_bash_command(cur_round, response,
                                               self.analyze_tool) # return non-none prompt <=> continue chat
  
  def execute(self, result_history: list[Result]) -> CrashResult:
    """Executes the agent based on previous run result."""
    logger.info('Executing Crash Analyzer')
    last_result = result_history[-1] # RunResult
    benchmark = last_result.benchmark # last RunResult.benchmark
    generated_target_name = os.path.basename(benchmark.target_path)
    sample_id = os.path.splitext(generated_target_name)[0]
    generated_oss_fuzz_project = f'{benchmark.id}-{sample_id}-lldb' 
    generated_oss_fuzz_project = evaluator_lib.rectify_docker_tag(
        generated_oss_fuzz_project)

    fuzz_target_path = os.path.join(last_result.work_dirs.fuzz_targets,
                                    f'{last_result.trial:02d}.fuzz_target')
    build_script_path = os.path.join(last_result.work_dirs.fuzz_targets,
                                     f'{last_result.trial:02d}.build_script')
    
    self._create_ossfuzz_project_with_lldb(generated_oss_fuzz_project, 
                                           fuzz_target_path, build_script_path) # probably return without modifying dockerfile?
                                           
    self.analyze_tool = LLDBTool(benchmark, name='lldb', 
                                 project=generated_oss_fuzz_project,)
    self.analyze_tool.execute('compile > /dev/null')
    prompt = self._initial_prompt(last_result) # prompt to analyze crash
    #TODO: delete
    print('analyzer initial prompt:', prompt)
    prompt.add_problem(self.analyze_tool.tutorial())
    #TODO: delete
    print('analyzer after append tutorial prompt:', prompt)
    crash_result = CrashResult(
      benchmark=benchmark,
      trial=last_result.trial,
      work_dirs=last_result.work_dirs,
      fuzz_target_source=last_result.fuzz_target_source,
      build_script_source=last_result.build_script_source,
      author=self,
      chat_history=last_result.chat_history)
    cur_round = 1
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt and cur_round < MAX_ROUND: #when prompt is empty or cur_round >= MAX_ROUND, exit.
        logger.info('ROUND %02d agent prompt: %s', cur_round, prompt.get())
        response = self.llm.chat_llm(client=client, prompt=prompt)
        logger.debug('ROUND %02d LLM response: %s', cur_round, response)
        prompt = self._container_tool_reaction(cur_round, response,
                                               crash_result)
        cur_round += 1
        self._sleep_random_duration()
    finally:
      # Cleanup: stop the container
      logger.debug('Stopping the crash analyze container %s',
                   self.analyze_tool.container_id)
      self.analyze_tool.terminate() # only stop the container
      
    return crash_result
