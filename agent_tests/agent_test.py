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
"""A test for the function analyzer agent."""

import argparse
import json
import os
import traceback
from datetime import datetime
from typing import List, Tuple, Type

import logger
import run_one_experiment
from agent import base_agent, context_analyzer
from agent_tests import base_agent_test, context_analyzer_test
from data_prep import introspector
from experiment import benchmark as benchmarklib
from experiment import workdir
from llm_toolkit import models
from results import AnalysisResult, CrashResult, Result, RunResult

RESULTS_DIR = f'./results-{datetime.now().strftime("%Y-%m-%d-%H-%M")}'

NUM_ANA = int(os.getenv('LLM_NUM_ANA', '2'))

agents = {
    'ContextAnalyzer': (context_analyzer.ContextAnalyzer, context_analyzer_test.ContextAnalyzerAgentTest),
}


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Evaluate the function analyzer agent.')

  parser.add_argument('-y',
                      '--benchmark-yaml',
                      type=str,
                      required=True,
                      help='A benchmark YAML file.')

  parser.add_argument('-f',
                      '--function-name',
                      type=str,
                      required=True,
                      help='The function name to analyze.')

  parser.add_argument('-p',
                      '--pipeline',
                      type=str,
                      required=True,
                      help='Comma-separated list of agent names for testing.')

  parser.add_argument('-pf',
                      '--prompt-file',
                      type=str,
                      required=True,
                      default='',
                      help='A file containing the prompt to reconstruct for initial agent.')

  parser.add_argument('-mr',
                      '--max-round',
                      type=int,
                      default=100,
                      help='Max trial round for agents.')

  parser.add_argument('-e',
                      '--introspector-endpoint',
                      type=str,
                      default=introspector.DEFAULT_INTROSPECTOR_ENDPOINT)

  parser.add_argument(
      '-of',
      '--oss-fuzz-dir',
      help='OSS-Fuzz dir path to use. Create temporary directory by default.',
      default='')

  parser.add_argument('-w', '--work-dir', default=RESULTS_DIR)

  parsed_args = parser.parse_args()

  if not parsed_args.benchmark_yaml.endswith('.yaml') or not os.path.isfile(parsed_args.benchmark_yaml):
    raise ValueError('Benchmark YAML file must be a valid .yaml file.')

  if not os.path.isfile(parsed_args.prompt_file):
    raise ValueError('Prompt file must be a valid file.')
  with open(parsed_args.prompt_file, 'r') as file:
    prompt_content = file.read()
    if not prompt_content.strip():
      raise ValueError('Prompt file cannot be empty.')
    parsed_args.prompt = prompt_content.strip()

  return parsed_args

def get_test_pipeline(agents_text: str) -> List[Tuple[Type[base_agent.BaseAgent], Type[base_agent_test.BaseAgentTest]]]:
  """Returns a pipeline of agents for testing."""

  agent_list = agents_text.strip().split(',')
  pipeline = []
  for agent_name in agent_list:
    if agent_name not in agents:
      raise ValueError(f'Agent {agent_name} is not defined in the agents dictionary.')
    pipeline.append(agents[agent_name])
  if not pipeline:
    raise ValueError('No agents found in the pipeline. Please provide a valid agent list.')
  return pipeline

def get_result_list_for_agent(
    agent_class: Tuple[Type[base_agent.BaseAgent], Type[base_agent_test.BaseAgentTest]],
    benchmark: benchmarklib.Benchmark,
    prompt: str) -> List[Result]:
  """Returns the initial result list for the agent."""

  agent_test_class = agent_class[1]
  # Ensure agent_test_class is a subclass of BaseAgentTest
  if not issubclass(agent_test_class, base_agent_test.BaseAgentTest):
    raise TypeError(f"{agent_test_class.__name__} is not a subclass of BaseAgentTest")

  agent_test_instance = agent_test_class(args, trial=1)
  return agent_test_instance.setup_initial_result_list(benchmark, prompt)

def write_result(args: argparse.Namespace, trial: int, result: Result) -> None:
  """Writes the result to a file in the work directory."""

  result_file = os.path.join(args.work_dirs.base, f'{trial}_result.json')
  with open(result_file, 'w') as file:
    json.dump(result.to_dict(), file, indent=2)

  logger.info('Result written to %s', result_file, trial=trial)

if __name__ == '__main__':

  model = models.LLM.setup(ai_binary='', name='vertex_ai_gemini-2-5-pro-chat')

  args = parse_args()

  introspector.set_introspector_endpoints(args.introspector_endpoint)

  run_one_experiment.prepare(args.oss_fuzz_dir)

  # Initialize test benchmark
  benchmarks = benchmarklib.Benchmark.from_yaml(args.benchmark_yaml)

  test_benchmark = [benchmark for benchmark in benchmarks
                    if benchmark.function_name == args.function_name]

  if not test_benchmark:
    raise ValueError(f'No benchmark found for function {args.function_name}.')

  benchmark = test_benchmark[0]

  # Initialize the working directory
  args.work_dirs = workdir.WorkDirs(os.path.join(args.work_dir, f'output-{benchmark.id}'))

  pipeline = get_test_pipeline(args.pipeline)

  trial = 1

  result_list = get_result_list_for_agent(pipeline[0], benchmark, args.prompt)

  result = None

  try:

    for agent_class in pipeline:
      agent_instance = agent_class[0](trial, model, args, benchmark)

      # Execute the agent with the initial results
      result = agent_instance.execute(result_list)

      # Prepare for the next agent in the pipeline
      result_list.append(result)

    if result:
      # Write the final result to a file
      write_result(args, trial, result)

  except Exception as e:
    logger.error('An error occurred during the agent execution: %s', str(e), trial=trial)
    logger.error('Traceback: %s', traceback.format_exc(), trial=trial)
