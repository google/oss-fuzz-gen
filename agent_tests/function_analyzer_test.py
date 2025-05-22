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
import logging
from typing import List

from agent.function_analyzer import FunctionAnalyzer
from experiment import benchmark as benchmarklib
from experiment.benchmark import Benchmark
from llm_toolkit import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RESULTS_DIR = './results'


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Evaluate the function analyzer agent.')

  parser.add_argument('-y',
                      '--benchmark-yaml',
                      type=str,
                      required=True,
                      help='A benchmark YAML file.')

  parser.add_argument('-w', '--work-dir', default=RESULTS_DIR)

  parser.add_argument('-mr',
                      '--max-round',
                      type=int,
                      default=100,
                      help='Max trial round for agents.')

  parsed_args = parser.parse_args()

  return parsed_args


if __name__ == "__main__":

  model = models.LLM.setup(ai_binary='', name='vertex_ai_gemini-1-5-chat')

  args = parse_args()

  function_analyzer = FunctionAnalyzer(trial=1, llm=model, args=args)

  benchmarks: List[Benchmark] = benchmarklib.Benchmark.from_yaml(
      args.benchmark_yaml)

  if len(benchmarks) == 0:
    raise ValueError("No benchmarks found in the YAML file.")

  test_benchmark = benchmarks[0]
  logger.info("Loaded benchmark for function: %s", test_benchmark.function_name)

  # Initialize the function analyzer with the first benchmark
  function_analyzer.initialize(test_benchmark)

  # Run the function analyzer
  result = function_analyzer.execute([])

  # Print the result
  logger.info("Function Analyzer Result:")
  logger.info("Result available: %s", result.result_available)
  logger.info("Requirements: %s", result.requirements)
