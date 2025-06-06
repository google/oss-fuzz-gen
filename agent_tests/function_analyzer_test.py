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
import os
from typing import List

import run_all_experiments
from agent import function_analyzer
from experiment import benchmark as benchmarklib
from experiment import workdir
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

  parser.add_argument('-d',
                      '--benchmarks-directory',
                      type=str,
                      help='A directory containing benchmark YAML files.')

  parser.add_argument('-w', '--work-dir', default=RESULTS_DIR)

  parser.add_argument('-mr',
                      '--max-round',
                      type=int,
                      default=100,
                      help='Max trial round for agents.')

  parsed_args = parser.parse_args()

  return parsed_args


if __name__ == "__main__":

  model = models.LLM.setup(ai_binary='', name='vertex_ai_gemini-2-5-pro-chat')

  args = parse_args()

  # Initialize the working directory
  args.work_dirs = workdir.WorkDirs(args.work_dir)

  # Initialize the function analyzer
  function_analyzer = function_analyzer.FunctionAnalyzer(trial=1,
                                                         llm=model,
                                                         args=args)

  # Initialize benchmarks
  benchmarks: List[
      benchmarklib.Benchmark] = run_all_experiments.prepare_experiment_targets(
          args)

  if len(benchmarks) == 0:
    raise ValueError("No benchmarks found in the YAML file.")

  logger.info("Loaded %d benchmarks from the YAML file %s.", len(benchmarks),
              args.benchmark_yaml)

  # Analyze each benchmark
  for test_benchmark in benchmarks:
    logger.info("Loaded benchmark (%d/%d) for function: %s",
                benchmarks.index(test_benchmark) + 1, len(benchmarks),
                test_benchmark.function_name)

    # Initialize the function analyzer with the first benchmark
    function_analyzer.initialize(test_benchmark)

    # Run the function analyzer
    result = function_analyzer.execute([])

    # If result is available, write it to the work_dirs directory
    if result.result_available and result.result_raw:
      result_file = os.path.join(
          args.work_dirs.base,
          f"{test_benchmark.project}_{test_benchmark.function_name}.txt")
      with open(result_file, 'w') as f:
        f.write(result.result_raw)
      logger.info("Analysis results written to %s", result_file)
    else:
      logger.info("No requirements found for benchmark %s",
                  test_benchmark.function_name)
