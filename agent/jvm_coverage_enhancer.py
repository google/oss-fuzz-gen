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
"""
Module: JVM Coverage Enhancer

This module provides a helper agent to improve code coverage for JVM-based
fuzz targets by generating or fixing JVM harnesses using LLM prompts.
"""

import os

from agent.prototyper import Prototyper
from llm_toolkit.prompt_builder import JvmFixingBuilder
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, BuildResult


class JvmCoverageEnhancer(Prototyper):
  """Helper agent for JVM-specific coverage improvement."""

  def __init__(self, llm, benchmark, analysis_result: AnalysisResult,
               build_result: BuildResult, args):
    super().__init__(llm, benchmark, args=args)
    self.benchmark = benchmark
    self.analysis = analysis_result
    self.build = build_result
    self.args = args

  def initial_prompt(self) -> Prompt:
    """Constructs initial JVM-focused prompt."""
    # Extract the fuzz target source code
    source_code = self.analysis.run_result.fuzz_target_source

    # Build the JVM fixing prompt
    builder = JvmFixingBuilder(model=self.llm,
                               benchmark=self.benchmark,
                               generated_harness=source_code,
                               errors=[])
    prompt = builder.build(example_pair=[])

    # Save to a dedicated JVM prompt file
    prompt_path = os.path.join(self.args.work_dirs.prompt, 'jvm_initial.txt')
    prompt.save(prompt_path)
    return prompt
