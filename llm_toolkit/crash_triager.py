#!/usr/bin/env python3
# Copyright 2024 Google LLC
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
"""Triaging the crash with LLM."""

import os
import logging
from enum import Enum

from experiment import benchmark as benchmarklib
from llm_toolkit import models
from llm_toolkit import output_parser as parser
from llm_toolkit import prompt_builder


class TriageResult(Enum):
  """Crash triage results."""
  NOT_APPLICABLE = '-'
  DRIVER = 'DRIVER'
  PROJECT = 'PROJECT'


# ========================= LLM Triage ========================= #
def llm_triage(
    ai_binary: str,
    target_path: str,
    benchmark: benchmarklib.Benchmark,
    crash_info: str,
    triage_model_name: str,
) -> TriageResult:
  """Triages crash with LLM based on crash information and relevant code."""
  with open(target_path) as target_file:
    target_code = target_file.read()

  response_dir = f'{os.path.splitext(target_path)[0]}-triage'
  os.makedirs(response_dir, exist_ok=True)
  prompt_path = os.path.join(response_dir, 'prompt.txt')

  apply_llm_triage(ai_binary,
                   benchmark,
                   target_code,
                   crash_info,
                   prompt_path,
                   response_dir,
                   triage_model_name,
                   temperature=0.5)

  triage_candidates = []
  for file in os.listdir(response_dir):
    if not parser.is_raw_output(file):
      continue
    triage_path = os.path.join(response_dir, file)
    triage_result, triage = parser.parse_triage(triage_path)
    triage_candidates.append([triage_path, triage])

  if not triage_candidates:
    logging.warning('LLM did not generate rawoutput for %s', prompt_path)
    return TriageResult.NOT_APPLICABLE

  # TODO(fdt622): Use the common vote
  # Currently, we prefer the longest triage.
  preferred_triage_path, preferred_triage = max(triage_candidates,
                                                key=lambda x: len(x[1]))
  logging.info('Will use the longest triage: %s',
               os.path.relpath(preferred_triage_path))
  preferred_triage_name, _ = os.path.splitext(preferred_triage_path)
  triage_report_path = os.path.join(response_dir,
                                    f'{preferred_triage_name}.txt')
  parser.save_output(preferred_triage, triage_report_path)
  return triage_result


def apply_llm_triage(
    ai_binary: str,
    benchmark: benchmarklib.Benchmark,
    target_code: str,
    crash_info: str,
    prompt_path: str,
    response_dir: str,
    triage_model_name: str = models.DefaultModel.name,
    temperature: float = 0.4,
):
  """Queries LLM to triage the crash."""
  triage_model = models.LLM.setup(
      ai_binary=ai_binary,
      name=triage_model_name,
      num_samples=1,
      temperature=temperature,
  )

  builder = prompt_builder.DefaultTemplateBuilder(triage_model)
  prompt = builder.build_triage_prompt(benchmark, target_code, crash_info)
  prompt.save(prompt_path)

  triage_model.generate_code(prompt, response_dir)
