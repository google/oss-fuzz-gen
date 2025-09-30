#!/usr/bin/env python3
"""Triaging the crash with LLM."""

import logging
import os

from experiment import benchmark as benchmarklib
from llm_toolkit import models
from llm_toolkit import output_parser as parser
from llm_toolkit import prompt_builder

class TriageResult:
  """Crash triage results."""
  NOT_APPLICABLE = '-'
  DRIVER = 'DRIVER'
  PROJECT = 'PROJECT'

# ========================= LLM Triage ========================= #
def llm_triage(
    ai_binary: str,
    driver_path: str,
    benchmark: benchmarklib.Benchmark,
    crash_info: str,
    crash_func: dict,
    triage_model_name: str,
) -> str:
  """Triages crash with LLM based on crash information and relevant code."""
  with open(driver_path) as target_file:
    driver_code = target_file.read()

  response_dir = f'{os.path.splitext(driver_path)[0]}-triage'
  os.makedirs(response_dir, exist_ok=True)
  prompt_path = os.path.join(response_dir, 'prompt.txt')

  apply_llm_triage(ai_binary,
                   benchmark,
                   driver_code,
                   crash_info,
                   crash_func,
                   prompt_path,
                   response_dir,
                   triage_model_name,
                   temperature=0.5)

  triage_candidates = []
  triage_result = TriageResult.NOT_APPLICABLE
  for file in os.listdir(response_dir):
    if not parser.is_raw_output(file):
      continue
    triage_path = os.path.join(response_dir, file)
    triage_result, triage = parser.parse_triage(triage_path)
    triage_candidates.append([triage_path, triage])

  if not triage_candidates:
    logging.warning('LLM did not generate rawoutput for %s', prompt_path)
    return TriageResult.NOT_APPLICABLE

  # TODO(maoyixie): Use the common vote
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
    driver_code: str,
    crash_info: str,
    crash_func: dict,
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
  prompt = builder.build_triager_prompt(benchmark, driver_code, crash_info,
                                        crash_func)
  prompt.save(prompt_path)

  triage_model.query_llm(prompt, response_dir)
