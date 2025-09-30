#!/usr/bin/env python3
"""Corpus generator using LLMs."""

import os

from data_prep import introspector
from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from llm_toolkit import models
from llm_toolkit import output_parser as parser
from llm_toolkit import prompt_builder

def get_script(
    ai_binary: str,
    fixer_model_name: str,
    target_harness_path: str,
    benchmark: Benchmark,
) -> str:
  """Uses LLMs to generate a python script that will create a seed corpus for a
  harness.

  The script generated is purely generated and should be considered untrusted
  in the general sense. OSS-Fuzz-gen already executes arbitrary code since
  OSS-Fuzz-gen executes arbitrary open source projects with no checking on
  what code is committed to the given projects."""
  corpus_model = models.LLM.setup(
      ai_binary=ai_binary,
      name=fixer_model_name,
  )

  # Get the corpus generation template
  with open(
      os.path.join(prompt_builder.DEFAULT_TEMPLATE_DIR,
                   'corpus_generation_via_python_script.txt'), 'r') as f:
    prompt_to_query = f.read()
  with open(target_harness_path) as target_harness_file:
    target_harness_code = target_harness_file.read()

  prompt_to_query = prompt_to_query.replace('{HARNESS_SOURCE_CODE}',
                                            target_harness_code)

  project_repository = oss_fuzz_checkout.get_project_repository(
      benchmark.project)
  target_source_code = introspector.query_introspector_function_source(
      benchmark.project, benchmark.function_signature)

  prompt_to_query = prompt_to_query.replace('{PROJECT_NAME}', benchmark.project)
  prompt_to_query = prompt_to_query.replace('{PROJECT_REPOSITORY}',
                                            project_repository)
  prompt_to_query = prompt_to_query.replace('{TARGET_FUNCTION_SOURCE}',
                                            target_source_code)

  prompt = corpus_model.prompt_type()()
  prompt.add_priming(prompt_to_query)

  response_dir = f'{os.path.splitext(target_harness_path)[0]}-corpus'
  os.makedirs(response_dir, exist_ok=True)
  prompt_path = os.path.join(response_dir, 'prompt.txt')
  prompt.save(prompt_path)

  corpus_model.query_llm(prompt, response_dir)
  for file in os.listdir(response_dir):
    if not parser.is_raw_output(file):
      continue
    corpus_generator_path = os.path.join(response_dir, file)
    with open(corpus_generator_path, 'r') as f:
      corpus_generator_source = f.read()

    corpus_generator_source = corpus_generator_source.replace('</results>', '')
    corpus_generator_source = corpus_generator_source.replace('<results>', '')
    corpus_generator_source = corpus_generator_source.replace('```python', '')
    corpus_generator_source = corpus_generator_source.replace('```', '')
    return corpus_generator_source

  # Return an empty Python program if generation failed.
  return 'import os'
