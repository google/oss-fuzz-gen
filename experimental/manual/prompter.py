"""Play with Gemini models manually
Usage:
  # Under venv.
  python -m experimental.manual.prompter -p <prompt_file> -l <model_name>
  # <prompt_file> is a plain text file.
  # <model_name> is `name` attribute of classes in llm_toolkit/models.py.
  # E.g.,
  python -m experimental.manual.prompter -p prompt.txt -l vertex_ai_gemini-1-5
"""

import argparse
import os

from llm_toolkit import models, prompts

NUM_SAMPLES: int = 1
TEMPERATURE: float = 1
MAX_TOKENS: int = 8192


def parse_args() -> argparse.Namespace:
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(
      description='Run all experiments that evaluates all target functions.')
  parser.add_argument('-n',
                      '--num-samples',
                      type=int,
                      default=NUM_SAMPLES,
                      help='The number of samples to request from LLM.')
  parser.add_argument(
      '-t',
      '--temperature',
      type=float,
      default=TEMPERATURE,
      help=('A value presenting the variety of the targets generated by LLM. '
            'It should be within [0,2] for Gemini-1.5 models and [0,1] for '
            'Gemini-1.0 models'))
  parser.add_argument('-l',
                      '--model',
                      default=models.DefaultModel.name,
                      help=('Models available: '
                            f'{", ".join(models.LLM.all_llm_names())}'))
  parser.add_argument('-p',
                      '--prompt',
                      help='Prompt file for LLM.',
                      required=True)
  parser.add_argument('-r',
                      '--response-dir',
                      default='./responses',
                      help='LLM response directory.')
  return parser.parse_args()


def setup_model() -> models.LLM:
  return models.LLM.setup(
      ai_binary='',
      name=args.model,
      max_tokens=MAX_TOKENS,
      num_samples=args.num_samples,
      temperature=args.temperature,
  )


def construct_prompt() -> prompts.Prompt:
  with open(args.prompt, 'r') as prompt_file:
    content = prompt_file.read()
  return model.prompt_type()(initial=content)


if __name__ == "__main__":
  args = parse_args()
  model = setup_model()
  prompt = construct_prompt()
  os.makedirs(args.response_dir, exist_ok=True)
  model.query_llm(prompt, response_dir=args.response_dir)
