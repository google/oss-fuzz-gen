"Use Agent to chat with LLM and fix build errors."
import os
import re
import subprocess
import sys

import vertexai
import yaml
from vertexai import generative_models
from vertexai.generative_models import GenerativeModel

PROJECT = sys.argv[1]
FUNCTION_UNDER_TEST = sys.argv[2]

IMAGE_NAME = f'gcr.io/oss-fuzz/{PROJECT}'
with open(f'benchmark-sets/all/{PROJECT}.yaml', 'r') as benchmark_file:
  data = yaml.safe_load(benchmark_file)
  FUZZ_TARGET_PATH = data['target_path'].strip()
  FUZZ_TARGET_BINARY = data['target_name'].strip()

# with open(sys.argv[2]) as fuzz_target_file:
#   CODE_TO_BE_FIXED = fuzz_target_file.read()

# with open(sys.argv[3]) as error_message_file:
#   ERROR_MESSAGES = error_message_file.read()

# if len(sys.argv) > 4:
#   with open(sys.argv[4]) as example_file:
#     EXAMPLE_TARGET = example_file.read()

project_id = 'oss-fuzz'
vertexai.init(project=project_id, location="us-central1")
model = GenerativeModel("gemini-1.5-pro-001")

SAFETY_CONFIG = [
    generative_models.SafetySetting(
        category=generative_models.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
    generative_models.SafetySetting(
        category=generative_models.HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
    generative_models.SafetySetting(
        category=generative_models.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
    generative_models.SafetySetting(
        category=generative_models.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold=generative_models.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
]


def _start_docker_container() -> str:
  result = subprocess.run(
      ['docker', 'run', '-d', '-t', '--entrypoint=/bin/bash', IMAGE_NAME],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
      check=True)
  container_id = result.stdout.strip()
  return container_id


def _construct_prompt(content: str = '') -> str:
  with open('prompts/agent/gen-initial.txt', 'r') as prompt_file:
    content = prompt_file.read()
    content = content.replace('{FUZZ_TARGET_PATH}', FUZZ_TARGET_PATH)
    content = content.replace('{PROJECT}', PROJECT)
    content = content.replace('{FUNCTION_UNDER_TEST}', FUNCTION_UNDER_TEST)
    return content


def _parse_tag(response: str, tag: str) -> str:
  match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
  return match.group(1).strip() if match else ''


def execute_bash_command(container_id: str, command: str) -> str:
  result = subprocess.run(
      ['docker', 'exec', container_id, '/bin/bash', '-c', command],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      check=False,
      text=True)
  print('ERR', result.stderr)
  print('OUT', result.stdout)
  print('RET', result.returncode)
  print('FIN', result.stderr if result.returncode else result.stdout)
  # return result.stdout if result.returncode == 0 else result.stderr
  return result.stderr if result.stderr else result.stdout


def main() -> None:
  chat = model.start_chat()

  # Start the Docker container
  container_id = _start_docker_container()
  print(f"Started Docker container: {container_id}")
  # fuzz_target_basename, ext = os.path.splitext(FUZZ_TARGET_PATH)
  # example = f'{fuzz_target_basename}_example{ext}'
  # execute_bash_command(container_id, f'mv "{FUZZ_TARGET_PATH}" "{example}"')

  # replace_target = f'echo "{CODE_TO_BE_FIXED}" > "{FUZZ_TARGET_PATH}"'
  # execute_bash_command(container_id, replace_target)
  execute_bash_command(
      container_id,
      'compile > /src/compile_output && rm -rf /out/* > /dev/null')
  output = ''
  response = ''
  cur_round = 0
  prompt = _construct_prompt(output)

  try:
    while cur_round < 100:
      cur_round += 1
      print(f"ROUND {cur_round} Prompt:\n{prompt}")
      response = chat.send_message(
          prompt or ' ', stream=False,
          safety_settings=SAFETY_CONFIG).text  # type: ignore

      print(f"ROUND {cur_round} LLM response:\n{response}")
      if _parse_tag(response, 'conclusion'):
        print('------------- Received conclusion ----------------')
        fuzz_target = _parse_tag(response, 'fuzz target')
        replace_target = f'printf \'%s\n\' "{fuzz_target}" > "{FUZZ_TARGET_PATH}"'
        replace_target = f"""cat << 'EOF' > {FUZZ_TARGET_PATH}
{fuzz_target}
EOF
"""
        execute_bash_command(container_id, replace_target)
        command = _parse_tag(response, 'bash')
        if command:
          output = execute_bash_command(container_id, command)
          print(f"Agent output:\n{output}")

        print("================= Recompile ===========================")
        prompt = execute_bash_command(container_id, 'compile > /dev/null')
        print(f"Recompile output:\n{prompt}")
        result_output = execute_bash_command(
            container_id, f'ls -l /out/{FUZZ_TARGET_BINARY}')
        print(f"Resutl output:\n{result_output}")

        if 'not found' in result_output or 'No such file or directory' in result_output:
          print(f"***** Failed in {cur_round} rounds *****\n")
          continue
        print(f"***** Succeeded in {cur_round} rounds *****\n")
        break
      command = _parse_tag(response, 'bash')

      # Execute the command in the container
      prompt = execute_bash_command(container_id, command)
      print(f"ROUND {cur_round} Agent output:\n{prompt}")

  finally:
    # Cleanup: stop and remove the container
    print("Stopping and removing the container...")
    subprocess.run(['docker', 'stop', container_id], check=True)
    # subprocess.run(['docker', 'rm', container_id], check=True)


if __name__ == "__main__":
  main()
