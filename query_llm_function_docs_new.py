import json
import logging
import os
from typing import List

from tqdm import tqdm

from experiment import benchmark as benchmarklib
from llm_toolkit import models, prompt_builder, prompts

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
current_dir = os.path.dirname(os.path.abspath(__file__))
os.environ['OPENAI_API_BASE'] = 'https://api.gptsapi.net/v1'
os.environ['OPENAI_API_KEY'] = 'sk-iQ8c12405cdc22bcf88e7451cf5013a309dbcbdd95eOgZG9'

class DocumentationPromptBuilder(prompt_builder.PromptBuilder):
    def __init__(self, model: models.LLM, target_lib_name: str):
        super().__init__(model)
        self.target_lib_name = target_lib_name

    def build(self, test_case: dict) -> prompts.Prompt:
        system_prompt_path = os.path.join(current_dir, 'prompts', 'template_xml', 'system_prompt.txt')
        template_path = os.path.join(current_dir, 'prompts', 'template_xml', 'exec_code_doc.txt')

        with open(system_prompt_path, 'r', encoding='utf-8') as file:
            system_prompt = file.read()

        with open(template_path, 'r', encoding='utf-8') as file:
            instruction_template = file.read()

        target_function = test_case.get('target_function')
        function_declare = test_case.get('function_declare')
        test_case_code = test_case.get('test_case_code')

        system_prompt_formatted = system_prompt.replace("{target_lib_name}", self.target_lib_name)
        instruction_formatted = instruction_template.replace("{function_declare_under_test}",
                                                             '\n'.join(function_declare))
        instruction_formatted = instruction_formatted.replace("{function_under_test}", '\n'.join(target_function))
        instruction_formatted = instruction_formatted.replace("{unit_test_code_fragments}", test_case_code)

        prompt = self._model.prompt_type()()
        prompt.add_priming(system_prompt_formatted)
        prompt.add_problem(instruction_formatted)

        return prompt


def documentation_engineer(model: models.LLM, target_lib_name: str, test_case_dict: List[dict], output_dir: str):
    """
    Generate function documentation and save to individual files.
    """
    prompt_builder = DocumentationPromptBuilder(model, target_lib_name)

    for test_case in tqdm(test_case_dict, desc="Generating Function Documentation"):
        test_case_name = test_case.get('test_case_name')
        try:
            prompt = prompt_builder.build(test_case)
            model.query_llm(prompt, output_dir)
            
            # Read the saved file (assuming first sample)
            response_file = os.path.join(output_dir, "01.rawoutput")
            with open(response_file, "r", encoding="utf-8") as f:
                doc = f.read()
            output_path = os.path.join(output_dir, f"{test_case_name}_doc.txt")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(doc)

            logging.info(f"Successfully generated documentation for test case: {test_case_name}")

        except Exception as e:
            logging.error(f"Failed to process test case {test_case_name}: {e}")
            continue


if __name__ == '__main__':
    target_lib_name = 'libaom'
    test_cases_info_path = os.path.join(current_dir, 'test_case_exec', 'exec_code_result', target_lib_name, 'test_case_info.json')
    output_dir = os.path.join(current_dir, 'test_case_exec', 'exec_code_result', target_lib_name, 'docs')

    os.makedirs(output_dir, exist_ok=True)

    with open(test_cases_info_path, 'r', encoding='utf-8') as file:
        test_case_dict = json.load(file)

    model = models.LLM.setup(
    ai_binary=None,
    name="gpt-4o-mini"
    )

    documentation_engineer(model, target_lib_name, test_case_dict, output_dir)