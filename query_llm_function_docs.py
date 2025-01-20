from langchain_community.chat_models import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage
from tqdm import tqdm
import os,json
import warnings
import logging
warnings.filterwarnings("ignore", category=DeprecationWarning)
# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def documentation_engineer_prompt(target_lib_name):
    prompt_list = []
    test_cases_info_path = os.path.join('test_case_exec', 'exec_code_result', target_lib_name, 'test_case_info.json')
    system_prompt_path = os.path.join('prompts', 'template_xml', 'system_prompt.txt')
    template_path = os.path.join('prompts', 'template_xml', 'exec_code_doc.txt')

    with open(system_prompt_path, 'r', encoding='utf-8') as file:
        system_prompt = file.read()

    with open(template_path, 'r', encoding='utf-8') as file:
        instruction_template = file.read()

    with open(test_cases_info_path, 'r', encoding='utf-8') as file:
        test_case_dict = json.load(file)

    for test_case in test_case_dict:
        target_function = test_case.get('target_function')
        function_declare = test_case.get('function_declare')
        test_case_code = test_case.get('test_case_code')
        test_case_name = test_case.get('test_case_name')

        system_prompt_formatted = system_prompt.replace("{target_lib_name}", target_lib_name)
        instruction_formatted = instruction_template.replace("{function_declare_under_test}",
                                                             '\n'.join(function_declare))
        instruction_formatted = instruction_formatted.replace("{function_under_test}", '\n'.join(target_function))
        instruction_formatted = instruction_formatted.replace("{unit_test_code_fragments}", test_case_code)

        system_message = SystemMessage(content=system_prompt_formatted)
        human_message = HumanMessage(content=instruction_formatted)
        messages = [system_message, human_message]
        prompt_list.append((messages,test_case_name))
    return prompt_list


def documentation_engineer(target_lib_name):
    """
    生成函数文档并追加到 doc.json，确保在异常情况下程序能继续运行，并打印日志信息
    """
    prompt_list = documentation_engineer_prompt(target_lib_name)

    try:
        model = ChatOpenAI(
            model_name="gpt-4o-mini",
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            openai_api_base=os.getenv("OPENAI_API_BASE")
        )
        logging.info("Model connected successfully")
    except Exception as e:
        logging.error(f"Model connection failed: {e}")
        return

    doc_path = os.path.join("test_case_exec", "exec_code_result", target_lib_name, "doc.json")

    # 确保目标文件夹存在
    os.makedirs(os.path.dirname(doc_path), exist_ok=True)

    # 如果文件不存在，则创建一个空的 JSON 列表文件
    if not os.path.exists(doc_path):
        with open(doc_path, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)

    # 读取现有 JSON 数据
    try:
        with open(doc_path, "r", encoding="utf-8") as f:
            existing_data = json.load(f)
            if not isinstance(existing_data, list):
                logging.warning(f"File {doc_path} is not a list, resetting to an empty list")
                existing_data = []
    except json.JSONDecodeError:
        logging.warning(f"JSON decode error in {doc_path}, resetting file")
        existing_data = []

    # 生成并追加新的文档信息
    for prompt in tqdm(prompt_list, desc="Generating Function Documentation"):
        testcase_name = prompt[1]

        try:
            response = model(prompt[0])
            doc = response.content
            doc_info = {
                "test_case_name": testcase_name,
                "doc": doc
            }

            # 追加新数据
            existing_data.append(doc_info)

            # 每次追加完后，将数据写回文件
            with open(doc_path, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, ensure_ascii=False, indent=2)

            logging.info(f"Successfully added documentation for test case: {testcase_name}")

        except Exception as e:
            logging.error(f"Failed to process test case {testcase_name}: {e}")
            continue

    logging.info(f"Documentation saved successfully at {doc_path}")

if __name__ == '__main__':
    documentation_engineer('libaom')




