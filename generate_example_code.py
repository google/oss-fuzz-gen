import argparse
import os.path
import json
from parse_unit_test import parse_unit_test, extract_public_function, extract_function_declare
from test_case_exec import exec_test_case, parse_exec_code
from query_llm_function_docs import documentation_engineer


def load_test_cases(target_lib_name: str) -> dict:
    # Construct the path to the test_case.json file
    test_case_file = os.path.join('parse_unit_test', 'parse_unit_test_result', target_lib_name, 'test_cases.json')

    # Check if the file exists
    if not os.path.exists(test_case_file):
        raise FileNotFoundError(f"The file {test_case_file} does not exist.")

    # Load and return the JSON content as a dictionary
    with open(test_case_file, 'r', encoding='utf-8') as file:
        return json.load(file)


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Parse paths for the main function')

    parser.add_argument('-t', '--target-lib-dir', type=str, required=True,
                        help='Path to the target library directory')

    parser.add_argument('-b', '--binary-name', type=str, required=True,
                        help='Name of the binary file')

    parser.add_argument('-n', '--target-lib-name', type=str, required=True,
                        help='Name of the target library')

    parser.add_argument('-f', '--binary-folder-path', type=str, required=True,
                        help='Path to the folder containing the binary files')

    parser.add_argument('-c', '--compile-cmd-dir', type=str, required=True,
                        help='Path to the directory containing compile commands')

    parser.add_argument('-u', '--unit-test-dir', type=str, required=True,
                        help='Path to the unit test directory')

    parser.add_argument('-e', '--executable-path', type=str, required=True,
                        help='Path to the executable file')
    parser.add_argument('-l', '--language', type=str, required=True, choices=['C', 'C++'],
                        help='Programming language (C or C++)')

    return parser.parse_args()


def run_pipeline(args):
    """执行业务逻辑"""
    try:
        # 构造 result_folder 路径
        result_folder = os.path.join('parse_unit_test', 'parse_unit_test_result', args.target_lib_name)

        # 判断是否需要解析单元测试
        test_case_file = os.path.join(result_folder, 'test_cases.json')
        if not os.path.exists(test_case_file):
            print(f"{test_case_file} does not exist. Running parse_unit_test.main...")
            print("")
            parse_unit_test.main(args.compile_cmd_dir, args.unit_test_dir, args.target_lib_name)

        # 判断是否需要追加函数到 JSON 文件
        target_function_file = os.path.join(result_folder, 'target_function.json')
        if not os.path.exists(target_function_file):
            print(f"{target_function_file} does not exist. Running extract_public_function.append_functions_to_json...")
            extract_public_function.append_functions_to_json(args.target_lib_name, args.binary_folder_path)

        # 判断是否需要处理函数声明
        api_declare_file = os.path.join(result_folder, 'api_declare.json')
        if not os.path.exists(api_declare_file):
            print(f"{api_declare_file} does not exist. Running extract_function_declare.main...")
            extract_function_declare.main(args.target_lib_dir, args.target_lib_name, args.binary_name)

        # 执行测试用例
        test_cases = load_test_cases(args.target_lib_name)
        for test_case in test_cases:
            testcase_list = test_case.get('testcase_list')
            for test_case_id in testcase_list:
                exec_test_case.execute_command_with_env(test_case_id, args.executable_path, args.target_lib_name)

        exec_test_case.convert_profraw_to_lcov(args.target_lib_name,args.executable_path)

        # Open the coverage directory and process all .lcov files
        coverage_dir = os.path.join("test_case_exec", "exec_code_result", args.target_lib_name, "coverage")

        if os.path.exists(coverage_dir):
            for file_name in os.listdir(coverage_dir):
                if file_name.endswith(".lcov"):
                    file_path = os.path.join(coverage_dir, file_name)
                    print(f"Processing file: {file_path}")
                    exec_test_case.extract_and_generate_files(file_path, args.target_lib_name, args.unit_test_dir,args.language)
        else:
            print(f"Coverage directory {coverage_dir} does not exist.")

        exec_code_dir = os.path.join("test_case_exec", "exec_code_result", args.target_lib_name, "exec_code")

        target_function_path = os.path.join("parse_unit_test", "parse_unit_test_result", args.target_lib_name, "target_function.json")
        with open(target_function_path, 'r', encoding='utf-8') as file:
            target_function_dict = json.load(file)
        target_function_list =target_function_dict.get(args.binary_name)

        target_declare_path = os.path.join("parse_unit_test", "parse_unit_test_result", args.target_lib_name, "api_declare.json")
        with open(target_declare_path, 'r', encoding='utf-8') as file:
            target_declare_dict = json.load(file)
        target_declare_list =target_declare_dict.get(args.binary_name)

        test_case_info_list = []
        for root, dirs, files in os.walk(exec_code_dir):
            for file in files:
                test_case_name = os.path.splitext(file)[0].replace('_','.')
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_content = f.read()  # 读取整个文件内容
                except Exception as e:
                    print(f"Error reading file {file}: {e}")

                cursor = parse_exec_code.parse_exec_code(args.language, file_path)
                target_function_call = parse_exec_code.travler_cursor(cursor, target_function_list)
                target_declare_call_list = set()
                for target_fucntion in target_function_call:
                    target_declare_call_list.add(target_declare_list.get(target_fucntion,target_fucntion))

                test_case_info = {
                    'test_case_name': test_case_name,
                    'target_function': list(target_function_call),
                    'function_declare': list(target_declare_call_list),
                    'test_case_code': file_content
                }
                test_case_info_list.append(test_case_info)

        # 构造保存文件的路径
        output_dir = os.path.join("test_case_exec", "exec_code_result", args.target_lib_name)
        output_file = os.path.join(output_dir, "test_case_info.json")

        # 确保目标文件夹存在
        os.makedirs(output_dir, exist_ok=True)

        # 将 test_case_info_list 写入 JSON 文件
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(test_case_info_list, f, ensure_ascii=False, indent=4)
            print(f"Test case information successfully written to {output_file}")
        except Exception as e:
            print(f"Error writing test case information to {output_file}: {e}")

        #生成文档
        documentation_engineer(args.target_lib_name)



    except Exception as e:
        print(f"An error occurred: {e}")



def main():
    """主函数"""

    args = parse_args()
    run_pipeline(args)


if __name__ == '__main__':
    main()