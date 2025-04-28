from .utils import load_compile_commands, process_compile_args, is_path_contained_in, extract_lines
from clang.cindex import Cursor
from clang import cindex  # 导入 Clang 的 Python 接口模块
from typing import List, Tuple, Optional
import os
from tqdm import tqdm
import re
import json
import logging


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()  # Log to the console
    ]
)

# 设置 Clang 库的路径
cindex.Config.set_library_file('/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/llvm/libclang.so.17.0.6')


def parse_source_file_and_get_cursor(cmd: cindex.CompileCommand) -> Tuple[cindex.Cursor, str, List[str]]:
    src_file = cmd.filename  # 获取源文件路径

    # 检查文件是否存在
    if not os.path.exists(src_file):
        logging.error(f"Source file {src_file} does not exist.")
        raise FileNotFoundError(f"Source file {src_file} does not exist.")

    # 处理编译参数
    compile_args = process_compile_args(cmd)
    # 创建索引对象
    index = cindex.Index.create()

    try:
        # 解析源文件，生成 TranslationUnit
        logging.info(f"Parsing source file: {src_file}")
        tu = index.parse(
            src_file,
            args=compile_args,
            options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
        logging.info(f"Successfully parsed source file: {src_file}")
    except cindex.TranslationUnitLoadError as e:
        logging.error(f"Failed to parse source file {src_file}: {e}")
        raise RuntimeError(f"Failed to parse source file {src_file}: {e}")
    finally:
        # 释放索引对象资源
        del index

    return tu.cursor, src_file, compile_args


def extract_include_path(compile_args: List[str]):
    include_path = []
    for arg in compile_args:
        if arg.startswith('-I') and "googletest" not in arg:
            include_path.append(arg[2:])
    return include_path


def extract_test_case(macro_definition_list: List[str]):
    pattern = r'^(TEST_P|TEST_F|TEST)\(([^)]+),\s*([^)]+)\)'
    test_case_list = []
    for macro_definition in macro_definition_list:
        match = re.match(pattern, macro_definition)
        if match:
            test_case_name = match.group(2).strip()
            test_name = match.group(3).strip()
            fully_qualified_test_name = f"{test_case_name}.{test_name}"
            test_case_list.append(fully_qualified_test_name)
    return test_case_list


def extract_macro_definition(macro_def_info_list: List[Tuple[str, int, int]]) -> List[str]:
    macro_definition_list = []
    for macro in macro_def_info_list:
        macro_definition = extract_lines(macro[0], macro[1], macro[2])
        macro_definition_list.append(macro_definition)
    return macro_definition_list


def get_macro_definition_info(cursor: Cursor, src_file: str) -> Optional[Tuple[str, int, int]]:
    test_macro_names = {"TEST_F", "TEST_P", "TEST"}
    if (cursor.kind == cindex.CursorKind.MACRO_INSTANTIATION and
            cursor.spelling in test_macro_names and
            cursor.location.file is not None and
            cursor.location.file.name == src_file):
        start_line = cursor.extent.start.line
        end_line = cursor.extent.end.line
        macro_definition = (src_file, start_line, end_line)
        return macro_definition


def traverse_cursor(cursor, macro_def_info_list, includes_paths, src_file, include_list):
    # Initialize included_file to None
    included_file = None

    # Handle macro definitions
    macro_def_info = get_macro_definition_info(cursor, src_file)
    if macro_def_info is not None:
        macro_def_info_list.append(macro_def_info)

    # Handle inclusion directives
    if cursor.kind == cindex.CursorKind.INCLUSION_DIRECTIVE:
        try:
            included_file = cursor.get_included_file().name
        except Exception as e:
            logging.error(f"Error getting included file for {cursor.spelling}: {e}")

        if included_file is not None:
            if any(os.path.commonpath([included_file, include_path]) == include_path for include_path in includes_paths) and "test" not in included_file:
                include_list.add(cursor.spelling)

    # If the cursor is a namespace, traverse its children
    if cursor.kind == cindex.CursorKind.NAMESPACE:
        for child in cursor.get_children():
            traverse_cursor(child, macro_def_info_list, includes_paths, src_file, include_list)


def main(compile_cmd_dir: str, unit_test_dir: str, target_lib_name: str):
    compile_cmd = load_compile_commands(compile_cmd_dir)
    test_case_list = []
    for cmd in tqdm(compile_cmd, desc="Parsing unit test code", unit="cmd"):
        root_cursor, src_file, compile_args = parse_source_file_and_get_cursor(cmd)
        includes_paths = extract_include_path(compile_args)

        # Skip if not a unit test file
        if not is_path_contained_in(unit_test_dir, src_file):
            logging.info(f"Skipping non-unit test file: {src_file}")
            continue

        macro_def_info_list = []
        include_list = set()

        # Traverse the cursor tree starting from root_cursor's children
        logging.info(f"Traversing cursor tree for file: {src_file}")
        for child in root_cursor.get_children():
            traverse_cursor(child, macro_def_info_list, includes_paths, src_file, include_list)

        macro_definition_list = extract_macro_definition(macro_def_info_list)
        test_case_in_single_file = extract_test_case(macro_definition_list)

        # Only add to test_case_list if test_case_in_single_file is not empty
        if test_case_in_single_file:
            test_case_info = {
                "src": src_file,
                "testcase_list": test_case_in_single_file,
                "include_list": list(include_list)
            }
            test_case_list.append(test_case_info)
            logging.info(f"Processed file: {src_file}")
        else:
            logging.info(f"No test cases found in file: {src_file}")

    # 获取当前脚本所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # 创建 parse_unit_test_result 文件夹
    base_folder = os.path.join('parse_unit_test', 'parse_unit_test_result')
    if not os.path.exists(base_folder):
        logging.info(f"Creating base folder: {base_folder}")
        os.makedirs(base_folder)

    # 创建 target_lib_name 文件夹在 parse_unit_test_result 下
    target_folder = os.path.join(base_folder, target_lib_name)
    if not os.path.exists(target_folder):
        logging.info(f"Creating target folder: {target_folder}")
        os.makedirs(target_folder)

    # 将 test_case_list 写入 JSON 文件
    output_file = os.path.join(target_folder, 'test_cases.json')
    logging.info(f"Writing test cases to JSON file: {output_file}")
    with open(output_file, 'w') as f:
        json.dump(test_case_list, f, indent=4)
    logging.info("Processing completed.")


if __name__ == '__main__':
    compile_cmd_dir = '/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/llmForFuzzDriver/DriverGnerationFromUT/targetLib/aom/build'
    unit_test_dir = '/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/llmForFuzzDriver/DriverGnerationFromUT/targetLib/aom/test'
    target_lib_name = "libaom"

    logging.info("Starting unit test parsing.")
    main(compile_cmd_dir, unit_test_dir, target_lib_name)
    logging.info("Unit test parsing completed.")