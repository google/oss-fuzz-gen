import os
import json
from clang import cindex
from utils import extract_lines
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def parse_source_file_and_get_cursor(src_file: str) -> cindex.Cursor:
    if not os.path.exists(src_file):
        raise FileNotFoundError(f"Source file {src_file} does not exist.")

    header_extension = os.path.splitext(src_file)[1]
    if header_extension in ['.h', '.hpp']:
        compile_args = ['-x', 'c', '-std=c99']
    else:
        compile_args = ['-x', 'c++', '-std=c++11']

    index = cindex.Index.create()
    try:
        tu = index.parse(src_file, args=compile_args, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    except cindex.TranslationUnitLoadError as e:
        raise RuntimeError(f"Failed to parse source file {src_file}: {e}")
    finally:
        del index
    return tu.cursor


def load_target_functions(target_lib: str, binary_name: str) -> set:
    json_path = os.path.join('parse_unit_test_result', target_lib, 'target_function.json')
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"JSON file {json_path} does not exist.")
    with open(json_path, 'r') as f:
        data = json.load(f)
    if binary_name not in data:
        return set()
    return set(data[binary_name])


def get_function_signature(cursor: cindex.Cursor) -> str:
    file_path_decl = cursor.location.file.name
    start_line = cursor.extent.start.line
    end_line = cursor.extent.end.line

    raw_comment = cursor.raw_comment
    decl = extract_lines(file_path_decl, start_line, end_line)

    if raw_comment:
        function_declaration = raw_comment + "\n" + decl
    else:
        function_declaration = decl
    return function_declaration


def save_api_declare_to_json(api_declare: dict, output_file: str) -> None:
    with open(output_file, 'w', encoding='utf-8') as file:
        json.dump(api_declare, file, indent=4)


def main(target_lib_dir: str, target_lib: str, binary_name: str) -> None:
    logging.info("Generating API declarations from header files based on target functions.")
    target_functions = load_target_functions(target_lib, binary_name)

    api_declare = {}
    function_kind = [cindex.CursorKind.FUNCTION_DECL, cindex.CursorKind.CXX_METHOD, cindex.CursorKind.FUNCTION_TEMPLATE]

    for root, dirs, files in os.walk(target_lib_dir):
        for file in files:
            if file.endswith((".h", ".hpp")):
                file_path = os.path.join(root, file)
                cursor = parse_source_file_and_get_cursor(file_path)
                for child in cursor.walk_preorder():
                    if child.kind in function_kind and os.path.basename(
                            child.location.file.name) == file and child.linkage == cindex.LinkageKind.EXTERNAL:
                        if child.spelling in target_functions:
                            function_declaration = get_function_signature(child)
                            if binary_name not in api_declare:
                                api_declare[binary_name] = {}
                            api_declare[binary_name][child.spelling] = function_declaration
    output_dir = os.path.join('parse_unit_test_result', target_lib)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'api_declare.json')
    save_api_declare_to_json(api_declare, output_file)


if __name__ == '__main__':
    target_lib_dir = '/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/aom/header'
    target_lib = 'libaom'
    binary_name = 'libaom.a'
    main(target_lib_dir, target_lib, binary_name)