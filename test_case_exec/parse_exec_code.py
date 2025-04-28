from clang.cindex import Cursor
from clang import cindex
import logging
import os


def parse_exec_code(language: str, file_path: str) -> Cursor:
    # 设置编译参数

    language = language.lower()
    if language == 'c':
        compile_args = ['-x', 'c']
    elif language == 'c++':
        compile_args = ['-x', 'c++']
    else:
        logging.error(f"Unsupported language: {language}")
        raise ValueError(f"Unsupported language: {language}")

    # 检查文件是否存在
    if not os.path.exists(file_path):
        logging.error(f"Source file {file_path} does not exist.")
        raise FileNotFoundError(f"Source file {file_path} does not exist.")

    # 创建索引对象
    index = cindex.Index.create()

    try:
        # 解析源文件
        tu = index.parse(
            file_path,
            args=compile_args,
            options=cindex.TranslationUnit.PARSE_INCOMPLETE
        )
    except cindex.TranslationUnitLoadError as e:
        logging.error(f"Failed to parse source file {file_path}: {e}")
        raise RuntimeError(f"Failed to parse source file {file_path}: {e}")
    finally:
        del index  # 释放索引对象资源

    # 返回解析后的光标
    return tu.cursor

def travler_cursor(cursor: Cursor,target_function_list: set):
    target_function_call = set()
    for child in cursor.get_tokens():
        if child.kind == cindex.TokenKind.IDENTIFIER and child.spelling in target_function_list:
            target_function_call.add(child.spelling)
    return target_function_call

if __name__ == '__main__':
    file_path = "exec_code_result/libaom/exec_code/AomImageTest_AomImgAllocHugeWidth.cpp"
    cursor = parse_exec_code('c++', file_path)
    target_function_list = {'aom_img_alloc_with_border','aom_img_alloc','aom_img_free','aom_bit_depth_t'}
    a = travler_cursor(cursor,target_function_list)
    print(a)