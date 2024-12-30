import json
import os
from clang.cindex import CompilationDatabase
from clang import cindex

def generate_unique_cursor_id(referenced: cindex.Cursor)->str:
    if referenced and referenced.location and referenced.location.file:
        referenced_file = referenced.location.file.name
        referenced_line = referenced.location.line
        return f'{referenced_file} [line: {referenced_line}]'


def find_corresponding_source(header_path: str) -> str:

    # 获取头文件所在目录和文件名
    directory, header_file = os.path.split(header_path)
    # 获取文件名（不含扩展名）
    base_name = os.path.splitext(header_file)[0]
    # 定义可能的源文件扩展名
    source_extensions = ['.c', '.cpp', '.cc', '.cxx']
    # 遍历目录中的文件
    for file in os.listdir(directory):
        # 获取文件的完整路径
        file_path = os.path.join(directory, file)
        # 检查是否为文件且扩展名在可能的源文件扩展名列表中
        if os.path.isfile(file_path) and os.path.splitext(file)[1] in source_extensions:
            # 获取文件名（不含扩展名）
            file_base_name = os.path.splitext(file)[0]
            # 如果文件名与头文件名匹配，则返回该文件路径
            if file_base_name == base_name:
                return file_path
    # 如果未找到匹配的源文件，返回空字符串
    return ''


def extract_lines(filename: str, start_line: int, end_line: int) -> str:
    # 检查 start_line 和 end_line 是否为整数且大于 0
    if not isinstance(start_line, int) or not isinstance(end_line, int):
        raise TypeError("start_line 和 end_line 必须是整数")
    if start_line <= 0 or end_line <= 0:
        raise ValueError("start_line 和 end_line 必须大于 0")
    if start_line > end_line:
        raise ValueError("start_line 不能大于 end_line")

    with open(filename, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        # 确保 end_line 不超过文件总行数
        end_line = min(end_line, len(lines))
        selected_lines = lines[start_line - 1:end_line]
        return ''.join(selected_lines)



def parse_test_case_source(file_path:str)-> dict:
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data


# 加载 compile_commands.json
def load_compile_commands(path):
    comp_db = CompilationDatabase.fromDirectory(path)
    all_compile_commands = comp_db.getAllCompileCommands()
    return all_compile_commands


# 加载公共 API
def load_public_api(path):
    # 自动添加文件名 public_api.json
    compile_commands_path = os.path.join(path, 'api_list.json')
    with open(compile_commands_path, 'r') as file:
        return json.load(file)


def is_path_contained_in(base_path, check_path):
    """
    判断 check_path 是否位于 base_path 或其子目录中。

    :param base_path: 基准路径（目录）
    :param check_path: 要检查的路径（文件或目录）
    :return: True 如果 check_path 位于 base_path 或其子目录中，否则 False
    """
    # 转换为绝对路径，确保路径判断的可靠性
    abs_base_path = os.path.abspath(base_path)
    abs_check_path = os.path.abspath(check_path)

    # 确保 base_path 是一个目录
    if not os.path.isdir(abs_base_path):
        raise ValueError(f"The base_path '{base_path}' is not a valid directory.")

    # 检查 check_path 是否以 base_path 为前缀，表明在目录内
    return abs_check_path.startswith(abs_base_path + os.sep)


def is_path_contained_in_any(base_paths, check_path):
    """
    判断 check_path 是否位于 base_paths 列表中任意一个路径或其子目录中。

    :param base_paths: 基准路径列表（每个元素是一个目录路径）
    :param check_path: 要检查的路径（文件或目录）
    :return: True 如果 check_path 位于 base_paths 中的任意路径或其子目录中，否则 False
    """
    # 转换为绝对路径，确保路径判断的可靠性
    abs_check_path = os.path.abspath(check_path)

    # 检查每个 base_path 是否有效
    for base_path in base_paths:
        # 转换为绝对路径
        abs_base_path = os.path.abspath(base_path)

        # 确保 base_path 是一个目录
        if not os.path.isdir(abs_base_path):
            raise ValueError(f"The base_path '{base_path}' is not a valid directory.")

        # 如果 check_path 以 base_path 为前缀，表示位于该目录内
        if abs_check_path.startswith(abs_base_path + os.sep):
            return True

    # 如果遍历所有 base_paths 后没有找到符合条件的路径，返回 False
    return False


def process_compile_args(cmd):
    """
    处理编译参数列表，移除与解析无关的选项，并将优化级别设置为 -O0。

    参数：
        cmd (clang.cindex.CompileCommand): 包含编译参数的编译命令。

    返回：
        list: 处理后的编译参数列表。
    """
    # 移除第一个参数（通常是编译器名称）
    compile_args = list(cmd.arguments)[1:]

    # 移除 '-c' 参数
    compile_args = [arg for i, arg in enumerate(compile_args)
                    if arg != '-c' and (i == 0 or compile_args[i - 1] != '-c')]

    # 移除 '-o' 及其后续参数
    cleaned_args = []
    skip_next = False
    for arg in compile_args:
        if skip_next:
            skip_next = False
            continue
        if arg == '-o':
            skip_next = True  # 跳过 '-o' 的下一个参数
        else:
            cleaned_args.append(arg)

    # 查找并移除现有的优化参数（如 '-O1', '-O2', '-O3', '-Os', '-Ofast'）
    optimization_flags = ['-O0', '-O1', '-O2', '-O3', '-Os', '-Ofast']
    cleaned_args = [arg for arg in cleaned_args if arg not in optimization_flags]

    # 添加 '-O0' 参数以禁用优化
    cleaned_args.append('-O0')

    return cleaned_args



def write_dict_to_json_in_dir(data_dict: dict, target_dir: str, file_name:str):
    """
    将字典内容追加到指定目录的 JSON 文件，文件名为硬编码的 method_definitions.json。
    如果文件不存在，则创建文件并写入。
    """

    # 确保目标目录存在
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # 组合目标文件路径
    file_path = os.path.join(target_dir, file_name)

    # 如果文件存在，先读取旧内容并合并
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as json_file:
            try:
                existing_data = json.load(json_file)
            except json.JSONDecodeError:
                existing_data = {}
        # 合并字典（旧内容和新内容）
        if isinstance(existing_data, dict):
            data_dict = {**existing_data, **data_dict}
        else:
            raise ValueError("Existing data is not a dictionary!")

    # 写入合并后的数据
    with open(file_path, 'w', encoding='utf-8') as json_file:
        json.dump(data_dict, json_file, indent=4, ensure_ascii=False)