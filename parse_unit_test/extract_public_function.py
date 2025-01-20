import subprocess
import json
import os


def append_functions_to_json(target_lib, folder_path):
    # 确保输出目录存在
    output_dir = os.path.join(os.getcwd(), 'parse_unit_test', 'parse_unit_test_result', target_lib)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'target_function.json')

    # 读取现有的 JSON 数据，如果存在
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            data = json.load(f)
    else:
        data = {}

    # 遍历文件夹中的所有文件
    for filename in os.listdir(folder_path):
        librarypath = os.path.join(folder_path, filename)
        if os.path.isfile(librarypath):
            # 获取库文件名（去掉路径部分）
            library_name = os.path.basename(librarypath)

            # 使用 subprocess 执行 nm 命令，获取库文件中的所有符号
            result = subprocess.run(
                ['nm', '--demangle', '--defined-only', '-g', librarypath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                print(f"Error running nm on {librarypath}: {result.stderr}")
                continue  # 跳过当前文件，处理下一个

            # 提取所有 T 类型的符号（函数）
            functions = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == 'T':
                    functions.append(parts[-1])

            # 将函数添加到对应库的条目中
            if library_name in data:
                existing_functions = set(data[library_name])
                existing_functions.update(functions)
                data[library_name] = list(existing_functions)
            else:
                data[library_name] = functions

    # 将结果写回文件
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    target_lib = "libaom"  # 替换为你的目标库名称
    folder_path = "/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/aom/build/ceshi"  # 替换为包含二进制文件的文件夹路径
    append_functions_to_json(target_lib, folder_path)