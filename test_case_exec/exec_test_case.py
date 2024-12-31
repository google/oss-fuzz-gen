import subprocess
import os
import xml.etree.ElementTree as ET
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("execution.log"),  # Log to a file
        logging.StreamHandler()  # Log to the console
    ]
)

def execute_command_with_env(test_case_id, command, target_lib):
    env_var_name = "LLVM_PROFILE_FILE"
    test_case_id_file = test_case_id.replace(".", "_")

    profraw_output_path = os.path.join("result", target_lib, "profraw", f"{test_case_id_file}.profraw")
    xml_output_path = os.path.join("result", target_lib, "xml", f"{test_case_id_file}.xml")

    os.makedirs(os.path.dirname(profraw_output_path), exist_ok=True)
    os.makedirs(os.path.dirname(xml_output_path), exist_ok=True)

    env = os.environ.copy()
    env[env_var_name] = profraw_output_path

    if not os.path.isfile(command):
        logging.error(f"Command not found: {command}")
        return None

    args = [f'--gtest_filter={test_case_id}']
    full_command = [command] + args + [f'--gtest_output=xml:{xml_output_path}']
    logging.info(f"Running command: {' '.join(full_command)}")

    try:
        result = subprocess.run(full_command, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.debug("Command executed successfully.")
        if os.path.exists(xml_output_path):
            try:
                tree = ET.parse(xml_output_path)
                root = tree.getroot()
                tests_run = int(root.attrib.get('tests', '0'))
                if tests_run == 0:
                    logging.debug("No tests were run with the given filter.")
                    if os.path.exists(profraw_output_path):
                        try:
                            os.remove(profraw_output_path)
                            logging.debug(f"Deleted {profraw_output_path} since no tests were run.")
                        except OSError as e:
                            logging.error(f"Error deleting {profraw_output_path}: {e}")
            except ET.ParseError:
                logging.error("Failed to parse XML output.")
        else:
            logging.error("XML output file not found.")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}")
        logging.error(f"Stdout: {e.stdout.decode()}")
        logging.error(f"Stderr: {e.stderr.decode()}")
        return e


def convert_profraw_to_txt(target_lib, command_path):
    profraw_dir = os.path.join("result", target_lib, "profraw")
    coverage_dir = os.path.join("result", target_lib, "coverage")

    os.makedirs(coverage_dir, exist_ok=True)

    if not os.path.exists(profraw_dir):
        logging.error(f"Profraw directory not found: {profraw_dir}")
        return

    for profraw_file in os.listdir(profraw_dir):
        if profraw_file.endswith(".profraw"):
            profraw_path = os.path.join(profraw_dir, profraw_file)
            profdata_path = os.path.join(coverage_dir, profraw_file.replace(".profraw", ".profdata"))
            txt_path = os.path.join(coverage_dir, profraw_file.replace(".profraw", ".txt"))

            try:
                subprocess.run(
                    ["llvm-profdata", "merge", "-sparse", profraw_path, "-o", profdata_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                logging.debug(f"Converted {profraw_file} to {profdata_path}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to convert {profraw_file} to .profdata: {e}")
                continue

            try:
                with open(txt_path, "w") as txt_file:
                    subprocess.run(
                        ["llvm-cov", "show", command_path, "-instr-profile", profdata_path],
                        check=True,
                        stdout=txt_file,
                        stderr=subprocess.PIPE,
                    )
                logging.info(f"Generated coverage report: {txt_path}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to generate coverage report for {profraw_file}: {e}")
                continue

            try:
                os.remove(profdata_path)
                logging.debug(f"Deleted intermediate file: {profdata_path}")
            except OSError as e:
                logging.error(f"Failed to delete {profdata_path}: {e}")


def extract_high_frequency_lines(file_path, output_path=None):
    """
    从指定文件中提取执行次数大于1的代码行，并保存到另一个文件中。

    参数:
    file_path (str): 输入文件的路径。
    output_path (str, 可选): 输出文件的路径。如果不指定，则不保存文件。

    返回:
    list: 包含执行次数大于1的代码行的列表。
    """
    high_frequency_lines = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split('|')
                if len(parts) < 3:
                    continue  # 跳过格式不正确的行
                exec_count_str = parts[1].strip()
                if not exec_count_str:
                    exec_count = 0
                else:
                    try:
                        exec_count = int(exec_count_str)
                    except ValueError:
                        continue  # 执行次数不是有效整数，跳过
                if exec_count > 0:
                    code_line = parts[2].strip() + '\n'
                    high_frequency_lines.append(code_line)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as output_file:
                output_file.writelines(high_frequency_lines)
    except FileNotFoundError:
        print(f"文件 {file_path} 未找到。")
    except IOError as e:
        print(f"读写错误: {e}")
    except Exception as e:
        print(f"意外错误: {e}")
    return high_frequency_lines


def convert_profraw_to_lcov(target_lib, command_path):
    profraw_dir = os.path.join("result", target_lib, "profraw")
    coverage_dir = os.path.join("result", target_lib, "coverage")

    os.makedirs(coverage_dir, exist_ok=True)

    if not os.path.exists(profraw_dir):
        logging.error(f"Profraw directory not found: {profraw_dir}")
        return

    for profraw_file in os.listdir(profraw_dir):
        if profraw_file.endswith(".profraw"):
            profraw_path = os.path.join(profraw_dir, profraw_file)
            profdata_path = os.path.join(coverage_dir, profraw_file.replace(".profraw", ".profdata"))
            lcov_path = os.path.join(coverage_dir, profraw_file.replace(".profraw", ".lcov"))

            try:
                subprocess.run(
                    ["llvm-profdata", "merge", "-sparse", profraw_path, "-o", profdata_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                logging.debug(f"Converted {profraw_file} to {profdata_path}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to convert {profraw_file} to .profdata: {e}")
                continue

            try:
                with open(lcov_path, "w") as lcov_file:
                    subprocess.run(
                        ["llvm-cov", "export", command_path, "-instr-profile", profdata_path, "--format=lcov"],
                        check=True,
                        stdout=lcov_file,
                        stderr=subprocess.PIPE,
                    )
                logging.info(f"Generated coverage report: {lcov_path}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to generate coverage report for {profraw_file}: {e}")
                continue

            try:
                os.remove(profdata_path)
                logging.debug(f"Deleted intermediate file: {profdata_path}")
            except OSError as e:
                logging.error(f"Failed to delete {profdata_path}: {e}")

import os
import logging


def extract_and_generate_files(lcov_file_path, target_lib, target_path, language):
    target_path = os.path.abspath(target_path)
    coverage_dir = os.path.join("result", target_lib, "exec_code")
    os.makedirs(coverage_dir, exist_ok=True)

    # Determine the output filename based on the lcov file name and language
    lcov_base_name = os.path.splitext(os.path.basename(lcov_file_path))[0]
    if language == "C":
        output_extension = '.c'
    elif language == "C++":
        output_extension = '.cpp'
    else:
        output_extension = '.txt'
    output_file_name = lcov_base_name + output_extension
    output_file_path = os.path.join(coverage_dir, output_file_name)

    all_executed_lines = []

    current_file = None
    current_executed_lines = []
    skip_until_end = False

    with open(lcov_file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue  # Skip empty lines
            if line.startswith('TN:'):
                continue  # Ignore test names
            elif line.startswith('SF:'):
                if current_file:
                    # Process the previous file
                    process_file(current_file, current_executed_lines, all_executed_lines, target_path)
                    current_executed_lines = []
                file_path = line[len('SF:'):].strip()
                current_file = os.path.abspath(file_path)
                if not current_file.startswith(target_path):
                    skip_until_end = True
                else:
                    skip_until_end = False
            elif line.startswith('DA:'):
                if current_file and not skip_until_end:
                    parts = line[len('DA:'):].split(',')
                    if len(parts) == 2:
                        try:
                            lineno = int(parts[0])
                            count = int(parts[1])
                            if count > 0:
                                current_executed_lines.append(lineno)
                        except ValueError:
                            continue
            elif line == 'end_of_record':
                if current_file:
                    process_file(current_file, current_executed_lines, all_executed_lines, target_path)
                    current_file = None
                    current_executed_lines = []
                skip_until_end = False

    # Process the last file if any
    if current_file:
        process_file(current_file, current_executed_lines, all_executed_lines, target_path)

    # Write all executed lines into the single output file
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        output_file.writelines(all_executed_lines)

    logging.info(f"Generated file: {output_file_path}")


def process_file(source_file, executed_lines, all_executed_lines, target_path):
    try:
        with open(source_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        # Fetch executed lines
        for lineno in executed_lines:
            if 1 <= lineno <= len(lines):
                all_executed_lines.append(lines[lineno - 1])
    except Exception as e:
        logging.error(f"Failed to process file {source_file}: {e}")




if __name__ == "__main__":
    test_case_id = "AomImageTest.AomImgAllocHugeWidth"
    command_path = "/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/aom/build/test_libaom"
    target_lib = "my_target_lib"
    ut = "/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/aom/test"
    output = "output.txt"
    language = "C++"

    try:
        execute_command_with_env(test_case_id, command_path, target_lib)
    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
    except subprocess.CalledProcessError as cpe:
        logging.error(f"CalledProcessError: {cpe}")

    #convert_profraw_to_txt(target_lib, command_path)

    convert_profraw_to_lcov(target_lib,command_path)

    # 指定输入和输出文件路径
    file_path = 'result/my_target_lib/coverage/AomImageTest_AomImgAllocHugeWidth.lcov'
    output_path = 'output.txt'

    # 调用函数并将结果保存到文件
    extract_high_frequency_lines(file_path, output_path)
    lines1 = extract_and_generate_files(file_path,target_lib,ut,language)
    # 或者不指定输出文件路径，仅获取结果列表
    lines = extract_high_frequency_lines(file_path)
    #for line in lines:
    #    print(line)