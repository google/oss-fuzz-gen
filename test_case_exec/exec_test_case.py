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
        logging.info("Command executed successfully.")
        if os.path.exists(xml_output_path):
            try:
                tree = ET.parse(xml_output_path)
                root = tree.getroot()
                tests_run = int(root.attrib.get('tests', '0'))
                if tests_run == 0:
                    logging.warning("No tests were run with the given filter.")
                    if os.path.exists(profraw_output_path):
                        try:
                            os.remove(profraw_output_path)
                            logging.info(f"Deleted {profraw_output_path} since no tests were run.")
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
    # Define paths
    profraw_dir = os.path.join("result", target_lib, "profraw")
    coverage_dir = os.path.join("result", target_lib, "coverage")  # Coverage folder at the same level as profraw

    # Ensure the coverage directory exists
    os.makedirs(coverage_dir, exist_ok=True)

    # Check if the profraw directory exists
    if not os.path.exists(profraw_dir):
        logging.error(f"Profraw directory not found: {profraw_dir}")
        return

    # Iterate over all .profraw files in the profraw directory
    for profraw_file in os.listdir(profraw_dir):
        if profraw_file.endswith(".profraw"):
            profraw_path = os.path.join(profraw_dir, profraw_file)
            profdata_path = os.path.join(coverage_dir, profraw_file.replace(".profraw", ".profdata"))
            txt_path = os.path.join(coverage_dir, profraw_file.replace(".profraw", ".txt"))

            # Step 1: Convert .profraw to .profdata using llvm-profdata
            try:
                subprocess.run(
                    ["llvm-profdata", "merge", "-sparse", profraw_path, "-o", profdata_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                logging.info(f"Converted {profraw_file} to {profdata_path}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to convert {profraw_file} to .profdata: {e}")
                continue

            # Step 2: Generate .txt coverage report using llvm-cov
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

            # Step 3: Delete the intermediate .profdata file
            try:
                os.remove(profdata_path)
                logging.info(f"Deleted intermediate file: {profdata_path}")
            except OSError as e:
                logging.error(f"Failed to delete {profdata_path}: {e}")


if __name__ == "__main__":
    test_case_id = "AomImageTest.AomImgAllocHugeWidth"
    command_path = "/media/fengxiao/3d47419b-aaf4-418e-8ddd-4f2c62bebd8b/workSpace/aom/build/test_libaom"
    target_lib = "my_target_lib"

    try:
        execute_command_with_env(test_case_id, command_path, target_lib)
    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
    except subprocess.CalledProcessError as cpe:
        logging.error(f"CalledProcessError: {cpe}")

    convert_profraw_to_txt(target_lib, command_path)