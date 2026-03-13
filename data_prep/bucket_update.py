import sys
import argparse
import os
import yaml
from google.cloud import storage
import logging
from datetime import datetime, timezone
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiment.benchmark import Benchmark  
from introspector import get_project_funcs, query_introspector_function_signature
from datetime import datetime


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

OSS_FUZZ_EXP_BUCKET = 'oss-fuzz-llm-public'
YAML_DIR = 'benchmark-sets/all'

def extract_from_bucket(bucket, project_name: str) -> list:
    """Retrieve all fuzz target files and their content from the bucket."""
    fuzz_targets = []
    project_prefix = f"human_written_targets/{project_name}/"
    blobs = bucket.list_blobs(prefix=project_prefix)

    for blob in blobs:
        # Change current language logic
        logger.info(f"Retrieving content for fuzz target: {blob.name}")
        content = blob.download_as_text()

        fuzz_targets.append({
            "full_path": f"/src/{blob.name.split('/')[-1]}",
            "content": content,
            "signatures": [],  
            "metadata": {
                "language": "c++" if blob.name.endswith(".cpp") else "c",
                "dependencies": [],
                "notes": f"Extracted from {blob.name}"
            },
        })
    return fuzz_targets

def extract_from_benchmark(project_name: str) -> list:
    """Extract fuzz targets and Project Info from benchmark YAML files."""
    yaml_path = os.path.join(YAML_DIR, f"{project_name}.yaml")
    if not os.path.exists(yaml_path):
        logger.error(f"YAML file for project '{project_name}' not found")
        return []

    benchmarks = Benchmark.from_yaml(yaml_path)
    fuzz_targets = []
    for benchmark in benchmarks:
        fuzz_targets.append({
            "full_path": benchmark.target_path,
            "content": "",
            "signatures": [benchmark.function_signature],
            "metadata": {
                "language": benchmark.language,
                "dependencies": [],
                "notes": f"Extracted from {yaml_path}"
            }
        })
    return fuzz_targets

def extract_from_fi(project_name: str) -> list:
    """Extract fuzz targets and Project Info from FuzzIntrospector."""
    try:
        project_funcs = get_project_funcs(project_name)
        fuzz_targets = []
        for target_path, functions in project_funcs.items():
            target_entry = {
                "full_path": target_path,
                "content": "",
                "signatures": [],
                "metadata": { 
                    "language": "c++" if target_path.endswith(".cpp") else "c",
                    "dependencies": [],
                    "notes": f"Extracted from FuzzIntrospector for {project_name}"
                }
            }
            for function in functions:
                function_name = function.get("function-name")
                if function_name:
                    signature = query_introspector_function_signature(project_name, function_name)
                    if signature:
                        target_entry["signatures"].append(signature)
                    else:
                        logger.info(f"Error: No signature found for function '{function_name}' in project '{project_name}'.")
            fuzz_targets.append(target_entry)
        return fuzz_targets
    except Exception as e:
        logger.error(f"Error extracting data from FI for project '{project_name}': {e}")
        return []
    

def merge_fuzz_targets(info_targets: list, bucket_targets: list) -> list:
    """Merge fuzz targets from either benchmark or FI and the bucket."""
    merged_targets = {}

    for bucket_target in bucket_targets:
        key = os.path.basename(bucket_target["full_path"])
        bucket_target["metadata"]["version"] = datetime.now(timezone.utc)
        merged_targets[key] = bucket_target

    for info_target in info_targets:
        key = os.path.basename(info_target["full_path"])
        if key in merged_targets:
            merged_target = merged_targets[key]
            merged_target["metadata"].update(info_target["metadata"])
            for sig in info_target.get("signatures", []):
                if sig not in merged_target.get("signatures", []):
                    merged_target.setdefault("signatures", []).append(sig)
        else:
            info_target["metadata"]["version"] = datetime.now(timezone.utc)
            merged_targets[key] = info_target

    return list(merged_targets.values())


def prepare_project(project_name: str, fuzz_targets: list) -> dict:
    """Prepare Project Info for the project."""
    return {
        "project_name": project_name,
        "last_updated": datetime.now(timezone.utc),
        "fuzz_targets": fuzz_targets
    }

def upload_project(bucket,project_name: str, yaml_data: dict):
    """Upload Project Info to the cloud bucket."""
    try:
        temp = f"data_prep/tmp/{project_name}.yaml"
        os.makedirs("data_prep/tmp", exist_ok=True)
        with open(temp, "w") as tempf:
            yaml.dump(yaml_data, tempf, sort_keys=False)
        destination_path = f"human_written_targets/{project_name}/{project_name}.yaml"
        blob = bucket.blob(destination_path)
        blob.upload_from_filename(temp)
        logger.info(f"Uploaded project info for '{project_name}' to GCS at '{destination_path}'.")
    except Exception as e:
        logger.error(f"Failed to upload project info for '{project_name}' to GCS: {e}")

def update_project(project_name: str, use_info: str):
    """Update project info in the cloud bucket."""
    try:
        logger.info(f"Retrieving fuzz target content from the bucket for project '{project_name}'...")
        storage_client = storage.Client.create_anonymous_client()
        bucket = storage_client.bucket(OSS_FUZZ_EXP_BUCKET)

        bucket_targets = extract_from_bucket(bucket, project_name)
        
        if use_info == 1:
            logger.info(f"Extracting fuzz targets from FI for project '{project_name}'...")
            info_targets = extract_from_fi(project_name)

        else: 
            logger.info(f"Extracting fuzz targets from benchmark YAML for project '{project_name}'...")
            info_targets = extract_from_benchmark(project_name)

        logger.info(f"Merging fuzz targets")
        merged_targets = merge_fuzz_targets(info_targets, bucket_targets)

        logger.info(f"Preparing metadata for project '{project_name}'...")
        yaml_data = prepare_project(project_name, merged_targets)

        logger.info(f"Upload project '{project_name}' to Bucket.")
        upload_project(bucket,project_name, yaml_data)

    except Exception as e:
        logger.error(f"An error occurred while updating project '{project_name}': {e}")

def _parse_arguments():
    """Parses command line args."""
    parser = argparse.ArgumentParser(
      description='Parse project-related arguments')
    parser.add_argument('-p',
                        '--project-name',
                        type=str,
                        required=True,
                        help='Name of the project')
    parser.add_argument('--use_info',
                        type=int,
                        default = 1,
                        help='Use info from benchmark(0) or fuzz introspector(1)',)
    parsed_args = parser.parse_args()
    return parsed_args
  
if __name__ == "__main__":
    args = _parse_arguments()
    update_project(args.project_name,args.use_info)
