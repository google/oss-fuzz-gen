import sys
import argparse
import os
import yaml
from google.cloud import storage
import logging
import datetime
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiment.benchmark import Benchmark  

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

OSS_FUZZ_EXP_BUCKET = 'oss-fuzz-llm-public'
YAML_DIR = 'benchmark-sets/all'

# TO DO: To retrieve the Targets & Its content from the Bucket
def retrieve_fuzz_target_content(bucket, project_name: str) -> list:
    """Retrieve all fuzz target files and their content from the bucket."""
    fuzz_targets = []
    project_prefix = f"human_written_targets/{project_name}/"
    blobs = bucket.list_blobs(prefix=project_prefix)

    for blob in blobs:
        # there may be other types of files as well
        if blob.name.endswith(".cc") or blob.name.endswith(".cpp") or blob.name.endswith(".c"):
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

def extract_data_from_yaml(project_name: str) -> list:
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
            "signatures": [benchmark.function_signature],
            "metadata": {
                "language": benchmark.language,
                "dependencies": [],
                "notes": f"Extracted from {yaml_path}"
            }
        })
    return fuzz_targets

def merge_fuzz_targets(benchmark_targets: list, bucket_targets: list) -> list:
    """Merge fuzz targets from the benchmark YAML and the bucket."""
    merged_targets = {}

    for bucket_target in bucket_targets:
        key = os.path.basename(bucket_target["full_path"])
        bucket_target["metadata"]["version"] = datetime.datetime.now(datetime.UTC)
        merged_targets[key] = bucket_target

    for benchmark_target in benchmark_targets:
        key = os.path.basename(benchmark_target["full_path"])
        if key in merged_targets:
            merged_target = merged_targets[key]
            merged_target["metadata"].update(benchmark_target["metadata"])
            for sig in benchmark_target.get("signatures", []):
                if sig not in merged_target.get("signatures", []):
                    merged_target.setdefault("signatures", []).append(sig)
        else:
            if "content" not in benchmark_target:
                benchmark_target["content"] = ""
            benchmark_target["metadata"]["version"] = datetime.datetime.now(datetime.UTC)
            merged_targets[key] = benchmark_target

    return list(merged_targets.values())

# TO DO: If the function signature is missing in benchmark, fallback to FI, also check for COVERAGE METRICS
def fallback_to_fi(project_name: str, fuzz_targets: list):
    """Fallback to FI for missing function signatures/additional metrics"""
    # for target in fuzz_targets:
    #     if not target["signatures"]:
    #         logger.info(f"Fetching missing signature for {target['full_path']} from FI.")
    #         signature = get_function_signature({"function_name": target["full_path"]}, project_name)
    #         if signature:
    #             target["signatures"].append(signature)
    pass

def prepare_project(project_name: str, fuzz_targets: list) -> dict:
    """Prepare Project Info for the project."""
    return {
        "project_name": project_name,
        "last_updated": datetime.datetime.now(datetime.UTC),
        "fuzz_targets": fuzz_targets
    }

def upload_project(project_name: str, yaml_data: dict):
    """Upload Project Info to the cloud bucket."""
    try:
        #To Do Upload logic to Bucket
        # blob.upload_from_string(yaml_data)
        # Testing current logic with dummy uploads
        dummy_path = os.path.join("data_prep/uploads", f"{project_name}.yaml")
        os.makedirs("data_prep/uploads", exist_ok=True)
        with open(dummy_path, "w") as dfile:
            yaml.dump(yaml_data, dfile,sort_keys=False)

        logger.info(f"Simulated upload: Project-info for project '{project_name}' saved ")
    except Exception as e:
        logger.error(f"Failed to simulate upload for project '{project_name}': {e}")

def update_project(project_name: str):
    """Update project info in the cloud bucket."""
    try:
        logger.info(f"Retrieving fuzz target content from the bucket for project '{project_name}'...")
        storage_client = storage.Client.create_anonymous_client()
        bucket = storage_client.bucket(OSS_FUZZ_EXP_BUCKET)
        bucket_targets = retrieve_fuzz_target_content(bucket, project_name)

        logger.info(f"Extracting fuzz targets from benchmark YAML for project '{project_name}'...")
        benchmark_targets = extract_data_from_yaml(project_name)

        logger.info(f"Merging fuzz targets from benchmark YAML and bucket for project '{project_name}'...")
        merged_targets = merge_fuzz_targets(benchmark_targets, bucket_targets)

        logger.info(f"Preparing metadata for project '{project_name}'...")
        yaml_data = prepare_project(project_name, merged_targets)

        logger.info(f"Simulating upload for project '{project_name}'...")
        upload_project(project_name, yaml_data)

        logger.info(f"Update process for project '{project_name}' completed successfully.")
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
    parsed_args = parser.parse_args()
    return parsed_args
  
if __name__ == "__main__":
    args = _parse_arguments()
    update_project(args.project_name)
