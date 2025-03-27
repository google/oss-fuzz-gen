"""Retrieves Project Info from the Cloud Bucket"""

import argparse
import os
import json
import yaml
from google.cloud import storage  
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

OSS_FUZZ_EXP_BUCKET = 'oss-fuzz-llm-public'
CACHE_DIR = os.path.join(os.path.dirname(__file__), "cached-info")

#TO DO: Implement functions to retrieve signatures, paths, and targets separately
def fetch_project_info(project_name: str) -> dict:
    """Connects and Fetches the Project Info from the Cloud Bucket."""
    storage_client = storage.Client.create_anonymous_client()
    bucket = storage_client.bucket(OSS_FUZZ_EXP_BUCKET)
    #TO DO: To actually check and download the yaml in the cloud bucket
    #Actual Path for Blob Found in Bucket, currently simulates behaviour when blob not found
    # blob_name = f"human_written_targets/{project_name}/{project_name}.yaml"

    #Dummy Path for Blob Found in Bucket, to simulate behaviour when blob is found
    blob_name = f"human_written_targets/ndpi/fuzz_alg_bins.cpp"
    
    blob = bucket.blob(blob_name)

    if blob.exists():
        logger.info(f"Found YAML file in Bucket ({project_name}.yaml)")
        #Dummy yaml for testing
        dummy_file_path = 'data_prep/uploads/avahi.yaml'
        with open(dummy_file_path, "r") as dummy_file:
            return yaml.safe_load(dummy_file)
        
        #Actual Downloading and returning of the bucket yaml
        # content = blob.download_as_text()
        # project_data = yaml.safe_load(content)
        # return project_data

    elif not blob.exists():
        logger.warning(f" YAML file not found in Bucket ({project_name}.yaml)")
        return None

def cache_project_info(project_name: str, project_data: dict):
    """Caches Project Info Locally."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR,f"{project_name}.yaml")
    with open(cache_path, "w") as cache_file:
        yaml.dump(project_data, cache_file)
    logger.info(f"Cached Project {project_name} Locally")

def retrieve_project_info(project_name: str) -> dict:
    """Retrieves Project Info using Local Cache if Available 
    else Retrieve it from Bucket and Cache Locally."""
    cache_path = os.path.join(CACHE_DIR, f"{project_name}.yaml")
    if os.path.exists(cache_path):
        logger.info("Fetching Project Info from Local Cache")
        with open(cache_path, "r") as cache_file:
            return yaml.safe_load(cache_file)

    logger.info(f"Fetching Project Info for project {project_name} from Bucket.")
    project_data = fetch_project_info(project_name)
    if project_data:
        cache_project_info(project_name, project_data)
    return project_data

def _parse_arguments():
    """Parses command line args."""
    parser = argparse.ArgumentParser(
      description='Parse project-related arguments')

    # project_name argument
    parser.add_argument('-p',
                        '--project-name',
                        type=str,
                        required=True,
                        help='Name of the project')
    parsed_args = parser.parse_args()
    return parsed_args
  
if __name__ == "__main__":
    args = _parse_arguments()
    project_name = args.project_name

    project_data = retrieve_project_info(project_name)

    if project_data:
        print(yaml.dump(project_data, indent=2))
    else:
        logger.error("Failed to retrieve Project Info")