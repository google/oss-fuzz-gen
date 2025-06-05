import argparse
import os

from google.cloud import storage

GCS_BUCKET_NAME = 'pamusuo-tests'

CGS_RESULTS_DIR = "Function-analysis-results"


def upload_directory_to_gcs(local_folder_path,
                            bucket_name,
                            destination_blob_prefix=""):
  """
    Uploads all .txt files from a local folder to a Google Cloud Storage bucket.

    Args:
        local_folder_path (str): The path to the local folder containing the .txt files.
        bucket_name (str): The name of your Google Cloud Storage bucket.
        destination_blob_prefix (str): An optional prefix for the blob names in GCS.
                                       Useful for organizing files within the bucket.
                                       e.g., "my_text_files/"
    """
  storage_client = storage.Client()
  bucket = storage_client.bucket(bucket_name)

  print(f"Starting upload from local folder: {local_folder_path}")

  for root, _, files in os.walk(local_folder_path):
    for file_name in files:
      if file_name.endswith(".txt"):
        local_file_path = os.path.join(root, file_name)

        # Construct the blob path in GCS
        # This ensures the folder structure is maintained if needed
        # For simplicity, we'll just put all files directly under the prefix
        # If you want to maintain subdirectories, you'd adjust this.
        relative_path = os.path.relpath(local_file_path, local_folder_path)
        destination_blob_name = os.path.join(
            destination_blob_prefix, relative_path).replace(
                "\\", "/")  # Replace backslashes for Linux/GCS compatibility

        blob = bucket.blob(destination_blob_name)

        try:
          blob.upload_from_filename(local_file_path)
          print(
              f"Uploaded {local_file_path} to gs://{bucket_name}/{destination_blob_name}"
          )
        except Exception as e:
          print(f"Error uploading {local_file_path}: {e}")


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Upload a directory to a Google Cloud Storage bucket.")
  parser.add_argument("-d",
                      "--directory",
                      help="Path to the directory to upload",
                      required=True)
  parser.add_argument("-b",
                      "--bucket",
                      help="Name of the GCS bucket",
                      default=GCS_BUCKET_NAME)
  args = parser.parse_args()

  # Ensure the directory exists
  if not os.path.isdir(args.directory):
    raise ValueError(
        f"The specified directory does not exist: {args.directory}")

  # Upload the directory to GCS
  upload_directory_to_gcs(args.directory, args.bucket, CGS_RESULTS_DIR)
