"""Cloud Run Function to update trends report web page from GitHub."""
import io
import os
import tempfile
import urllib.request
import zipfile

from google.cloud import storage

REPO_ZIP_LINK = 'https://github.com/google/oss-fuzz-gen/archive/refs/heads/main.zip'
ZIP_DIR = 'oss-fuzz-gen-trends-report'


def trends_report_web(event, context):
  """Update trends report web page files from GitHub."""
  bucket = storage.Client().bucket('oss-fuzz-gcb-experiment-run-logs')

  with urllib.request.urlopen(REPO_ZIP_LINK) as response:
    zip_contents = response.read()

  with tempfile.TemporaryDirectory() as temp:
    with zipfile.ZipFile(io.BytesIO(zip_contents)) as zip_file:
      zip_file.extractall(temp)
      for path in zip_file.namelist():
        parts = path.split('/report/trends_report_web/')

        # Upload files under report/trends_report_web/
        if len(parts) > 1 and parts[1] != '':
          fname = parts[1]
          print(f'uploading {path} to trend-reports/{fname}')
          blob = bucket.blob(f'trend-reports/{fname}')
          blob.upload_from_filename(os.path.join(temp, path))


if __name__ == "__main__":
  trends_report_web(None, None)
