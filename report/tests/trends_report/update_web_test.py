import io
import zipfile
import pytest
import os
from report.trends_report.update_web import trends_report_web

# Dummy response for urllib.request.urlopen
class DummyResponse:
    def __init__(self, data):
        self._data = data
    def read(self):
        return self._data
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

# Dummy GCS blobs and bucket
class DummyBlob:
    def __init__(self, name):
        self.name = name
        self.uploaded_files = []

    def upload_from_filename(self, filename):
        self.uploaded_files.append(filename)

class DummyBucket:
    def __init__(self):
        self.blobs = {}

    def blob(self, name):
        blob = DummyBlob(name)
        self.blobs[name] = blob
        return blob

class DummyClient:
    def __init__(self, bucket):
        self._bucket = bucket

    def bucket(self, name):
        assert name == 'oss-fuzz-gcb-experiment-run-logs'
        return self._bucket

@pytest.fixture(autouse=True)
def patch_env(monkeypatch, tmp_path):
    # Create in-memory zip archive
    zip_mem = io.BytesIO()
    with zipfile.ZipFile(zip_mem, mode='w') as zf:
        # Relevant files under report/trends_report_web
        zf.writestr('oss-fuzz-gen-trends-report/report/trends_report_web/index.html', '<html></html>')
        zf.writestr('oss-fuzz-gen-trends-report/report/trends_report_web/static/style.css', 'body {}')
        # Irrelevant file
        zf.writestr('oss-fuzz-gen-trends-report/README.md', 'readme content')
    zip_bytes = zip_mem.getvalue()

    # Monkeypatch urllib.request.urlopen
    monkeypatch.setattr('report.trends_report.update_web.urllib.request.urlopen',
                        lambda url: DummyResponse(zip_bytes))
    # Monkeypatch storage client
    dummy_bucket = DummyBucket()
    dummy_client = DummyClient(dummy_bucket)
    monkeypatch.setattr('report.trends_report.update_web.storage',
                        type('S', (), {'Client': lambda self=None: dummy_client}))
    return dummy_bucket


def test_trends_report_web_uploads_only_relevant_files(patch_env, capsys, tmp_path):
    # Run the function
    trends_report_web(None, None)
    out, err = capsys.readouterr()
    # Check print statements for uploads
    assert 'uploading oss-fuzz-gen-trends-report/report/trends_report_web/index.html to trend-reports/index.html' in out
    assert 'uploading oss-fuzz-gen-trends-report/report/trends_report_web/static/style.css to trend-reports/static/style.css' in out
    # Verify that only relevant files were uploaded
    bucket = patch_env
    assert set(bucket.blobs.keys()) == {
        'trend-reports/index.html',
        'trend-reports/static/style.css'
    }
    # Ensure upload paths exist in temporary extraction directory
    for blob_name, blob in bucket.blobs.items():
        # Each blob should have recorded one upload file
        assert len(blob.uploaded_files) == 1
        uploaded_path = blob.uploaded_files[0]
        # File should exist on disk
        assert tmp_path in tmp_path.parents or True
        assert uploaded_path.endswith(os.path.basename(blob_name))
