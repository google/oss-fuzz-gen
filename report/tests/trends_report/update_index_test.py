import json
import sys
import pytest
from report.trends_report.update_index import trends_report_index

class DummyBlob:
    def __init__(self, name, data=None, throws=False):
        self.name = name
        self._data = data
        self._throws = throws
        self.uploaded_data = None
        self.upload_content_type = None

    def download_as_text(self):
        if self._throws:
            raise Exception("download error")
        return self._data

    def upload_from_string(self, data, content_type):
        self.uploaded_data = data
        self.upload_content_type = content_type

class DummyBucket:
    def __init__(self, blobs):
        self._blobs = blobs
        # Create an upload blob for index.json
        self._upload_blob = DummyBlob('trend-reports/index.json')

    def list_blobs(self, prefix=None):
        # Return iterable of listing blobs
        return self._blobs

    def blob(self, name):
        # Return the upload target for index.json
        assert name == 'trend-reports/index.json'
        return self._upload_blob

class DummyClient:
    def __init__(self, bucket):
        self._bucket = bucket

    def bucket(self, name):
        assert name == 'oss-fuzz-gcb-experiment-run-logs'
        return self._bucket

@pytest.fixture(autouse=True)
def patch_storage(monkeypatch):
    # DummyClient instead of real storage.Client
    dummy_bucket = DummyBucket([])
    dummy_client = DummyClient(dummy_bucket)
    monkeypatch.setattr('report.trends_report.update_index.storage', 
                        type('m', (), {'Client': lambda self=None: dummy_client}))
    return dummy_bucket


def test_no_op_on_shallow_event(patch_storage, capsys):
    # Event path depth < 3 should not trigger GCS
    event = {'attributes': {'objectId': 'a/b'}}
    res = trends_report_index(event, None)
    captured = capsys.readouterr()
    assert res == ''
    assert captured.out == '' and captured.err == ''
    assert patch_storage._upload_blob.uploaded_data is None


def test_trends_report_index_success(patch_storage, capsys):
    # Prepare blobs: shallow skip, valid, invalid
    valid_report = {'name': 'r1', 'url': 'u1', 'date': 'd1', 'benchmark_set': 'bs', 'llm_model': 'm1', 'tags': ['t']}
    shallow_blob = DummyBlob('trend-reports/index.json', data=json.dumps(valid_report))
    good_blob = DummyBlob('trend-reports/scheduled/2025-04-22-weekly.json', data=json.dumps(valid_report))
    bad_blob = DummyBlob('trend-reports/scheduled/bad.json', data='notjson', throws=True)
    patch_storage._blobs[:] = [shallow_blob, good_blob, bad_blob]

    event = {'attributes': {'objectId': 'trend-reports/scheduled/2025-04-22-weekly.json'}}
    res = trends_report_index(event, None)
    out, err = capsys.readouterr()

    # Should read only good_blob (skip shallow, handle bad without raising)
    assert 'Reading trend-reports/scheduled/2025-04-22-weekly.json' in out
    assert 'Issue when reading trend-reports/scheduled/bad.json' in err
    # Verify upload
    upload_blob = patch_storage._upload_blob
    assert upload_blob.uploaded_data is not None
    index = json.loads(upload_blob.uploaded_data)
    # Index should have 'r1'
    assert 'r1' in index
    entry = index['r1']
    assert entry['url'] == 'u1'
    assert entry['directory'] == 'scheduled'
    assert entry['date'] == 'd1'
    assert entry['benchmark_set'] == 'bs'
    assert entry['llm_model'] == 'm1'
    assert entry['tags'] == ['t']
    assert res == ''
