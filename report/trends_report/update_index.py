"""Cloud Run Function to update the trends report index."""
import json
import sys

from google.cloud import storage


def trends_report_index(event, context):
  """Read all the trends reports in GCS and write an index at the root."""
  # Don't trigger on changes to index.json or other top level files
  if len(event['attributes']['objectId'].split('/')) < 3:
    return ''

  index = {}
  bucket = storage.Client().bucket('oss-fuzz-gcb-experiment-run-logs')
  for b in bucket.list_blobs(prefix='trend-reports/'):
    # Skip reading index.json or other top level files
    if len(b.name.split('/')) < 3:
      continue

    print(f'Reading {b.name}')
    try:
      # e.g. trend-reports/scheduled/2024-11-02-weekly-all.json -> scheduled
      directory = b.name.split('/')[1]
      report = json.loads(b.download_as_text())
      index[report['name']] = {
          'directory': directory,
          'name': report['name'],
          'url': report['url'],
          'date': report['date'],
          'benchmark_set': report['benchmark_set'],
          'llm_model': report['llm_model'],
          'tags': report['tags'],
      }
    except:
      print('****************************', file=sys.stderr)
      print(f'Issue when reading {b.name}', file=sys.stderr)
      print('****************************', file=sys.stderr)

  bucket.blob('trend-reports/index.json').upload_from_string(
      json.dumps(index), content_type='application/json')

  return ''
