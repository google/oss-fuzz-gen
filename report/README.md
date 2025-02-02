# Reports

## Experiment Report

*  While the experiment is running, `upload_report.sh` periodically generates
   an experiment report and uploads it to
   `gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/`.
*  After the experiment a final report is generated and uploaded to GCS.
*  These reports are accessible to collaborators via
   `https://llm-exp.oss-fuzz.com/Result-reports/{experiment_name}`

## Trends Report

1. After each experiment is finished, `docker_run.sh` uploads a summary json
   file to `gs://oss-fuzz-gcb-experiment-run-logs/trend-reports/`.
2. Upload of the summary json triggers a
   [Cloud Run Function](https://pantheon.corp.google.com/functions/details/us-central1/llm-trends-report-index?env=gen1&project=oss-fuzz)
   which updates
   `gs://oss-fuzz-gcb-experiment-run-logs/trend-reports/index.json`.
3. The
   [trends report web page](https://llm-exp.oss-fuzz.com/trend-reports/index.html)
   loads the index and discovers available summary json files.

# Updating the Code

*  The Cloud Run Functions are updated manually by running
   `deploy_functions.sh`.
*  The web page files in `gs://oss-fuzz-gcb-experiment-run-logs/trend-reports/`
   are updated via a
   [Cloud Run Function](https://pantheon.corp.google.com/functions/details/us-central1/llm-trends-report-web?env=gen1&project=oss-fuzz).

