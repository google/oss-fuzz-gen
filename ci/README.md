# TODO

## Automate PR experiments
Automatically runs a test experiment for PRs **created or approved by us**.
Currently, here is how we do it manually:
1. Wait for the `Build Docker image for PR / build (pull_request)` CI to finish.
    * This CI uploads/updates an image (tagged with PR ID) to our artifact registry.
2. Auth to gcloud locally.
    * E.g., `gcloud auth login && gcloud auth application-default login && gcloud auth application-default set-quota-project oss-fuzz`.
3. Request a GKE experiment with `request_pr_exp.py`.
    * E.g., `python -m report.request_pr_exp -p <PR-ID> -n <YOUR-NAME>`.
4. Copy and Paste the links printed by the script to the PR so that others can see it and track improvements / regressions.
    * E.g., https://github.com/google/oss-fuzz-gen/pull/118#issuecomment-1958555260
5. (Optional) Repeat 1-3 if the experiment failed. Add `-f` in step 3 so that the old GKE job and bucket dir will be removed to give place to the new one.
    * E.g., `python -m report.request_pr_exp -p <PR-ID> -n <YOUR-NAME> -f`
