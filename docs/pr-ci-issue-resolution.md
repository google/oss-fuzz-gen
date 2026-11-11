# PR CI Issue Resolution Log

This file records verified fixes for the experimental fix-build-agent PR.
It contains no credentials or generated experiment output.

## 1. PR Image Build Failure

- Symptom: The `oss-fuzz-gen-exp` image build failed while installing the
  Google Cloud GKE authentication plugin.
- Root cause: The current Google Cloud APT repository no longer provides
  `google-cloud-sdk-gke-gcloud-auth-plugin` under that package name.
- Verified fix: In `ci/Dockerfile`, replace it with
  `google-cloud-cli-gke-gcloud-auth-plugin`.
- Validation: The package error was removed from the Docker build failure.
- Commit: `6457839 Fix GKE auth plugin package name`.

## 2. Pyright Anthropic Vertex Error

- Symptom: Pyright reported that `AnthropicVertex` was not exported by the
  installed `anthropic` type information.
- Root cause: The runtime API and the pinned SDK type information were not
  exposed consistently to the type checker.
- Verified fix: Resolve `AnthropicVertex` with `getattr`, check for its
  absence, and then construct the client.
- Validation: Pyright completed with `0 errors, 0 warnings, 0 informations`.
- Commit: `26814fe Fix PR compatibility checks`.

## 3. Excessive Fix-Agent Dependency Lockfile

- Symptom: OSV-Scanner reported vulnerabilities in packages such as
  `torch`, `transformers`, `tinytag`, `mako`, `aiohttp`, and `Pygments`.
- Root cause: `fix_build_agent/requirements.txt` was a full environment lock,
  not a minimal list of dependencies directly imported by the agent. The
  security scanner scans the tracked file even when the CI image does not
  install it directly.
- Verified fix: Reduce the file to the agent's direct runtime dependencies:
  `google-adk`, `litellm`, `openpyxl`, `python-dotenv`, and `PyYAML`.
- Validation: The bundled agent imported successfully from its own working
  directory and `pip check` reported no broken requirements.
- Commit: `0ae3d64 Trim build agent runtime dependencies`.

## 4. Remaining Direct-Dependency Vulnerabilities

- Symptom: OSV-Scanner still reported multiple vulnerabilities in
  `litellm==1.80.5` and `python-dotenv==1.1.1`.
- Root cause: The remaining direct dependencies were pinned below the fixed
  versions reported by OSV-Scanner.
- Verified fix: Upgrade to `litellm==1.84.0` and `python-dotenv==1.2.2`.
- Validation: Both packages imported successfully and `pip check` reported
  no broken requirements.
- Commit: `3638378 Update vulnerable build agent dependencies`.

## Verification Notes

- Pylint emits many diagnostics for the imported `agent_tools.py` code. The
  official presubmit invokes Pylint with `|| true`, so these diagnostics do
  not determine the job result. They should not be hidden as resolved issues.
- A successful local package import does not prove that the PR GKE image has
  been rebuilt. The PR image CI must pass before running `/gcbrun exp`.
- If OSV-Scanner reports new packages, first determine whether they are
  direct imports or transitive dependencies, then update or remove the
  smallest responsible dependency set.

## 5. Empty GKE HTML Report

- Symptom: The GCS report page was generated successfully but showed zero
  benchmarks and zero projects.
- Root cause: `report/docker_run.py` always asked `report/upload_report.sh` to
  read `results`, while fix-build runs write to
  `results-fix-build/<model-family>`. The wrapper also dropped the first
  additional argument instead of removing `--` only when it was present.
- Verified fix: Select the actual fix-build result directory, preserve the
  downstream fix-build flags, and use a dedicated report generator that reads
  project metadata, original build logs, repair traces, round counts, patches,
  fixed files, and agent logs.
- Validation: The local generator found four project records and rendered
  their repair artifacts into `/tmp/fix-build-report-3/index.html`.
