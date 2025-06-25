"""A dedicated parser to parse the run log and extract
information such as the crash details, crash symptoms,
stack traces, etc. to be rendered in the report."""
import re


class RunLogsParser:
  """Parse the run log."""

  def __init__(self, run_logs: str):
    self._run_logs = run_logs
    self._lines = run_logs.split('\n')

  def get_crash_details(self) -> str:
    """Get the raw crash details for the given sample."""
    crash_details = ""
    start_idx = 0
    end_idx = len(self._lines) - 1

    for idx, line in enumerate(self._lines):
      if "==========" in line:
        start_idx = idx
      if 0 < start_idx < idx and "artifact_prefix" in line:
        end_idx = idx

    # If we found a start index, then we can get the crash details
    # Otherwise, return an empty string (for rendering purposes,
    # because then this will just be the entire run log)
    if start_idx > 0:
      crash_details = '\n'.join(self._lines[start_idx:end_idx + 1])

    return crash_details

  def get_crash_symptom(self) -> str:
    """Get the crash symptom from the run log."""
    crash_symptom = ""

    pattern = re.compile(r"(?:^\s*\x1b\[[0-9;]*m)*==\d+==\s*(ERROR:.*)",
                         re.DOTALL)

    for line in self._lines:
      match = pattern.search(line)
      if match:
        crash_symptom = match.group(1)
        break

    return crash_symptom
