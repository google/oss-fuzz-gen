"""Generate a prompt to identify and remediate the security vulnerability
Usage:
  # Under venv.
  1. python oss_fuzz_vuln_prompt.py
       --repo_url <repo_url>
       --regression_range <regression_range>
       --crash_revision <crash_revision>
       --crash_stacktrace <crash_stacktrace> > prompt.tx
    # <repo_url> is the URL of the git repository.
    # <regression_range> is the regression range or the regressing commit.
    # <crash_revision> is the revision where the crash occurred.
    # <crash_stacktrace> is the file containing the crash stacktrace.

  2. python -m experimental.manual.prompter
       -p prompt.tx
       -l <model_name e.g. vertex_ai_gemini-1-5>
"""

import argparse
import os
import re
import subprocess

from git import BadName, InvalidGitRepositoryError, Repo

PROMPT_TEMPLATE = """
Perform the following tasks to identify and remediate the security vulnerability:

1. Vulnerability Identification:
--- Stack Trace ---
{stacktrace}

--- Changeset (Git Diff Format) ---
{changeset_diff}

--- Source Code ---
{source_code_content}

---
* Carefully review the stack trace to identify the precise line and function where the crash occurs.
* Determine if the changeset directly introduced the vulnerability by correlating the crash stace with the changeset.
* Exclude: Do not analyze the fuzzer code, test files, or build scripts for vulnerabilities.
* If the changeset is not the cause, thoroughly examine the provided source code files to identify the root cause of the vulnerability.
* Provide a clear description of the vulnerability, including:
  * Type: Specify the vulnerability category (e.g., buffer overflow, SQL injection, cross-site scripting).
  * Impact: Describe the potential consequences of exploitation (e.g., code execution, data loss, unauthorized access).
  * Code Patterns: Explain the specific code constructs or patterns that allow the vulnerability to exist.
* Approximate line number matches when comparing changeset to stack trace, as changeset revision is typically earlier.

2. Technical Explanation:
* Provide a detailed, step-by-step technical explanation of how an attacker could exploit the identified vulnerability.
* Describe the code's logic flow, emphasizing the conditions or inputs that trigger the vulnerability.
* Use diagrams, flowcharts, or annotated code snippets to illustrate the vulnerability's execution path and data flow.

3. Remediation Patch:
* Create a patch that completely addresses the root cause of the vulnerability.
* Return the patch in git diff format (Use prefix '+' for added and '-' for removed lines).
* Ensure the patch applies cleanly on the source code files provided.
* Ensure the patch preserves the intended functionality of the codebase without introducing regressions.
* Thoroughly test the patch in the relevant environment to verify that it eliminates the crash and prevents exploitation.
"""
PROMPT_MAX_LENGTH = 1048576
PROJECTS_DIR = os.path.join('oss-fuzz', 'projects')
STACK_FRAME_START_REGEX = re.compile(r'\s*#\d+\s+0x[0-9A-Fa-f]+\s+')
STACK_FRAME_PATH_LINE_REGEX = re.compile(
    r'(?<=\[|\(|\s)([a-zA-Z/.][^\s]*?)\s*(:|@)\s*(\d+)(?=\]$|\)$|:\d+$|$)')
EXCLUDED_FILE_PATH_SUBSTRINGS = ('/compiler-rt/', '/glibc-')


def get_local_repo_path(repo_url):
  """Returns the local path of the repository."""
  local_repo_name = repo_url.split('/')[-1]
  return os.path.join(PROJECTS_DIR, local_repo_name)


def get_git_commit_range(regression_range):
  """Converts a regression range to a git commit range."""
  # If the range is a single commit, return the range as previous commit:commit.
  if not ':' in regression_range and not '..' in regression_range:
    return f"{regression_range}~..{regression_range}"

  return regression_range.replace(':', '..')


def get_changeset_diff(repo_url, regression_range):
  """Fetches the code diff for a given commit range in a Git repository."""
  local_repo_path = get_local_repo_path(repo_url)

  try:
    if not os.path.exists(local_repo_path):
      subprocess.run(["git", "clone", repo_url, local_repo_path],
                     stdout=subprocess.DEVNULL,
                     check=True)
    else:
      subprocess.run(["git", "pull"],
                     cwd=local_repo_path,
                     stdout=subprocess.DEVNULL,
                     check=True)
  except Exception as e:
    raise RuntimeError(f"Error cloning/pulling repository {repo_url}: {e}")

  try:
    repo = Repo(local_repo_path)
  except InvalidGitRepositoryError:
    raise ValueError(f"Invalid Git repository path: {local_repo_path}")

  try:
    diff = repo.git.diff(get_git_commit_range(regression_range))
    return diff.encode('utf-8', 'replace').decode('utf-8')
  except Exception as e:
    raise RuntimeError(f"Error retrieving changeset diff: {e}")


def find_file(file_path, commit):
  """Finds a file in a git commit tree."""
  # Check if the file exists in the git commit tree.
  for tree in commit.tree.traverse():
    if tree.path == file_path:
      return file_path

  # Check if another file with same name exists in the commit tree.
  filename = os.path.basename(file_path)
  for tree in commit.tree.traverse():
    if os.path.basename(tree.path) == filename:
      return str(tree.path)

  # File not found.
  return None


def get_file_content(repo_url, crash_revision, file_path):
  """Fetches the content of a file in a Git repository."""
  local_repo_path = get_local_repo_path(repo_url)
  local_file_path = file_path[:].removeprefix('/src/')
  local_file_path = local_file_path.split('/', 1)[-1]

  try:
    repo = Repo(local_repo_path)
  except InvalidGitRepositoryError:
    raise ValueError(f"Invalid git repository path: {local_repo_path}")

  try:
    commit = repo.commit(crash_revision)
  except BadName:
    print(f"Error: Commit hash '{crash_revision}' not found in repository.")
    return None

  local_file_path = find_file(local_file_path, commit)
  if not local_file_path:
    print(f"Error: '{file_path}' not found in repository.")
    return None

  try:
    return commit.tree[local_file_path].data_stream.read().decode('utf-8')
  except Exception:
    print(f"Error: '{file_path}' not found at commit '{crash_revision}'.")
    return None


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Generate a prompt for a security vulnerability.")
  parser.add_argument("--repo_url", help="Path to the GitHub repository")
  parser.add_argument(
      "--regression_range",
      help="Commit range in the format 'start_commit:end_commit'")
  parser.add_argument("--crash_revision",
                      help="Revision where the crash occurred")
  parser.add_argument("--crash_stacktrace",
                      help="File containing the crash stacktrace")

  args = parser.parse_args()
  os.makedirs(PROJECTS_DIR, exist_ok=True)

  with open(args.crash_stacktrace) as file_handle:
    stacktrace = file_handle.read()
  changeset_diff = get_changeset_diff(args.repo_url, args.regression_range)
  source_code_content = ""
  found_sanitizer_error = False
  for line in stacktrace.splitlines():
    if not STACK_FRAME_START_REGEX.match(line):
      continue

    match = STACK_FRAME_PATH_LINE_REGEX.search(line)
    if not match:
      continue

    file_path = match.group(1)
    if any(
        substring in file_path for substring in EXCLUDED_FILE_PATH_SUBSTRINGS):
      continue

    file_content = get_file_content(args.repo_url, args.crash_revision,
                                    file_path)
    if not file_content:
      continue

    source_code_content += (
        f'**FILE CONTENT: {file_path} **\n{file_content}\n**FILE CONTENT END**\n'
    )

  source_code_content = source_code_content[:PROMPT_MAX_LENGTH -
                                            len(PROMPT_TEMPLATE) -
                                            len(stacktrace) -
                                            len(changeset_diff)]
  prompt = PROMPT_TEMPLATE.format(stacktrace=stacktrace,
                                  changeset_diff=changeset_diff,
                                  source_code_content=source_code_content)
  print(prompt)
