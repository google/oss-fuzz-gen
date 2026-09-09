# OSS-Fuzz Autonomous Fuzz Build Repair Agent

This project is a high-performance, industrial-grade autonomous agent system designed to fix build errors in **OSS-Fuzz**. It leverages LLMs (DeepSeek) and a multi-agent orchestration framework (**google-adk**) to perform environment locking, root cause analysis, and dual-track (Config vs. Source) code repair.

## 🚀 Core Features

1.  **1+6 Validation Criteria**: A robust verification engine that ensures a fix is truly successful.
    *   **Step 1 (Primary Build)**: Successful generation of executable target binaries.
    *   **Step 6 (Runtime Stability Audit)**: A mandatory **45s critical stability test** ensuring execution speed (exec/s) > 0.
    *   **Steps 2-5 (Quality Metrics)**: Verification of Sanitizer injection (ASan), Engine symbols (libFuzzer/AFL++), Project logic linking, and Shared dependency integrity.
2.  **HAFix (Heuristic History-Enhanced Localization)**: Automatically identifies the "Buggy Commit" by analyzing Git history (`git blame`, `fl_diff`, `fn_pair`) to provide temporal context for the LLM.
3.  **Physical State Tree Rollback**: Utilizes Git to manage physical snapshots of the environment. If a repair path deteriorates (score > 7), the system performs a physical `git reset` to a stable state and clears the previous analysis bias.
4.  **Token-Efficient Memory Management**:
    *   **Prune Session History**: A whitelist-based strategy that physically wipes intermediate tool call noise (ls, find, read_file) while retaining core reasoning.
    *   **Context Truncation**: Specialized `tail_100_lines` logging and summary agents keep context within the 131k token limit.
5.  **Expert Knowledge RAG-Lite**: Matches build log patterns against a curated `expert_knowledge.json` to inject strategic guidance for complex infrastructure issues (e.g., WORKDIR conflicts).

## 📂 Project Structure

```text
.
├── agent.py                 # Main Orchestrator & Loop Logic
├── agent_tools.py           # Core Tools (Git, Build, 1+6 Validation, RAG)
├── oss-fuzz/                # Local OSS-Fuzz infrastructure (Must be at this level)
├── instructions/            # Agent Persona & Workflow Instructions
├── expert_knowledge.json    # Expert Pattern Knowledge Base
├── projects.yaml            # Project Task List (Metadata Source)
├── process/
│   └── project/             # Cloned Target Software (e.g., ./process/project/curl)
│   └── fixed/               # Archived successful repairs with full content
└── agent_logs/              # Real-time console & mirrored event logs

Here is the content converted into a professional Markdown format, ready to be used in your `README.md`:

---

## 🛠️ Setup Requirements

*   **Python**: 3.10+
*   **System Utilities**:
    *   **GitHub CLI (`gh`)**: Must be installed and authenticated (`gh auth login`).
    *   **Docker**: Required for OSS-Fuzz containerized builds.
    *   **Standard Tools**: `nm`, `ldd`, `python3`.
*   **API Key**: A valid DeepSeek API key set in a `.env` file.

```bash
# Install required Python libraries
pip install litellm google-adk requests openpyxl pyyaml python-dotenv
```

## ⚙️ Configuration

### 1. Create a `.env` file in the root:
```env
DPSEEK_API_KEY='your_api_key_here'
```

### 2. Define tasks in `projects.yaml`:
```yaml
- project: example_project
  sha: <oss_fuzz_commit_sha>
  software_repo_url: <target_git_url>
  software_sha: <target_software_commit_sha>
  base_image_digest: <docker_image_hash>
  engine: libfuzzer
  sanitizer: address
  architecture: x86_64
  fixed_state: 'no'
  state: 'no'
```

## 🔄 Workflow Logic

### Phase 1: Deterministic Setup
`initial_setup_agent` locks the Docker base image digest and checkouts the exact Git SHAs. It enforces `build_mode: source` for local mounting.

### Phase 2: Inner Loop (Max 8-15 Iterations)
*   **Build & 1+6 Audit**: `run_fuzz_and_collect_log_agent` executes the build via `run_fuzz_build_and_validate`.
*   **Decision**: `decision_agent` checks if Step 1 (Build) and Step 6 (Runtime) both passed.
*   **Reflection**: `reflection_agent` assigns a **Deterioration Score (1-10)** based on the 1+6 metrics.
*   **Rollback**: Catastrophic failures trigger a physical environment revert via Git.
*   **Diagnosis (HAFix)**: `commit_finder_agent` locates the buggy commit using temporal or trace analysis.
*   **Solve & Apply**: `fuzzing_solver_agent` generates a multi-file Patch Plan, which is then applied by `solution_applier_agent`.

### Phase 3: Cleanup & Archive
Successful fixes are validated, archived to `process/fixed/` with full content, and the `projects.yaml` report is updated.

## ⚠️ Critical Engagement Rules

*   **Anchor Integrity**: Patching requires an exact byte-for-byte match of the `ORIGINAL` block.
*   **Observability**: All STDOUT and STDERR are mirrored to `agent_logs/` via `StreamTee` for post-mortem debugging.

## 🚀 Execution

```bash
python agent.py
```
