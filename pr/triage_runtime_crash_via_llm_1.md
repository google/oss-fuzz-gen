# Triage runtime crash via LLM mentioned in [#221](https://github.com/google/oss-fuzz-gen/issues/221)

## Conditions to triage
- Build and run successfully.
- The crash is triggered.
- The SemanticCheckResult is not FP_TIMEOUT(may need additional prompts).
- The SemanticCheckResult is not NO_COV_INCRASE(may need additional prompts).

## Detailed information
- The input contains the crash information(stack trace and sanitizer output) and the fuzz target code.
- The Output is the response from LLM.
- One agent(crash_triage.py) was added to the llm_toolkit folder.
- Two prompts(triage_priming.txt and triage_problem.txt) were added to the prompts/template_xml folder .

