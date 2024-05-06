# Triaging runtime crash via LLM mentioned in [#221](https://github.com/google/oss-fuzz-gen/issues/221)

To reduce the workload of manually triaging runtime crash, we leverage LLM to identify the cause of crash. We pass fuzz target code and crash information to LLM, ask LLM with designed prompts,and save the reponse from LLM. The crash information contains stack trace and sanitizer output. We can also pass related project code to LLM in the future.

## Conditions to LLM triaging

Currently, triaging runtime crash with LLM would be activated only when all the following conditions are met:

- Build successfully.
- Run successfully.
- Trigger crash.
- SemanticCheckResult is one of the following types:
  - `NO_SEMANTIC_ERR`
  - `FP_NEAR_INIT_CRASH`
  - `FP_TARGET_CRASH`
  - `FP_OOM`
  - `NULL_DEREF`
  - `SIGNAL`

For the SemanticCheckResult type range mentioned above, we will include 'NO_COV_INCREASE' in the future, which requires additional prompt design.

## Input to LLM triaging

To retrieve crash information from fuzz log, we add function `extract_crash_info` to class `SemanticCheckResult` in `experiment/fuzz_target_error.py` file. The retrieved information is stored in variable `crash_info` in class `RunResult`. The fuzz target code can be obtained from `result/output-ProjectName-FunctionName/fixed_targets` folder.

## Prompt design

We require that the LLM: 1) definitively ascertain whether the crash is due to errors within the fuzz target or results from a vulnerability in the project under test; 2) deliver a thorough analysis of the findings. Two triage prompts, `triage_priming.txt` and `triage_problem.txt`, are appended to `prompts/template_xml` folder. Three functions, `build_triage_prompt`, `_format_triage_priming`, and `_format_triage_problem`, are added to `llm_toolkit/prompt_builder.py` file. The generated triage prompt would be saved in `result/output-ProjectName-FunctionName/fixed_targets` folder.

### Prompt example

TODO

## LLM triaging

One function, `triage_crash`, is added to `experiment/evaluator.py` file. The core component of LLM triage, `crash_triage.py`, is appended to `llm_toolkit` folder. `crash_triage.py` mainly contains functions `llm_triage` and `apply_llm_triage`.

## Response from LLM triaging

One function, `parse_triage_response`, is appended to `llm_toolkit/output_parser.py` file. The generated triage response from LLM would be saved in `result/output-ProjectName-FunctionName/fixed_targets` folder.

### Response example

TODO