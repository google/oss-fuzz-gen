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

We require that the LLM: 1) definitively ascertain whether the crash is due to errors within the fuzz target or results from a vulnerability in the project under test; 2) deliver a thorough analysis of the findings. Two triage prompts, `triage_priming.txt` and `triage_problem.txt`, are appended to `prompts/template_xml` folder. Three functions, `build_triage_prompt`, `_format_triage_priming`, and `_format_triage_problem`, are added to `llm_toolkit/prompt_builder.py` file. The generated triage prompt would be saved in `result/output-ProjectName-FunctionName/fixed_targets/TargetName-triage` folder.

Below is a generated prompt example:

```plaintext
[{"role": "system", "content": "Given the following crash report and fuzz target, investigate the cause of the crash.\n"}, {"role": "user", "content": "Below is the crash report:\n<log>\n=================================================================\r\n\u001b[1m\u001b[31m==13==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000003a7 (pc 0x000000572ba3 bp 0x7ffd25f0ba10 sp 0x7ffd25f0b970 T0)\r\n\u001b[1m\u001b[0m==13==The signal is caused by a READ memory access.\r\n==13==Hint: address points to the zero page.\r\nSCARINESS: 10 (null-deref)\r\n    #0 0x572ba3 in finalizeTable /src/liblouis/liblouis/compileTranslationTable.c:4377:13\r\n    #1 0x570e1c in _lou_getTranslationTable /src/liblouis/liblouis/compileTranslationTable.c:5059:8\r\n    #2 0x56c574 in LLVMFuzzerTestOneInput /src/liblouis/tests/fuzzing/table_fuzzer.cc:11:50\r\n    #3 0x43de33 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15\r\n    #4 0x43d61a in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:514:3\r\n    #5 0x43ece9 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:757:19\r\n    #6 0x43f9b5 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:895:5\r\n    #7 0x42ed1f in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:912:6\r\n    #8 0x458372 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10\r\n    #9 0x7f72da84a082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 87b331c034a6458c64ce09c03939e947212e18ce)\r\n    #10 0x41f75d in _start (/out/table_fuzzer+0x41f75d)\r\n\r\nDEDUP_TOKEN: finalizeTable--_lou_getTranslationTable--LLVMFuzzerTestOneInput\r\nAddressSanitizer can not provide additional info.\r\nSUMMARY: AddressSanitizer: SEGV /src/liblouis/liblouis/compileTranslationTable.c:4377:13 in finalizeTable\r\n==13==ABORTING\r\nMS: 3 CMP-ChangeByte-InsertRepeatedBytes- DE: \"\\000\\000\\000\\001\"-; base unit: 9fe132914f92e1ad968c7b50f9c606d3922e86c6\r\n0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x23,0x20,0x5d,0x6b,0x6f,0x69,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x6f,0x4c,0x65,\r\n\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000# ]koi\\000\\000\\000\\001\\000\\000\\000oLe\r\nartifact_prefix='./'; Test unit written to ./crash-578f79fcf8db7fb291a77fb9c20abf8c01eff949\r\nBase64: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMgXWtvaQAAAAEAAABvTGU=\r\nstat::number_of_executed_units: 938\r\nstat::average_exec_per_sec:     0\r\nstat::new_units_added:          57\r\nstat::slowest_unit_time_sec:    0\r\nstat::peak_rss_mb:              46\r\n\n</log>\n\nBelow is the fuzz target:\n<code>\n#include <fuzzer/FuzzedDataProvider.h>\n#include <liblouis/internal.h>\n\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    FuzzedDataProvider stream(data, size);\n\n    // Consume a random length string\n    std::string table_name = stream.ConsumeRandomLengthString();\n\n    // Call the _lou_getTranslationTable function\n    const TranslationTableHeader *table_header = _lou_getTranslationTable(table_name.c_str());\n\n    // Perform some operations with the table_header if needed\n    // For example, checking if the table_header is not NULL\n    if (table_header != nullptr) {\n        // Do something with the table_header\n    }\n\n    // Return 0 to indicate successful execution\n    return 0;\n}\n</code>\n\nTriage the crash:\nFirstly, you must clearly determine whether the crash is caused by errors within the fuzz target, such as incorrect function usage, improper parameter initializations, missing setup steps, etc., or if it stems from a vulnerability in the project under test.\nSecondly, you are required to provide a comprehensive analysis of your findings.\n<solution>"}]
```

## LLM triaging

One function, `triage_crash`, is added to `experiment/evaluator.py` file. The core component of LLM triage, `crash_triage.py`, is appended to `llm_toolkit` folder. `crash_triage.py` mainly contains functions `llm_triage` and `apply_llm_triage`.

## Response from LLM triaging

One function, `parse_triage_response`, is appended to `llm_toolkit/output_parser.py` file. The generated triage response from LLM would be saved in `result/output-ProjectName-FunctionName/fixed_targets/TargetName-triage` folder.

Below is a reponse example:

```plaintext
### Triage Analysis:

1. **Crash Cause:** The crash occurred in the `finalizeTable` function at line 4377 of `compileTranslationTable.c`. The crash is a segmentation fault (SEGV) caused by a READ memory access at an unknown address.

2. **Fuzz Target Analysis:**
   - The fuzz target reads input data using `FuzzedDataProvider` and extracts a random length string as `table_name`.
   - It then calls the `_lou_getTranslationTable` function with `table_name` as input.
   - The crash happens during the execution of the fuzz target, specifically within the `_lou_getTranslationTable` function.

3. **Root Cause Analysis:**
   - The crash is likely due to a bug in the `_lou_getTranslationTable` function or its interaction with the provided `table_name`.
   - The fuzz target does not seem to have any obvious issues that could directly cause a crash, such as invalid memory accesses or incorrect function usage.

4. **Next Steps:**
   - To investigate further, you need to analyze the implementation of the `_lou_getTranslationTable` function in the `compileTranslationTable.c` file.
   - Look for potential issues such as NULL pointer dereferences, out-of-bounds memory accesses, or incorrect handling of input data.
   - Consider running the fuzz target with different inputs to see if the crash is consistently reproducible.
   - Use debugging tools like AddressSanitizer, Valgrind, or GDB to pinpoint the exact cause of the crash within the `_lou_getTranslationTable` function.

5. **Recommendations:**
   - Review the implementation of `_lou_getTranslationTable` function for any potential vulnerabilities.
   - Validate input data handling within the function to ensure it can handle all possible inputs gracefully.
   - Test the function with various inputs, including edge cases, to uncover any hidden issues.
   - Consider adding additional checks and error handling mechanisms to prevent crashes in case of unexpected input scenarios.

6. **Conclusion:**
   - The crash is most likely caused by an issue within the `_lou_getTranslationTable` function or its interaction with the provided input data.
   - Further investigation into the function's implementation and input handling is necessary to identify and fix the root cause of the crash.
```

## Additions within `results` folder

`result/output-ProjectName-FunctionName/fixed_targets/TargetName-triage` folder is created to store the generated prompt file and trirage rawoutput from LLM.