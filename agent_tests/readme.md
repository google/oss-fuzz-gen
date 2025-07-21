# A Test Framework for OSS-Fuzz-Gen Agents

This is a test framework designed to enable developers test individual agents or a sequence of agents in OSS-Fuzz-Gen without the need for running full experiments.

## Why this framework?
This will enable OSS-Fuzz-Gen developers to make small changes in an agent's design or prompt and quickly evaluate if the change had the desired effect.
For example, a developer can modify the Coverage Analyzer to use previous coverage report and evaluate this change without running a full experiment.

Without this framework, evaluating this change would have required running an experiment involving several cycles of the Function Analyzer, Prototyper and Execution Stage until no crash occurs and the Coverage Analyzer is invoked.
This framework allows the developer to skip these steps, thereby saving time and associated LLM API expenses.

## How it works
OSS-Fuzz-Gen uses a pipeline design where, agents are stacked in a pipeline and executed using the results obtained from previously executed agents.
This framework is based on this pipeline design, but allows the developer to specify the list of agents in the pipeline, and a mock list of results from any previously "executed" agents.
This involves the following steps:
1. The developer provides a list of agents to be tested and any necessary files for initializing the test environment.
2. The framework retrieves the AgentTest class for the first agent in the list and uses this to initialize the state and create the result list.
3. The framework interatively calls the agents in the list using the created result list and appends their result after execution to the result list.
4. Finally, after all agents execute, the framework writes the list of results to an output file.

## How to test an agent
Agents can be tested using the command:
`python3 -m agent_tests.agent_test [args]`

The full list of arguments can be obtained using the --help flag.
`python3 -m agent_tests.agent_test --help`

Currently, this framework only supports testing the agents on a single benchmark.

The compulsory arguments to include are:
| Argument | Purpose |
|----------|---------|
| -y | The path to the benchmark yaml file containing the function to test |
| -f | The name of the function in the benchmark yaml file to test. This name should be copied from the yaml file |
| -p | A comma-separated list of agents (+ ExecutionStage) to test. Each agent name should correspond to the name of the agent's class. ExecutionStage can be provided in this list to include fuzzer execution. |

In addition, testing some agents involve additional arguments.
| Argument | Purpose |
|----------|---------|
| -pf | The path to a file containing a previous prompt for the first agent in the pipeline. This path should be copied from the report of a previous OSS-Fuzz-Gen experiment. Details from this file are used to reconstruct the result list for specific agents. |
| -npf | This flag should be passed if testing an agent that does not require a prompt file. |
| -afp | A path to a directory containing additional files needed by any agent under test. These files can be retrieved from the experiment directory of a previous experiment. |

Example CLI commands:
1. This command tests the Function Analyzer, Prototyper and Execution Stage in sequence.
```
python3 -m agent_tests.agent_test -y benchmark-sets/analyzer-tests-1/astc-encoder.yaml -f _Z20symbolic_to_physicalRK21block_size_descriptorRK25symbolic_compressed_blockPh -p FunctionAnalyzer,Prototyper,ExecutionStage -npf -of /usr/local/google/home/pamusuo/summer25/oss-fuzz
```

2. This command tests the Context Analyzer using the copy of a prompt from a previous experiment.
```
python3 -m agent_tests.agent_test -y benchmark-sets/analyzer-tests-1/libsndfile.yaml -f sf_open -p ContextAnalyzer -pf agent_tests/prompt_files/context-analyzer-01.txt -of /usr/local/google/home/pamusuo/summer25/oss-fuzz
```

3. This command tests the Crash Analyzer using a prompt and a path to a file containing the fuzz target, build script and crashing input.
```
python3 -m agent_tests.agent_test -y benchmark-sets/analyzer-tests-1/libsndfile.yaml -f sf_open -p CrashAnalyzer -pf agent_tests/prompt_files/crash-analyzer-01.txt -afp agent_tests/run_result_files/ -of /usr/local/google/home/pamusuo/summer25/oss-fuzz
```

## How to setup tests for an agent

Agents in OSS-Fuzz-Gen are designed to expect certain files to exist and previous results to have specific characteristics before they can execute correctly.
For example, the Crash Analyzer requires the existence of an artifact file that caused the crash, and a RunResult in its result list containing a crash and error stacktrace.

Hence, to test an agent directly, these required files and result object should be created and placed in the correct location.

This framework provides the `BaseAgentTest` base abstract class and the `setup_initial_result_list` method to reconstruct the necessary state and the initial result list.

To test a new agent directly, you should follow the following steps:
1. Create a new class that extends `BaseAgentTest` and implements `setup_initial_result_list`.
2. Review the implementation of the target agent to identify the data or files from the `last_result` object that it uses. Identify how these objects can be recreated or extracted from a previous experiment report. For example, since many of these data are added to the agent's prompt, they can also be extracted from the prompt of a previous execution.
3. In `setup_initial_result_list`, create any necessary files and initialize result objects with the necessary fields.
4. If additional files are needed, update `parse_args` function in `agent_test.py` with new arguments that will point to these files.
5. Add the agent and the corresponding `BaseAgentTest` to the list of supported agents in `agent_test.py`.

The necessary BaseAgentTest subclasses have been developed for FunctionAnalyzer, CrashAnalyzer, ContextAnalyzer and ExecutionStage.
