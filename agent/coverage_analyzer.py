# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""An LLM agent to analyze and provide insight of a fuzz target's low coverage.
Use it as a usual module locally, or as script in cloud builds.
"""
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from experiment.workdir import WorkDirs
from llm_toolkit import prompt_builder
from llm_toolkit.prompt_builder import CoverageAnalyzerTemplateBuilder
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, CoverageResult, Result, RunResult
from tool.container_tool import ProjectContainerTool


class CoverageAnalyzer(BaseAgent):
  """The Agent to refine a compilable fuzz target for higher coverage."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    last_result = results[-1]
    benchmark = last_result.benchmark

    if not isinstance(last_result, RunResult):
      logger.error('The last result in %s is not RunResult: %s',
                   self.name,
                   results,
                   trial=self.trial)
      return Prompt()

    builder = CoverageAnalyzerTemplateBuilder(self.llm, benchmark, last_result)
    prompt = builder.build(example_pair=[],
                           tool_guides=self.inspect_tool.tutorial(),
                           project_dir=self.inspect_tool.project_dir)
    # TODO: A different file name/dir.
    prompt.save(self.args.work_dirs.prompt)

    return prompt

  def _container_handle_conclusion(self, cur_round: int, response: str,
                                   coverage_result: CoverageResult,
                                   prompt: Prompt) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    conclusion = self._parse_tag(response, 'conclusion')
    if not conclusion:
      return prompt
    logger.info('----- ROUND %02d Received conclusion -----',
                cur_round,
                trial=self.trial)

    coverage_result.improve_required = conclusion.strip().lower() == 'true'
    coverage_result.insight = self._parse_tag(response, 'insights')
    coverage_result.suggestions = self._parse_tag(response, 'suggestions')

    return None

  def _container_tool_reaction(
      self, cur_round: int, response: str, run_result: RunResult,
      coverage_result: CoverageResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    del run_result
    prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])

    prompt = self._container_handle_bash_commands(response, self.inspect_tool,
                                                  prompt)
    # Only report conclusion when no more bash investigation is required.
    if not prompt.gettext():
      # Then build fuzz target.
      prompt = self._container_handle_conclusion(cur_round, response,
                                                 coverage_result, prompt)
      if prompt is None:
        # Succeeded.
        return None

    # Finally check invalid responses.
    if not response or not prompt.get():
      prompt = self._container_handle_invalid_tool_usage(
          self.inspect_tool, cur_round, response, prompt)
      prompt.append("""
Provide your verified conclusion with analysis insights and suggestions in the following format:
  * A clean Boolean value (True or False) representing your analysis conclusion on whether code coverage needs improvement.
  * Analysis insights of the low coverage, as detailed as possible with source code evidence.
  * Suggestions to improve the code coverage, this can be text description, code snippet, or the full refined fuzz target.

For example:
<conclusion>
True
</conclusion>
<insights>
The low coverage comes from the fact that the current fuzz target exercises only one very narrow code path—in this case, a single call to {FUNCTION_SIGNATURE} with naive argument derived directly from the input data. This approach misses many branches within the {PROJECT} because:

* Single Argument Limitation: By always providing a unprocessed and naive argument, the fuzz target never tests the handling of complex values, which likely involves additional logic (e.g., iterating over the array, handling edge cases like empty or very long tokens, and validating numeric conversions for lengths).

* Lack of Input Variation: Since the fuzzer input is used verbatim as the only command argument, many conditional paths (e.g., those triggered by specific token contents or argument counts) remain untested.

* Untested Functions: Only the function-under-test ({FUNCTION_SIGNATURE}) is being invoked. {PROJECT} has several functions (e.g., functions from {PROJECT_DIR}) that are necessary or conventional to invoke before the function as preparations, but their logic isn’t reached by the current target.

To increase code coverage, I need the following improvements:

* Fine-grained input preprocessing.
Instead of using naive values like NULL or constant strings, or passing the entire input as a single argument, split it into multiple tokens of suitable sizes and content. This will allow the fuzz target to test scenarios where:

The function requires tailored input (value, format, data structures, etc.).

Edge cases occur (e.g., empty tokens, very short or very long tokens).

Fuzz Additional Functions:
To further increase coverage in the {PROJECT} library, I will need to add other functions like:

Function X and Y from {PROJECT} to prepare the program state before invoking {FUNCTION_SIGNATURE}.

Function Z if available, or other parameter preparation functions to better initialize function parameters based on the data generated by fuzzer.
</insights>
<suggestions>
Create Proper parameters
Instead of using a dummy context (or no context at all), allocate and initialize each parameter with the expected type and content. Typically, this structure embeds a regular `type_a` plus additional fields. I can either try to call `function_a` or manually allocate the structure and initialize its members. This includes initializing the internal `type_b` (via `function_b`) which `{FUNCTION_SIGNATURE}` uses to parse incoming data.

Simulate Data Reception
Feed the fuzz input into the {FUNCTION_SIGNATURE} by calling something like:
```
# Code snippet.
```
This makes sure that when {FUNCTION_SIGNATURE} is called, it has some data to process. I can then observe how the parser behaves with various inputs (valid replies, malformed data, etc.).

Call `function_c`
With the context properly set up, invoking `function_c` will prepare the program states for `{FUNCTION_SIGNATURE}` to traverse more code paths (error handling, reply parsing, etc.). This is where more of {PROJECT}’s logic will be exercised.

Optionally Vary Context Fields
I will also consider fuzzing some of the fields within parameters to trigger different branches.

Here is the revised fuzz target:
```
# New fuzz target
```
</suggestions>
""")

    return prompt

  def execute(self, result_history: list[Result]) -> AnalysisResult:
    """Executes the agent to analyze the root cause to the low coverage."""
    WorkDirs(self.args.work_dirs.base, keep=True)
    last_result = result_history[-1]
    assert isinstance(last_result, RunResult)

    logger.info('Executing %s', self.name, trial=last_result.trial)
    benchmark = last_result.benchmark
    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
    cur_round = 1
    coverage_result = CoverageResult()
    prompt = self._initial_prompt(result_history)

    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt and cur_round < self.max_round:
        response = self.chat_llm(cur_round,
                                 client=client,
                                 prompt=prompt,
                                 trial=last_result.trial)
        prompt = self._container_tool_reaction(cur_round, response, last_result,
                                               coverage_result)
        cur_round += 1
    finally:
      # Cleanup: stop and remove the container
      logger.debug('Stopping and removing the inspect container %s',
                   self.inspect_tool.container_id,
                   trial=last_result.trial)
      self.inspect_tool.terminate()

    analysis_result = AnalysisResult(
        author=self,
        run_result=last_result,
        coverage_result=coverage_result,
        chat_history={self.name: coverage_result.to_dict()})
    return analysis_result
