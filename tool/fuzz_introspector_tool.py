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
"""A tool for LLM agents to interact within Fuzz Introspector to access
the project's information."""
import logging

from data_prep import introspector
from experiment import benchmark as benchmarklib
from tool import base_tool

logger = logging.getLogger(__name__)


class FuzzIntrospectorTool(base_tool.BaseTool):
  """Calls FI API with params."""

  def __init__(self, benchmark: benchmarklib.Benchmark, name: str = ''):
    super().__init__(benchmark, name)
    self.project_functions = None

  def _source_code(self, filename: str, start_line: int, end_line: int) -> str:
    """Calls the source code API of the Fuzz Introspector."""
    # A placeholder
    raise NotImplementedError

  def _xrefs(self, function_signature: str) -> list[str]:
    """Calls the xrefs API of the Fuzz Introspector."""
    # A placeholder
    raise NotImplementedError

  def _types_def(self, function_signature: str) -> list[str]:
    """Calls the type API of the Fuzz Introspector."""
    # A placeholder
    raise NotImplementedError

  def _function_signature(self, function_name: str) -> str:
    """Calls the function signature API of the Fuzz Introspector."""
    # A placeholder
    raise NotImplementedError

  def function_source_with_signature(self, project_name: str,
                                     function_signature: str) -> str:
    """
    Retrieves a function's source from the fuzz introspector API,
      using the project's name and function's signature.

    Args:
        project_name (str): The name of the project.
        function_signature (str): The signature of the function.

    Returns:
        str: Source code of the function if found, otherwise an empty string.
    """

    logger.info("Retrieving function source for '%s' in project '%s'.",
                function_signature, project_name)

    function_code = introspector.query_introspector_function_source(
        project_name, function_signature)

    if function_code.strip():
      logger.info("Function with signature '%s' found and extracted.",
                  function_signature)
    else:
      logger.error(
          "Error: Function with signature '%s' not found in project '%s'.",
          function_signature, project_name)

    return function_code

  def function_source_with_name(self, project_name: str,
                                function_name: str) -> str:
    """
    Retrieves a function's source from the fuzz introspector API,
      using the project's name and function's name.
      This function first retrieves the list of all
      functions in the project, so it can get the function's signature.
      Then it uses the function's signature to retrieve the source code.

    Args:
        project_name (str): The name of the project.
        function_name (str): The name of the function.

    Returns:
        str: Source code of the function if found, otherwise an empty string.
    """

    logger.info("Retrieving function source for '%s' in project '%s'.",
                function_name, project_name)

    if self.project_functions is None:
      logger.info(
          "Project functions not initialized. Initializing for project '%s'.",
          project_name)
      functions_list = introspector.query_introspector_all_functions(
          project_name)
      logger.info("Functions list:\n%s", functions_list)
      if functions_list:
        self.project_functions = {
            func["debug_summary"]["name"]: func
            for func in functions_list
            if "debug_summary" in func and "name" in func["debug_summary"]
        }
      else:
        self.project_functions = None

    if (self.project_functions is None or
        function_name not in self.project_functions):
      logger.error("Error: Required function not found for project '%s'.",
                   project_name)
      return ""

    function_signature = self.project_functions[function_name][
        "function_signature"]

    return self.function_source_with_signature(project_name, function_signature)

  def tutorial(self) -> str:
    raise NotImplementedError

  def execute(self, command: str) -> introspector.Any:
    raise NotImplementedError
