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
from tool.base_tool import BaseTool
from data_prep import introspector
import logging

logger = logging.getLogger(__name__)


class FuzzIntrospectorTool(BaseTool):
  """Calls FI API with params."""

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

  def _function_source(self, project_name: str, function_signature: str) -> str:

    """
    Retrieves a function's source from the fuzz introspector API,
      using the project's name and function's signature.

    Args:
        project_name (str): The name of the project.
        function_signature (str): The signature of the function.

    Returns:
        str: The source code of the function if found, otherwise an empty string.
    """

    function_code = introspector.query_introspector_function_source(project_name, function_signature)

    if function_code.strip():
      logger.info("Function with signature '%s' found and extracted.", function_signature)
    else:
      logger.error("Error: Function with signature '%s' not found in project '%s'.",
                   function_signature, project_name)

    return function_code

  def tutorial(self) -> str:
    raise NotImplementedError

  def execute(self, command: str) -> introspector.Any:
    raise NotImplementedError

