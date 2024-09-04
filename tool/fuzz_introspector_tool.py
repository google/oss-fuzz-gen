"""A tool for LLM agents to interact within Fuzz Introspector to access
the project's information."""
from tool.base_tool import BaseTool


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
