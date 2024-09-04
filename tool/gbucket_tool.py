"""A tool for LLM agents to interact within Google Cloud Buckets."""
from tool.base_tool import BaseTool


class GBucketTool(BaseTool):
  """Fetches file content from GBucket."""

  def human_targets(self, project: str) -> list[str]:
    """Human written fuzz targets of |project|."""
    # A placeholder.
    raise NotImplementedError

  def llm_targets(self, project: str) -> list[str]:
    """LLM generated fuzz targets of |project|."""
    # A placeholder.
    raise NotImplementedError
