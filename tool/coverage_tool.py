

import os
from typing import Any
import logging

from experiment.benchmark import Benchmark
from experiment.textcov import Textcov
from tool.base_tool import BaseTool


logger = logging.getLogger(__name__)

class CoverageTool(BaseTool):
  """A tool that provides LLM agents access to code coverage reports."""

  def __init__(self,
               benchmark: Benchmark,
               coverage_report_path: str) -> None:
    super().__init__(benchmark)
    if coverage_report_path and os.path.exists(coverage_report_path):
      with open(coverage_report_path, 'rb') as file:
        self.coverage_report = Textcov.from_file_raw(file)
    else:
      self.coverage_report = None

  def tutorial(self) -> str:
    """Constructs a tool guide tutorial for LLM agents."""
    return self._get_tutorial_file_content('coverage_tool.txt')

  def execute(self, command: str) -> Any:
    """Executes the coverage tool based on the command."""
    if not self.coverage_report:
      return 'Coverage report not available.'
    return self.coverage_report.get_coverage_reports(command)