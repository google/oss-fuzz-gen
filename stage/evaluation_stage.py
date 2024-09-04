"""The Evaluation Stage class for measuring code coverage and capture run-time
crashes of the fuzz targets. This stage will run the fuzz target with OSS-Fuzz
infra and report its code coverage and crashes."""
from results import Result
from stage.base_stage import BaseStage


class EvalationStage(BaseStage):
  """Evaluates fuzz targets and build scripts. This stage takes a fuzz target
  and its build script, runs them locally or on the cloud with OSS-Fuzz infra,
  and outputs code coverage report and run-time crash information for later
  stages to analyze and improve on. It OSS-Fuzz infra to perform these tasks."""

  def execute(self, result_history: list[Result]) -> Result:
    # A placeholder for now.
    return result_history[-1]
