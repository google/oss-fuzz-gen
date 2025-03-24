"""Standard coverage calculation functions to ensure consistency."""

from experiment import textcov


def calculate_coverage(cov: textcov.Textcov, linked_lines: int) -> float:
  """Calculates coverage according to formula: Cov(f) / Linked(f)."""
  if not linked_lines:
    return 0.0
  return cov.covered_lines / linked_lines


def calculate_coverage_improvement(new_cov: textcov.Textcov,
                                   existing_cov: textcov.Textcov,
                                   union_linked_lines: int) -> float:
  """Calculates coverage improvement: [Cov(f1) - Cov(f0)] / [Linked(f1 ∪ f0)]."""
  if not union_linked_lines:
    return 0.0

  # Make a copy to avoid modifying the original
  diff_cov = new_cov.copy()
  diff_cov.subtract_covered_lines(existing_cov)

  return diff_cov.covered_lines / union_linked_lines
