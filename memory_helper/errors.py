"""
memory_helper/errors.py
Classify compilation errors
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

import yaml

import logger

ANSI_ESC = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SHELL_NOISE = re.compile(
    r"^\s*(?:\+{1,2}\s?.*|pushd\b.*|popd\b.*|mkdir(?:\s|-p)\b.*|cp\b.*|zip\b.*|cd\b\s.*"
    r"|.*installing 'config/.*|\.\.\.\(truncated \d+ chars\)\.\.\."
    r"|sysctl: setting key \"vm\.mmap_rnd_bits\".*"
    r")\s*$",
    re.IGNORECASE,
)

ERROR_SIGNATURE = re.compile(
    r"(?i)(?:^|\W)("
    r"error:|fatal error:|undefined reference|collect2: error|ld: error|"
    r"linker command failed|cannot create executables|"
    r"FAILED:|ninja: build stopped|No rule to make target|"
    r"cmake error|make: \*\*\*.+Error|"
    r"command not found|syntax error|unexpected EOF|No such file or directory|"
    r"meson\.build:\d+:\d+: ERROR:"
    r")")

# Default maximum characters for error normalization to ensure consistency
# across vector search embeddings.
DEFAULT_NORM_MAX_CHARS = 3600


def _dedup_consecutive(lines: List[str]) -> List[str]:
  out: List[str] = []
  prev: Optional[str] = None
  for ln in lines:
    if ln != prev:
      out.append(ln)
      prev = ln
  return out


def _limit_include_stack(lines: List[str], max_keep: int = 4) -> List[str]:
  """ limit include stack """
  out: List[str] = []
  buf: List[str] = []

  def flush():
    if buf:
      out.extend(buf[:max_keep])
      buf.clear()

  for ln in lines:
    if ln.startswith("In file included from"):
      buf.append(ln)
    else:
      flush()
      out.append(ln)
  flush()
  return out


def _redact_paths_and_lines_keep_newlines(s: str) -> str:
  # Replace Unix-style and Windows-style paths with <PATH>, keep newlines.
  s = re.sub(r"/[^\s:]+(?:\.[A-Za-z0-9_]+)?", " <PATH> ", s)
  s = re.sub(r"[A-Za-z]:\\[^\s:]+", " <PATH> ", s)
  # Replace line numbers with <LINE>, keep the rest.
  s = re.sub(r":\d+(?=[:\s\)])", ":<LINE>", s)
  return s


def _squash_whitespace_per_line(lines: List[str]) -> List[str]:
  out: List[str] = []
  for ln in lines:
    ln = re.sub(r"\s+", " ", ln).strip()
    if ln:
      out.append(ln)
  return out


def normalize_err_text(stderr: str,
                       max_chars: int = DEFAULT_NORM_MAX_CHARS,
                       trial: Optional[int] = None) -> str:
  """Find normalized error text"""
  if not stderr:
    return ""

  txt = ANSI_ESC.sub("", stderr)
  lines = [ln for ln in txt.splitlines() if not SHELL_NOISE.match(ln)]
  lines = _limit_include_stack(lines, max_keep=4)
  lines = _dedup_consecutive(lines)

  # Find anchor before redaction to allow YAML patterns to match raw paths
  match_idx = None
  for i, ln in enumerate(lines):
    if ERROR_SIGNATURE.search(ln):
      match_idx = i
      break

  if match_idx is None:
    match_idx = find_anchor(lines, trial=trial)

  # Redact and squash
  redacted = _redact_paths_and_lines_keep_newlines("\n".join(lines))
  cleaned_lines = _squash_whitespace_per_line(redacted.splitlines())

  if match_idx is not None:
    pre, post = 40, 40
    start = max(0, match_idx - pre)
    end = min(len(lines), match_idx + post + 1)
    focused_raw = "\n".join(lines[start:end])
    focused = _redact_paths_and_lines_keep_newlines(focused_raw)
    focused = "\n".join(_squash_whitespace_per_line(focused.splitlines()))
  else:
    focused = "\n".join(cleaned_lines)

  # Emergency fallback
  if not focused.strip() and stderr:
    focused = f"Raw log tail: {stderr[-200:].strip()}"

  if len(focused) > max_chars:
    if match_idx is not None:
      overflow = len(focused) - max_chars
      snap = focused.find("\n", overflow)
      cut = snap if snap != -1 else overflow
      focused = f"...(truncated {cut} chars)...\n" + focused[cut:]
    else:
      # No error anchor: cut from the START to keep the TAIL at a line boundary.
      overflow = len(focused) - max_chars
      snap = focused.find("\n", overflow)
      cut = snap if snap != -1 else overflow
      focused = f"...(truncated {cut} chars)...\n" + focused[cut:]


  return focused


def normalize_err_text_fallback(stderr: str, max_chars: int = DEFAULT_NORM_MAX_CHARS) -> str:
  """Find normalized error text fallback"""
  if not stderr:
    return ""

  txt = ANSI_ESC.sub("", stderr)
  lines = [ln.rstrip() for ln in txt.splitlines() if ln.strip()]
  lines = [ln for ln in lines if "vm.mmap_rnd_bits" not in ln]
  if not lines:
    return ""

  redacted = _redact_paths_and_lines_keep_newlines("\n".join(lines))
  cleaned_lines = _squash_whitespace_per_line(redacted.splitlines())
  focused = "\n".join(cleaned_lines)

  if len(focused) > max_chars:
    # Snap to the nearest preceding newline so we never cut mid-flag or mid-word.
    cut = focused.rfind("\n", 0, max_chars)
    if cut == -1:
      cut = max_chars
    focused = focused[:cut] + f" ...(truncated {len(focused) - cut} chars)..."

  return focused


STDERR_PLAIN = re.compile(r"(?s)<stderr>(.*?)</stderr>")


def stderr_blocks(log: str) -> List[str]:
  """Find stderr block"""
  return [m.group(1).strip() for m in STDERR_PLAIN.finditer(log)]


def latest_stderr_block(log: str) -> Optional[str]:
  """Get latest stderr block"""
  blocks = stderr_blocks(log)
  if not blocks:
    return None

  # Prefer the last block that actually looks like a compiler/linker error.
  for b in reversed(blocks):
    if ERROR_SIGNATURE.search(b):
      return b
  # Fallback: last non-empty block, then last block.
  for b in reversed(blocks):
    if b.strip():
      return b
  return blocks[-1]


class ErrorPatternClassifier:
  """Classify raw error text using regex patterns from error_patterns.yaml."""

  def __init__(self, error_db_path: Optional[str] = None) -> None:
    # If no path is provided, default to error_patterns.yaml next to this file.
    if error_db_path is None:
      here = os.path.dirname(os.path.abspath(__file__))
      error_db_path = os.path.join(here, "error_patterns.yaml")

    with open(error_db_path, "r", encoding="utf-8") as f:
      self.error_db: Dict[str, Any] = yaml.safe_load(f) or {}

  def classify(
      self,
      error_text: str,
      trial: int = 1,
  ) -> Optional[Dict[str, Any]]:
    """Return the first matching line's classification
    (bottom-up) over raw error text."""
    error_text = error_text or ""
    lines = error_text.splitlines()
    total_lines = len(lines)

    for rev_idx, line in enumerate(reversed(lines), start=1):
      line_no = total_lines - rev_idx + 1
      for error_type, data in self.error_db.items():
        for pattern in data.get("patterns", []):
          try:
            if re.search(pattern, line, re.IGNORECASE):
              logger.info(
                  f"[DEBUG] Line {line_no}: matched {error_type}",
                  trial=trial,
              )
              logger.info(
                  f"         └─ {line.strip()}",
                  trial=trial,
              )
              return {
                  "type": error_type,
                  "good": data.get("good", []),
                  "bad": data.get("bad", []),
                  "matched_line": line.strip(),
                  "line_no": line_no,
              }
          except re.error:
            logger.warning(
                f"[WARN] invalid regex in error_patterns.yaml: {pattern}",
                trial=trial,
            )
    return None

  def find_anchor_idx(self, lines: List[str]) -> Optional[int]:
    """Find the index of the first line that matches any pattern in the YAML."""
    for i, line in enumerate(lines):
      for data in self.error_db.values():
        for pattern in data.get("patterns", []):
          try:
            if re.search(pattern, line, re.IGNORECASE):
              return i
          except re.error:
            continue
    return None


# --- Global helper-------------------------------------

_GLOBAL_ERROR_CLASSIFIER: Optional[ErrorPatternClassifier] = None


def _get_global_classifier() -> ErrorPatternClassifier:
  """Lazy-initialize a singleton ErrorPatternClassifier."""
  global _GLOBAL_ERROR_CLASSIFIER
  if _GLOBAL_ERROR_CLASSIFIER is None:
    _GLOBAL_ERROR_CLASSIFIER = ErrorPatternClassifier()
  return _GLOBAL_ERROR_CLASSIFIER


def find_anchor(lines: List[str], trial: Optional[int] = None) -> Optional[int]:
  """Find the index of the first matching line using YAML patterns."""
  clf = _get_global_classifier()
  return clf.find_anchor_idx(lines)


def classify_error(
    error_text: str,
    trial: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
  """Convenience wrapper: classify raw error text using error_patterns.yaml.

    This is what other components (e.g., MemoryPrototyper) should call:
        from memory_helper import classify_error
        info = classify_error(raw_error, trial=trial)
    """
  trial = -1 if trial is None else trial
  clf = _get_global_classifier()
  return clf.classify(error_text, trial=trial)
