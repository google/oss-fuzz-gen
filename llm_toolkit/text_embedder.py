import sys
from typing import Any, Callable, Optional, Type

from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
from google.api_core.exceptions import InvalidArgument

from llm_toolkit.models import VertexAIModel

class VertexEmbeddingModel (VertexAIModel):
  """Vertex AI Embedding model."""
  _vertex_ai_model = 'text-embedding-004'
  name = "text-embedding-004"
  def get_model(self) -> Any:
    # OVERRIDE: We must use TextEmbeddingModel, not GenerativeModel
    return TextEmbeddingModel.from_pretrained(self._vertex_ai_model)

  def embed_texts_error_norm(
      self,
      texts: list[str],
      batch_size: int = 8,
      per_item_soft_cap_chars: int = 4000,
      hard_single_item_min_chars: int = 128,
  ) -> list[list[float]]:
    """
    Embed a list of texts. Handles token limits via binary search truncation.
    """
#    self._ensure_model_loaded()

    processed: list[tuple[int, str]] = []
    placeholders: dict[int, list[float]] = {}

    # 1. Pre-process: strip, handle empty, apply soft cap
    for idx, t in enumerate(texts):
      t = (t or "").strip()
      if not t:
        placeholders[idx] = []
        continue
      if len(t) > per_item_soft_cap_chars:
        t = t[:per_item_soft_cap_chars]
      processed.append((idx, t))

    # 2. Process in batches
    i = 0
    n = len(processed)
    while i < n:
      chunk = processed[i: i + batch_size]
      self._embed_chunk_or_split(chunk, placeholders, hard_single_item_min_chars)
      i += batch_size

    # 3. Reassemble in original order
    return [placeholders.get(k, []) for k in range(len(texts))]

  def _embed_chunk_or_split(
      self,
      chunk: list[tuple[int, str]],
      placeholders: dict[int, list[float]],
      hard_single_item_min_chars: int,
  ) -> None:
    """Helper: tries to embed chunk; performs binary search on token errors."""

    def try_once(orig_idx: int, s: str) -> Optional[list[float]]:
      try:
        return self._embed_single_text(s)
      except Exception as inner_e:
        imsg = str(inner_e)
        # Heuristic: Detect token limit errors from Vertex AI
        # Vertex AI often raises InvalidArgument (400) for context length
        is_token_err = (
            "400" in imsg or
            "token" in imsg or
            "too long" in imsg or
            isinstance(inner_e, InvalidArgument)
        )

        if is_token_err:
          # Return None to signal "try truncating"
          return None

        print(
          f"[WARN] Single-item embed failed (non-token): {inner_e}; "
          f"filled [] for index {orig_idx}.",
          file=sys.stderr,
        )
        return []

    for orig_idx, txt in chunk:
      # First attempt: full text
      quick = try_once(orig_idx, txt)
      if quick is not None:
        placeholders[orig_idx] = quick
        continue

      # Binary search truncation
      lo, hi = hard_single_item_min_chars, len(txt)
      best_vec: Optional[list[float]] = None
      attempts = 0

      while lo <= hi and attempts < 12:
        attempts += 1
        mid_len = (lo + hi) // 2
        trial = txt[:mid_len]
        got = try_once(orig_idx, trial)

        if got is None:
          # Still too long -> move left (shorter text)
          hi = mid_len - 1
        else:
          # Success -> record result, try moving right (longer text)
          best_vec = got
          lo = mid_len + 1

      if best_vec is None:
        placeholders[orig_idx] = []
        print(
          f"[WARN] Embedding too large after truncation; index {orig_idx} set to [].",
          file=sys.stderr,
        )
      else:
        placeholders[orig_idx] = best_vec

  def _embed_single_text(self, text: str) -> list[float]:
    """Wraps the Vertex AI call. Returns vector or raises exception."""
    # We reuse the specific task type from your original logic
    model = self.get_model()
    inputs = [TextEmbeddingInput(text=text, task_type="RETRIEVAL_DOCUMENT")]

    # This call might raise exceptions (handled in _embed_chunk_or_split)
    embeddings = model.get_embeddings(inputs)

    if not embeddings:
      return []

    vec = embeddings[0].values

    # Ensure plain Python list
    return list(vec) if vec is not None else []
