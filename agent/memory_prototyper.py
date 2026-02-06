"""
Prototyper that can retrieve past error message and patch history
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import logger
from agent.prototyper import Prototyper  # existing Prototyper
from llm_toolkit import prompt_builder
from llm_toolkit.prompts import Prompt
from llm_toolkit.text_embedder import VertexEmbeddingModel
from memory_helper.cloudsql import (cloud_sql_connect_smart,
                                    knn_search_error_full_with_norm,
                                    maybe_register_successful_fix,
                                    update_stats_from_buffer)
from results import BuildResult, Result

MAX_CANDIDATES = 5
CANDIDATE_PREVIEW_LEN = 400


class MemoryPrototyper(Prototyper):
  """Prototyper + error memory + stats + online updater with patch capture.

  Behaviour summary:

    - On build failure:
        * We query Cloud SQL (KNN over normalized error text).
        * An LLM "planner" chooses at most one candidate entry to reuse.
        * We inject that entry as a <memory hint> into the next fixer prompt.

    - Stats:
        * For each retrieved entry id, we buffer:
              retrieved, attempted, success,
              retrieved_project, attempted_project, success_project
          in `_stats_buffer`, and flush them into the `stats` table when a
          benchmark is successfully fixed.

    - Online updater:
        * For the last failing round, we remember:
              - whether KNN had hits (`_last_round_had_hits`),
              - whether the planner actually attempted to use an entry
                (`_last_attempted_entry_id`),
              - the raw + normalized error text we queried on, and
              - the fuzz target / build script sources used to craft the fixer
                prompt (`_prev_*_for_diff`).
        * If a subsequent fixer-only round succeeds and the planner chose NULL
          (no entry used), we treat this as a new "successful fix episode":
              - we compute a patch (build diff or fuzz target text),
              - extract a short natural-language fix summary from chat history,
              - and call `maybe_register_successful_fix()` to insert a new row
                into `entries` (with dedup based on cosine distance).
  """

  def __init__(self, *args, **kwargs) -> None:
    super().__init__(*args, **kwargs)
    # stats_buffer[id] = {
    #   "retrieved": int,
    #   "attempted": int,
    #   "success": int,
    #   "retrieved_project": int,
    #   "attempted_project": int,
    #   "success_project": int,
    # }
    self._stats_buffer: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {
            "retrieved": 0,
            "attempted": 0,
            "success": 0,
            "retrieved_project": 0,
            "attempted_project": 0,
            "success_project": 0,
        })
    # Track the last entry the planner actually attempted to use.
    # If planner chose NULL, this stays None.
    self._last_attempted_entry_id: Optional[str] = None
    self._last_attempted_project_match: bool = False

    # Updater-related state:
    # - Whether the last failing round had any retrieval hits.
    # - The raw and normalized error text we queried for in that round.
    self._last_round_had_hits: bool = False
    self._last_raw_error_text: str = ""
    self._last_normalized_error: str = ""

    # For reconstructing patch_text from the last failing round to the success:
    # We snapshot the "old" sources right before we hand them to the fixer.
    self._prev_fuzz_target_for_diff: str = ""
    self._prev_build_script_for_diff: str = ""

    # Cache raw LLM responses so we can always mine <conclusion>/<reason>
    # from the same response that produced the final fuzz target / build script.
    self._chat_blocks: List[str] = []
    self.text_embedding_model = VertexEmbeddingModel(
        ai_binary=self.args.ai_binary,
        max_tokens=2048,  # Required by base __init__, but ignored by logic
        num_samples=1,  # Required by base __init__, but ignored by logic
        temperature=0.0  # Required by base __init__, but ignored by logic
    )

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """
    we do a DB connection check before prompt
    to delete in real environment
    """
    try:
      with cloud_sql_connect_smart() as conn:
        with conn.cursor() as cursor:
          cursor.execute("SHOW TABLES")
          result_sql = cursor.fetchall()
          logger.info(
              f"connection successful, query returned:"
              f" {result_sql} \n continue",
              trial=results[-1].trial)
    except Exception as e:
      logger.error(
          f"SQL connection fail, early abort, connection error message is: {e}",
          trial=results[-1].trial)
      raise RuntimeError(
          "Agent execution aborted: Database is unreachable.") from e
    return super()._initial_prompt(results)

  def chat_llm(self, *args, **kwargs) -> str:
    """Wrapper around Prototyper.chat_llm that also caches raw responses.

    We rely on this cache during online updating, instead of assuming
    BuildResult.chat_history is always populated for the successful round.
    """
    text = super().chat_llm(*args, **kwargs)
    if text:
      self._chat_blocks.append(text)
    return text

  def smart_truncate_log(self, text: str, max_chars: int = 15000) -> str:
    """Intelligently truncate compilation log,
    keeping the most relevant parts."""
    if len(text) <= max_chars:
      return text

    # If we have <stderr> tags, prioritize keeping them
    stderr_start = text.find("<stderr>")
    stderr_end = text.rfind("</stderr>")

    if stderr_start != -1 and stderr_end != -1:
      stderr_content = text[stderr_start:stderr_end + 9]  # Include tags

      # If stderr fits, keep it and add context from end of log
      if len(stderr_content) < max_chars:
        remaining_chars = max_chars - len(stderr_content)
        # Take the tail of the log for context (e.g. build summary)
        tail_content = text[-remaining_chars:]
        return (f"...[truncated]...\n{stderr_content}\n"
                f"...[context]...\n{tail_content}")
      # If stderr is too big, keep the
      # end of stderr (most likely place for error)
      return f"...[truncated]...\n{stderr_content[-max_chars:]}"

    # Fallback to standard tail truncation
    return f"...[truncated]...\n{text[-max_chars:]}"

  def _get_confidence_note(self, plan: dict) -> str:
    """Returns a note explanation based on the confidence score."""
    confidence = plan.get('confidence_level', 0)
    if confidence >= 3:
      return "Note: This fix was verified to resolve the error completely."
    if confidence == 2:
      return ("Note: This fix was verified to change the error type "
              "(progress made), but may not fully resolve the issue.")
    return "Note: This fix has uncertain confidence."

  # -------------------- internal helpers (stats + updater) --------------------

  def _bump_stats(
      self,
      entry_id: str,
      *,
      retrieved: int = 0,
      attempted: int = 0,
      success: int = 0,
      retrieved_project: int = 0,
      attempted_project: int = 0,
      success_project: int = 0,
  ) -> None:
    """Increment buffered stats for a given entry ID."""
    buf = self._stats_buffer[entry_id]
    buf["retrieved"] += retrieved
    buf["attempted"] += attempted
    buf["success"] += success
    buf["retrieved_project"] += retrieved_project
    buf["attempted_project"] += attempted_project
    buf["success_project"] += success_project

  def unified_diff_text(
      self,
      old: str,
      new: str,
      old_name: str = "build.sh",
      new_name: str = "build.sh",
  ) -> str:
    """Return a unified diff between two build scripts (or arbitrary text).

    This mirrors the offline ingestion logic in build_entries_from_logs.py:
    we always normalise line endings and ensure a trailing newline before
    feeding text into difflib.unified_diff.
    """
    import difflib

    if not old.endswith("\n"):
      old = old + "\n"
    if not new.endswith("\n"):
      new = new + "\n"

    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=old_name,
            tofile=new_name,
            lineterm="",
        ))

  def _extract_fix_action_from_chat(self, build_result: BuildResult) -> str:
    """Try to pull a short natural-language fix summary from chat_history.

    Preference order:
      1) <conclusion> ... </conclusion>
      2) <reason> ... </reason>

    We *do not* rely on specific channel names (PrototyperFixer/Fixer/etc.).
    Instead we scan all chat_history values, treating them as a list of blocks
    ordered by insertion; we then search from newest block backwards.
    """
    blocks: List[str] = []

    # First, prefer the raw LLM outputs we recorded via chat_llm.
    if self._chat_blocks:
      blocks.extend(self._chat_blocks)

    # Also include anything in build_result.chat_history as a fallback.
    chat = getattr(build_result, "chat_history", {}) or {}
    if chat:
      for v in chat.values():
        if isinstance(v, str) and v:
          blocks.append(v)
        elif isinstance(v, list):
          for x in v:
            if isinstance(x, str) and x:
              blocks.append(x)

    if not blocks:
      return ""

    def _search_tag(tag: str) -> str:
      start_tag = f"<{tag}>"
      end_tag = f"</{tag}>"
      # Search from the newest block backwards; within each block we use rfind
      # so we prefer the last occurrence in that block.
      for block in reversed(blocks):
        start = block.rfind(start_tag)
        if start == -1:
          continue
        start += len(start_tag)
        end = block.find(end_tag, start)
        if end == -1:
          continue
        content = block[start:end].strip()
        if content:
          return content
      return ""

    # Prefer <conclusion> over <reason>.
    for tag in ("conclusion", "reason"):
      val = _search_tag(tag)
      if val:
        return val

    return ""

  def _compute_patch_fields_for_success(
      self,
      success: BuildResult,
  ) -> Tuple[str, Optional[str], Optional[str]]:
    """Compute (patch_text, orig_build_script, orig_fuzz_target) for updater.

      - Online, we only know:
          * the "old" sources used in the last failing fixer round
            (`_prev_*_for_diff`), and
          * the "new" sources on the successful round (success.*_source).

        We reconstruct a patch with heuristics that are consistent with the
        offline ingestion style, but slightly simpler:

          * If only build.sh changed:
                - patch_text := unified diff of build.sh
                - orig_build_script := old build.sh
          * If only fuzz target changed:
                - patch_text := unified diff of fuzz target
                - orig_fuzz_target := old fuzz target
          * If both changed:
                - patch_text := concatenation of:
                      BUILD.SH DIFF block  +  FUZZ TARGET DIFF block
                  with clear delimiters so a future offline tool (or LLM)
                  can distinguish them.
                - orig_build_script := old build.sh
                - orig_fuzz_target  := old fuzz target
          * If nothing obvious changed:
                - patch_text := final code (fuzz target or build.sh),
                - orig_* fields kept best-effort.

        Additionally, if we previously *reused* `/src/build.bk.sh` (i.e.,
        there was no custom build.sh text) but the successful round now has
        a concrete build.sh, we record:

            orig_build_script = "reuse /src/build.bk.sh"

        so that the entry clearly indicates it started from the human
        build.bk.sh template.
    """
    old_ft = self._prev_fuzz_target_for_diff or ""
    old_bs = self._prev_build_script_for_diff or ""
    new_ft = success.fuzz_target_source or ""
    new_bs = success.build_script_source or ""

    patch_text = ""
    orig_build_script: Optional[str] = None
    orig_fuzz_target: Optional[str] = None

    is_build_fix = bool(old_bs and new_bs and old_bs != new_bs)
    is_ft_fix = bool(old_ft and new_ft and old_ft != new_ft)

    if is_build_fix and not is_ft_fix:
      # ---------------------------------------------------------------
      # Pure build.sh fix: store a unified diff for the build script.
      # ---------------------------------------------------------------
      patch_text = self.unified_diff_text(
          old_bs,
          new_bs,
          old_name="build.sh (orig)",
          new_name="build.sh (fixed)",
      )
      orig_build_script = old_bs

    elif is_ft_fix and not is_build_fix:
      # ---------------------------------------------------------------
      # Pure fuzz target fix: store a unified diff for the harness.
      # ---------------------------------------------------------------
      patch_text = self.unified_diff_text(
          old_ft,
          new_ft,
          old_name="fuzz_target (orig)",
          new_name="fuzz_target (fixed)",
      )
      orig_fuzz_target = old_ft

    elif is_build_fix and is_ft_fix:
      # ---------------------------------------------------------------
      # Both build.sh and fuzz target changed in this successful round.
      #
      # We:
      #   - compute a diff for build.sh
      #   - compute a diff for the fuzz target
      #   - concatenate them into a single patch_text with explicit
      #     delimiters, so humans / LLMs / offline tools can see both.
      # ---------------------------------------------------------------
      diff_bs = self.unified_diff_text(
          old_bs,
          new_bs,
          old_name="build.sh (orig)",
          new_name="build.sh (fixed)",
      ) if old_bs and new_bs else ""

      diff_ft = self.unified_diff_text(
          old_ft,
          new_ft,
          old_name="fuzz_target (orig)",
          new_name="fuzz_target (fixed)",
      ) if old_ft and new_ft else ""

      chunks: list[str] = []

      if diff_bs.strip():
        chunks.append("===== BEGIN BUILD.SH DIFF =====\n"
                      f"{diff_bs}\n"
                      "===== END BUILD.SH DIFF =====")

      if diff_ft.strip():
        chunks.append("===== BEGIN FUZZ TARGET DIFF =====\n"
                      f"{diff_ft}\n"
                      "===== END FUZZ TARGET DIFF =====")

      if chunks:
        patch_text = "\n\n".join(chunks)
        orig_build_script = old_bs
        orig_fuzz_target = old_ft
      else:
        # Fall back to the "nothing changed" case below.
        if new_ft:
          patch_text = new_ft
          orig_fuzz_target = old_ft or None
        elif new_bs:
          patch_text = new_bs
          orig_build_script = old_bs or None

    else:
      # ---------------------------------------------------------------
      # Fallback: nothing obviously changed, or we lack old_* context.
      # ---------------------------------------------------------------
      if new_ft:
        patch_text = new_ft
        orig_fuzz_target = old_ft or None
      elif new_bs:
        patch_text = new_bs
        orig_build_script = old_bs or None

    # ---------------------------------------------------------------
    # Special case: we previously "reused /src/build.bk.sh" (no old_bs),
    # but now we have a concrete build.sh and haven't set orig_build_script.
    #
    # This makes the entry self-describing, matching the natural-language
    # line in the prompt:
    #   Build script reuses `/src/build.bk.sh`.
    # ---------------------------------------------------------------
    if (not old_bs) and new_bs and not orig_build_script:
      orig_build_script = "reuse /src/build.bk.sh"

    return patch_text, orig_build_script, orig_fuzz_target

  def _flush_stats_on_success(self, build_result: BuildResult) -> None:
    """Flush buffered stats and possibly register a new successful fix."""

    trial = getattr(build_result, "trial", -1)
    bench = build_result.benchmark
    project = getattr(bench, "project", "") or ""

    # 1) Stats: credit success if we ever attempted an entry.
    if self._last_attempted_entry_id is not None:
      eid = self._last_attempted_entry_id
      project_match = self._last_attempted_project_match
      self._bump_stats(
          eid,
          success=1,
          success_project=1 if project_match else 0,
      )

    flushed_stats_ok = False
    if self._stats_buffer:
      try:
        update_stats_from_buffer(self._stats_buffer, trial=trial)
        flushed_stats_ok = True
      except Exception as exc:  # noqa: BLE001
        errcode = exc.args[0] if exc.args else None
        # 1205 = lock wait timeout, 1213 = deadlock
        if errcode in (1205, 1213):
          logger.warning(
              "MemoryPrototyper: stats flush hit lock timeout/deadlock "
              "(code=%s); will retry on a later success.",
              errcode,
              trial=trial,
          )
          # IMPORTANT: we do *not* clear _stats_buffer here.
          # Next successful benchmark from this process will try again.
        else:
          logger.warning(
              "MemoryPrototyper: failed to flush stats buffer: %s",
              exc,
              trial=trial,
          )

    # 2) Online updater.
    #    Record every successful fixing episode as a candidate memory entry
    #    as long as we have an error snapshot (raw + normalized).
    if self._last_raw_error_text and self._last_normalized_error:
      try:
        fix_action_text = self._extract_fix_action_from_chat(build_result)
        logger.info(
            "Online updater extracted fix_action (len=%d): %r",
            len(fix_action_text),
            fix_action_text[:120],
            trial=trial,
        )
        patch_text, orig_bs, orig_ft = self._compute_patch_fields_for_success(
            build_result)

        # Model name logic
        llm_model_name = getattr(self.llm, "name", None)
        if not isinstance(llm_model_name, str) or not llm_model_name.strip():
          llm_model_name = "unknown_model"

        maybe_register_successful_fix(
            raw_error_text=self._last_raw_error_text,
            normalized_error_text=self._last_normalized_error,
            project=project,
            benchmark=bench,
            fuzz_target_source=orig_ft or "",
            build_script_source=orig_bs or "",
            fix_action_text=fix_action_text,
            patch_text=patch_text,
            llm_model=llm_model_name,
            trial=trial,
            embedder=self.text_embedding_model)

      except Exception as exc:  # noqa: BLE001
        logger.warning(
            "MemoryPrototyper: maybe_register_successful_fix failed: %s",
            exc,
            trial=trial,
        )

    # 3) Reset state.
    #
    # We *only* clear the stats buffer if we think the flush succeeded.
    # If it failed (e.g., due to lock timeout), we keep the buffer so that
    # a later success can try again, instead of silently dropping counts.
    if flushed_stats_ok:
      self._stats_buffer.clear()

    self._last_attempted_entry_id = None
    self._last_attempted_project_match = False
    self._last_round_had_hits = False
    self._last_raw_error_text = ""
    self._last_normalized_error = ""
    self._prev_fuzz_target_for_diff = ""
    self._prev_build_script_for_diff = ""
    # Reset cached chat so the next benchmark starts clean.
    self._chat_blocks.clear()

  # -------------------- planner: choose at most one entry --------------------

  def _llm_choose_action_plan(
      self,
      normalized_err: str,
      hits: List[Dict[str, Any]],
      context: Dict[str, str],
      trial: int,
  ) -> Optional[Dict[str, Any]]:
    """Use the LLM to select at most ONE entry from hits, with rich context.

    The planner sees:

      - CURRENT_ERROR: the normalized error string (no paths/line numbers).
      - CONTEXT_JSON: metadata + truncated compile_log/fuzz_target/build_script.
      - CANDIDATES_JSON: a compact list of candidate entries with fields:

          id, project, error_type, func_name, distance,
          fix_action (NL summary), patch_text (unified diff/code snippet).

    It must either:

      - pick exactly one candidate id, or
      - return 'null' to indicate "no suitable memory fix".

    Output format (strict):

      <chosen_id>BEST_ID_OR_null</chosen_id>
      <reason>short explanation</reason>
    """

    if not hits:
      return None

    compact_hits: List[Dict[str, Any]] = []
    for h in hits[:MAX_CANDIDATES]:
      compact_hits.append({
          "id": h["id"],
          "project": h.get("project"),
          "error_type": h.get("error_type"),
          "func_name": h.get("func_name"),
          "distance": h.get("distance"),
          "confidence": h.get("confidence_level", 0),
          "fix_action": (h.get("fix_action") or "")[:CANDIDATE_PREVIEW_LEN],
          "patch_text": (h.get("patch_text") or "")[:CANDIDATE_PREVIEW_LEN],
      })

    instruction = (
        "You are an assistant that selects at most ONE reusable fix from a "
        "retrieved error memory.\n\n"
        "You are given:\n"
        "  (1) The current normalized compiler/linker error (in the "
        "      <CURRENT_ERROR> block).\n"
        "  (2) Additional context about the failing build (in CONTEXT_JSON):\n"
        "        - project name, language, target name, function signature\n"
        "        - truncated compile_log (stdout + stderr + shell noise)\n"
        "        - truncated fuzz target source code\n"
        "        - truncated build script source\n"
        "        - a short meta description explaining why this fuzz target /\n"
        "          build is considered incorrect or failing.\n"
        "  (3) A list of candidate past fixes, each with:\n"
        "        - id, project, error_type, func_name\n"
        "        - distance (cosine distance; smaller is closer)\n"
        "        - confidence (3=fully verified fix,"
        " 2=partial fix/progress made, <2=unknown)\n"
        "        - fix_action (natural-language explanation)\n"
        "        - patch_text (unified diff snippet or code change)\n\n"
        "Your job:\n"
        "  - Compare the CURRENT_ERROR + CONTEXT_JSON with each candidate’s\n"
        "    context.\n"
        "  - If one fix is clearly applicable to this *specific* build error,\n"
        "    choose it.\n"
        "  - If none are applicable, choose null.\n\n"
        "IMPORTANT:\n"
        "  - Check the <FAILURE_SUMMARY> block. It describes why the build is\n"
        "    considered failed"
        " (e.g. 'Binary not saved', 'Function not covered'),\n"
        "    which is crucial when <CURRENT_ERROR> is empty or inconclusive.\n"
        "    Use it to select fixes for build script"
        " or logic errors matching that\n"
        "    description.\n"
        "  - Do NOT pick a candidate only because"
        " distance is small; check that\n"
        "    the error pattern, file paths, symbols, and toolchain situation\n"
        "    actually match.\n"
        "  - Prefer fixes from the same project"
        " or very similar error message.\n"
        "  - Prefer higher confidence scores (3 is best)"
        " if the context matches.\n"
        "  - Avoid candidates that would obviously corrupt code or change\n"
        "    unrelated functionality.\n\n"
        "Respond exactly in the following tag-based format:\n"
        "<chosen_id>BEST_ID_OR_null</chosen_id>\n"
        "<reason>short explanation why you chose it "
        "or why you chose null</reason>\n")

    planner_input = {
        "normalized_error": normalized_err,
        "context": context,
        "candidates": compact_hits,
    }

    planner_prompt = prompt_builder.DefaultTemplateBuilder(self.llm,
                                                           None).build([])
    planner_prompt.append(instruction)

    # Expose high-level failure context (e.g. "compiles but binary missing")
    # prominently to the planner.
    failure_msg = context.get("prototyper_failure_prompt")
    if failure_msg:
      planner_prompt.append("\n\n<FAILURE_SUMMARY>\n")
      planner_prompt.append(failure_msg)
      planner_prompt.append("\n</FAILURE_SUMMARY>\n")

    # Keep CURRENT_ERROR as a separate, first-class normalized error block.
    planner_prompt.append("\n\n<CURRENT_ERROR>\n")
    planner_prompt.append(normalized_err)
    planner_prompt.append("\n</CURRENT_ERROR>\n\n<CONTEXT_JSON>\n")

    # CONTEXT_JSON intentionally *omits* `normalized_error` and `compile_error`
    # to avoid duplicating the main signal; it focuses on metadata and richer
    # context.
    planner_prompt.append(json.dumps(context, indent=2))
    planner_prompt.append("\n</CONTEXT_JSON>\n\n<CANDIDATES_JSON>\n")
    planner_prompt.append(json.dumps(planner_input["candidates"], indent=2))
    planner_prompt.append(
        "\n</CANDIDATES_JSON>\n\n"
        "Now output only the <chosen_id> and <reason> tags as specified above:")

    client = self.llm.get_chat_client(model=self.llm.get_model())
    raw_response = self.chat_llm(
        cur_round=0,
        client=client,
        prompt=planner_prompt,
        trial=trial,
    )

    def _extract_tag(text: str, tag: str) -> str:
      start_tag = f"<{tag}>"
      end_tag = f"</{tag}>"
      start = text.find(start_tag)
      if start == -1:
        return ""
      start += len(start_tag)
      end = text.find(end_tag, start)
      if end == -1:
        return ""
      return text[start:end].strip()

    try:
      text = raw_response.strip()
      chosen_raw = _extract_tag(text, "chosen_id")
      reason = _extract_tag(text, "reason")

      if not chosen_raw or chosen_raw.lower() in ("null", "none", "n/a"):
        logger.info(
            "Memory planner chose no plan. reason=%s",
            reason,
            trial=trial,
        )
        return None

      chosen_id_int: Optional[int] = None
      try:
        chosen_id_int = int(chosen_raw)
      except ValueError:
        chosen_id_int = None

      for h in hits:
        if chosen_id_int is not None and h["id"] == chosen_id_int:
          logger.info(
              "Memory planner chose entry id=%s. reason=%s",
              chosen_id_int,
              reason,
              trial=trial,
          )
          return h
        if str(h["id"]) == chosen_raw:
          logger.info(
              "Memory planner chose entry id=%s (string match). reason=%s",
              chosen_raw,
              reason,
              trial=trial,
          )
          return h

      logger.warning(
          "Memory planner chose id=%r not in hits; ignoring.",
          chosen_raw,
          trial=trial,
      )
      return None
    except Exception as exc:  # noqa: BLE001
      logger.warning(
          "Failed to parse planner tags: %s\nRaw: %r",
          exc,
          raw_response,
          trial=trial,
      )
      return None

  # -------------------- KNN + stats + planner wiring --------------------

  def _maybe_get_memory_plan(
      self,
      build_result: BuildResult,
  ) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Lookup Cloud SQL for a similar error
     return (normalized_err, best_hit).

    Inputs:

      - compile_error: raw stderr snippet extracted by OFG, if available.
      - compile_log: full wrapped log including <bash>, <stderr>, etc.

    We query on:

        query_text = compile_error or compile_log

    and let knn_search_error_full_with_norm():

      - normalize the error text (normalize_err_text / loose fallback),
      - compute an embedding,
      - query Cloud SQL for nearest neighbors, and
      - return (normalized_text, hits[]).
    """

    # compile_error = raw stderr snippet (if OFG extracted one)
    # compile_log   = full wrapped log including <bash>, <stderr>, etc.
    compile_err = build_result.compile_error or ""
    compile_log = build_result.compile_log or ""
    query_text = compile_err or compile_log

    if not query_text.strip():
      # Nothing to query with in this round.
      self._last_round_had_hits = False
      self._last_raw_error_text = ""
      self._last_normalized_error = ""
      return "", None

    normalized, hits = knn_search_error_full_with_norm(
        query_text,
        top_k=5,
        trial=build_result.trial,
        embedder=self.text_embedding_model)

    if not hits:
      # KNN executed but found no neighbors for this round.
      self._last_round_had_hits = False
      self._last_raw_error_text = query_text
      self._last_normalized_error = normalized
      return normalized, None

    # From here on: this failing round DID have retrieval hits.
    self._last_round_had_hits = True
    self._last_raw_error_text = query_text
    self._last_normalized_error = normalized

    bench = build_result.benchmark
    function_signature = getattr(bench, "function_signature", "") or ""
    fuzz_target_source = build_result.fuzz_target_source or ""
    build_script_source = build_result.build_script_source or ""
    current_project = getattr(bench, "project", "") or ""

    # Stats: record retrievals (including cross-project).
    for h in hits:
      eid = str(h["id"])
      project_match = (h.get("project") or "") == current_project
      self._bump_stats(
          eid,
          retrieved=1,
          retrieved_project=1 if project_match else 0,
      )

    binary_exists = getattr(build_result, "binary_exists", False)
    compiles_flag = getattr(build_result, "compiles", False)

    # NOTE: prototyper_failure_prompt is a short meta description of the
    # failure mode, not a full code dump. The planner can still see the
    # actual fuzz target, build script, and logs via the other context
    # fields (fuzz_target, build_script, compile_log, etc.).
    if binary_exists and function_signature:
      prototyper_failure_prompt = (
          "Binary was produced, but `LLVMFuzzerTestOneInput` "
          "does not correctly "
          f"exercise the function-under-test `{function_signature}`. The "
          "current fuzz target is considered invalid for this benchmark.")
    elif compiles_flag and not binary_exists:
      binary_path = os.path.join("/out",
                                 getattr(bench, "target_name", "") or "")
      prototyper_failure_prompt = (
          "The fuzz target and build script compile, but the final fuzz target "
          f"binary is not saved to the expected path `{binary_path}`. The "
          "build script likely misses a copy/move step or uses an incorrect "
          "target name or output location.")
    else:
      prototyper_failure_prompt = (
          "The current fuzz target and/or build script still fail to produce a "
          "working fuzzing binary. You must fix the compilation and/or output "
          "steps so that the project builds successfully and writes the fuzz "
          "target under `/out/`.")

    # CONTEXT_JSON intentionally *omits* `normalized_error` and `compile_error`
    # to avoid duplicating what is already in <CURRENT_ERROR>. It focuses on
    # metadata + richer context.
    context: Dict[str, str] = {
        "project": current_project,
        "language": getattr(bench, "language", "") or "",
        "target_name": getattr(bench, "target_name", "") or "",
        "function_signature": function_signature,
        "compile_log": compile_log[:2000],
        "fuzz_target": fuzz_target_source[:2000],
        "build_script": build_script_source[:2000],
        "prototyper_failure_prompt": prototyper_failure_prompt,
    }

    plan = self._llm_choose_action_plan(
        normalized_err=normalized,
        hits=hits,
        context=context,
        trial=build_result.trial,
    )

    if plan is None:
      # This failing round had hits, but the LLM planner chose NULL.
      self._last_attempted_entry_id = None
      self._last_attempted_project_match = False
      return normalized, None

    # Stats: record that the planner actually *attempted* to use this entry.
    eid = str(plan["id"])
    project_match = (plan.get("project") or "") == current_project
    self._bump_stats(
        eid,
        attempted=1,
        attempted_project=1 if project_match else 0,
    )
    self._last_attempted_entry_id = eid
    self._last_attempted_project_match = project_match

    build_result.chat_history.setdefault("MemoryPlanner", "")
    build_result.chat_history["MemoryPlanner"] += (
        f"\n[MemoryPlanner] Using entry id={plan['id']} "
        f"(project={plan.get('project')}, "
        f"error_type={plan.get('error_type')}, "
        f"distance={plan.get('distance')}).\n")
    return normalized, plan

  # --- override failure logic; use fixer+memory in Case 2, Case 3, Pref 7 ---

  def _generate_prompt_from_build_result(
      self,
      build_result_alt: Optional[BuildResult],
      build_result_ori: Optional[BuildResult],
      build_result: BuildResult,
      prompt: Prompt,
      cur_round: int,
  ) -> tuple[BuildResult, Optional[Prompt]]:
    """Same logic as Prototyper, but failure cases use memory + fixer template.

    Differences from the base Prototyper:

      - Case 1 (success): we additionally flush stats and trigger the online
        updater (if applicable) before returning.

      - Failure cases (Case 2, Case 3, Preference 7) do *not* inline the fuzz
        target / build script / compilation log themselves. Instead we:
            * prepend a high-level explanation + <memory hint>, and
            * let PrototyperFixerTemplateBuilder inject the canonical blocks.

      - Right before we construct the fixer prompt, we snapshot the fuzz target
        and build script into `_prev_*_for_diff` so that, if the next round
        succeeds, we can compute a patch between this failing view and the new
        successful view.
    """

    # Case 1: Successful → flush stats + updater.

    if build_result_alt and build_result_alt.success:
      logger.info(
          "Default /src/build.sh works perfectly, no need for a new "
          "buid script",
          trial=build_result.trial,
      )
      logger.info(
          "***** %s succeeded in %02d rounds *****",
          self.name,
          cur_round,
          trial=build_result.trial,
      )
      self._flush_stats_on_success(build_result_alt)
      return build_result_alt, None

    if build_result_ori and build_result_ori.success:
      logger.info(
          "***** %s succeeded in %02d rounds *****",
          self.name,
          cur_round,
          trial=build_result.trial,
      )
      self._flush_stats_on_success(build_result_ori)
      return build_result_ori, None

    # --- Precompute memory plan once for this failing BuildResult ---
    _, plan = self._maybe_get_memory_plan(build_result)

    extra_hints = ""
    if plan is not None:
      extra_hints = (
          "\n<reference_solution>\n"
          "A similar error was previously fixed with the following patch. \n"
          f"{self._get_confidence_note(plan)}\n"
          "Adapt the solution if necessary.\n\n"
          f"Project: {plan.get('project')}\n"
          f"Error type: {plan.get('error_type')}\n"
          f"Function: {plan.get('func_name')}\n\n"
          "Fix explanation:\n"
          "<fix_action>\n"
          f"{plan.get('fix_action') or ''}\n"
          "</fix_action>\n\n"
          "Patch:\n"
          "<patch>\n"
          f"{plan.get('patch_text') or ''}\n"
          "</patch>\n"
          "</reference_solution>\n")

    # Small helper: build a PrototyperFixerTemplateBuilder prompt for a given
    # selected BuildResult + explanation (Case 2/3 text) + memory hints.
    def _build_fix_prompt_for_result(
        selected_result: BuildResult,
        explanation: str,
    ) -> Tuple[BuildResult, Prompt]:
      # Snapshot the failing sources used to construct this fixer prompt.
      # If the next round succeeds, _compute_patch_fields_for_success() will
      # diff these against the new successful sources.
      self._prev_fuzz_target_for_diff = selected_result.fuzz_target_source or ""
      self._prev_build_script_for_diff = (selected_result.build_script_source or
                                          "")

      # We now only prepend a high-level explanation + memory hints.
      initial_text = prompt.get() + explanation + extra_hints

      # Use smart truncation for the log
      log_content = selected_result.compile_log or ""
      # Heuristic: limit log to 15k chars (approx 4k tokens).
      # This balances context with token limits.
      sel_compile_log = self.smart_truncate_log(log_content, max_chars=15000)

      fixer = prompt_builder.PrototyperFixerTemplateBuilder(
          model=self.llm,
          benchmark=selected_result.benchmark,
          build_result=selected_result,
          compile_log=sel_compile_log,
          initial=initial_text,
          template_name='prototyper-fixing-memory.txt')
      fixer_prompt = fixer.build(
          example_pair=[],
          project_dir=self.inspect_tool.project_dir,
      )
      return selected_result, fixer_prompt

    # From here we mirror Prototyper’s Case 2 / Case 3 logic, but instead of
    # directly appending prompt_text_* and returning, we fold those strings
    # + memory hints into the fixer template via _build_fix_prompt_for_result.

    function_signature = build_result.benchmark.function_signature
    binary_path = os.path.join("/out", build_result.benchmark.target_name)

    #  Case 2: Binary exists, but function-under-test not called
    # IMPORTANT: we no longer inline <fuzz target> / <build script> /
    # <compilation log> here; those are added once by the fixer template via
    # `prompt.get()`. We just give a high-level explanation.
    prompt_text = (
        "The fuzz target's `LLVMFuzzerTestOneInput` did not invoke the "
        f"function-under-test `{function_signature}`.\n"
        "Below you will see the current fuzz target, build script, and "
        "compilation log. Carefully analyze them to understand why the "
        "function-under-test is not being called correctly.\n\n"
        "That is NOT enough. YOU MUST MODIFY THE FUZZ TARGET to CALL "
        f"FUNCTION `{function_signature}` **EXPLICITLY OR IMPLICITLY** in "
        "`LLVMFuzzerTestOneInput` to generate a valid fuzz target.\n"
        "Study the source code for function usages to know how.\n")

    if build_result_alt and build_result_alt.binary_exists:
      prompt_text_3 = (
          prompt_text +
          "Although `/src/build.bk.sh` compiles and saves the binary to "
          "the correct path, the function-under-test is still not being "
          "properly exercised by the fuzz target.\n"
          "When you have a solution later, make sure you output the FULL fuzz "
          "target. YOU MUST NOT OMIT ANY CODE "
          "even if it is the same as before.\n")
      return _build_fix_prompt_for_result(build_result_alt, prompt_text_3)

    if (build_result_ori and build_result_ori.binary_exists and
        not build_result_ori.build_script_source):
      prompt_text_41 = (
          prompt_text +
          "Although `/src/build.bk.sh` compiles and saves the binary to "
          "the correct path, the function-under-test is still not being "
          "properly exercised by the fuzz target.\n"
          "When you have a solution later, make sure you output the FULL fuzz "
          "target. YOU MUST NOT OMIT ANY CODE "
          "even if it is the same as before.\n")
      return _build_fix_prompt_for_result(build_result_ori, prompt_text_41)

    if build_result_ori and build_result_ori.binary_exists:
      prompt_text_42 = (
          prompt_text +
          "Your build script compiles and saves the binary to the correct "
          "path, but the current fuzz target still does not correctly call "
          "the function-under-test.\n"
          "When you have a solution later, make sure you output the FULL fuzz "
          "target (and the FULL build script, if any). YOU MUST NOT OMIT ANY "
          "CODE even if it is the same as before.\n")
      return _build_fix_prompt_for_result(build_result_ori, prompt_text_42)

    #  Case 3: Compiles, but binary not saved to /out/...
    if (build_result_ori and build_result_ori.compiles and
        build_result_ori.build_script_source):
      # IMPORTANT: again, no duplicated <fuzz target> / <build script> /
      # <compilation log> here; the fixer template handles those blocks.
      prompt_text_51 = (
          "The fuzz target and build script compile successfully, but the "
          f"final fuzz target binary was not saved to the expected path at "
          f"`{binary_path}`.\n"
          "Below you will see the current fuzz target, build script, and "
          "compilation log. Carefully analyze the build steps to understand "
          "why the binary is not written to the correct location.\n\n"
          "YOU MUST MODIFY THE BUILD SCRIPT to ensure the binary is saved to "
          f"{binary_path}.\n"
          "When you have a solution later, make sure you output the FULL fuzz "
          "target (and the FULL build script, if any). YOU MUST NOT OMIT ANY "
          "CODE even if it is the same as before.\n")
      return _build_fix_prompt_for_result(build_result_ori, prompt_text_51)

    if (build_result_ori and build_result_ori.compiles and
        not build_result_ori.build_script_source):
      logger.error(
          "The human-written build.sh does not save the fuzz target binary to "
          "expected path /out/%s, indicating incorrect info in benchmark YAML.",
          build_result.benchmark.target_name,
          trial=build_result.trial,
      )
      prompt_text_52 = (
          "The fuzz target compiles successfully with `/src/build.bk.sh`, but "
          f"the final fuzz target binary was not saved to the expected path at "
          f"`{binary_path}`.\n"
          "Below you will see the current fuzz target and compilation log. "
          "Carefully analyze them to understand why the binary is not written "
          "to the correct location.\n\n"
          "YOU MUST MODIFY THE BUILD SCRIPT to ensure the binary is saved to "
          f"{binary_path}.\n"
          "When you have a solution later, make sure you output the FULL fuzz "
          "target (and the FULL build script, if any). YOU MUST NOT OMIT ANY "
          "CODE even if it is the same as before.\n")
      return _build_fix_prompt_for_result(build_result_ori, prompt_text_52)

    if build_result_alt and build_result_alt.compiles:
      logger.error(
          "The human-written build.sh does not save the fuzz target binary to "
          "expected path /out/%s, indicating incorrect info in benchmark YAML.",
          build_result.benchmark.target_name,
          trial=build_result.trial,
      )
      prompt_text_6 = (
          "The fuzz target compiles successfully with `/src/build.bk.sh`, but "
          f"the final fuzz target binary was not saved to the expected path at "
          f"`{binary_path}`.\n"
          "Below you will see the current fuzz target and compilation log. "
          "Carefully analyze them to understand why the binary is not written "
          "to the correct location.\n\n"
          "YOU MUST MODIFY THE BUILD SCRIPT to ensure the binary is saved to "
          f"{binary_path}.\n"
          "When you have a solution later, make sure you output the FULL fuzz "
          "target (and the FULL build script, if any). YOU MUST NOT OMIT ANY "
          "CODE even if it is the same as before.\n")
      return _build_fix_prompt_for_result(build_result_alt, prompt_text_6)

    #  Preference 7: new fuzz target + neither build.sh compiles
    # Here we just rely on the memory hint + fixer template.
    self._prev_fuzz_target_for_diff = build_result.fuzz_target_source or ""
    self._prev_build_script_for_diff = build_result.build_script_source or ""

    initial_text = prompt.get() + extra_hints
    final_compile_log = self.smart_truncate_log(
        build_result.compile_log or "",
        max_chars=15000,
    )

    fixer = prompt_builder.PrototyperFixerTemplateBuilder(
        model=self.llm,
        benchmark=build_result.benchmark,
        build_result=build_result,
        compile_log=final_compile_log,
        initial=initial_text,
        template_name='prototyper-fixing-memory.txt')
    fixer_prompt = fixer.build(
        example_pair=[],
        project_dir=self.inspect_tool.project_dir,
    )
    return build_result, fixer_prompt
