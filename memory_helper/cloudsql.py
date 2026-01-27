# memory_helper/cloudsql.py
from __future__ import annotations

import json
import os
import struct
import uuid
from contextlib import contextmanager
from typing import List, Dict, Any, Optional, Tuple

import logger  # OFG's structured logger

from .errors import (
    classify_error,
    normalize_err_text,
    normalize_err_text_fallback,
    latest_stderr_block,
)
from llm_toolkit.text_embedder import VertexEmbeddingModel
from google.auth import default
from google.auth.transport.requests import Request
import requests
from google.cloud.sql.connector import Connector, IPTypes
import pymysql



INSTANCE_CONNECTION_NAME = "uom-ossfuzz-gen:australia-southeast1:ofg-test"
DB_NAME = "ofg"
_DB_USER = None

def _log_info(msg: str, *args, trial: Optional[int] = None) -> None:
    """Helper to always provide a trial kwarg to OFG logger."""
    t = -1 if trial is None else trial
    logger.info(msg, *args, trial=t)


def _log_warning(msg: str, *args, trial: Optional[int] = None) -> None:
    t = -1 if trial is None else trial
    logger.warning(msg, *args, trial=t)



def get_credentials():
    credentials, project = default()
    if hasattr(credentials, "service_account_email"):
        # Note: Some SA creds return 'default' or None, so we check for actual conten
        if credentials.service_account_email and credentials.service_account_email != "default": # type: ignore
            db_user = credentials.service_account_email.split('@')[0]  # type: ignore
            logger.info (f"[AUTH] found service account {db_user}", trial=1)
            return db_user


    try:
        # We must ensure the token is valid/refreshed before using i
        if not credentials.valid:  # type: ignore
            credentials.refresh(Request()) # type: ignore
        # Call Google's userinfo endpoint using the access token
        response = requests.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {credentials.token}"}   # type: ignore
        )
        response.raise_for_status()
        data = response.json()

        email = data.get("email")
        if not email:
            raise ValueError("Could not retrieve email from token info.")
        #logger.info(f"[AUTH] found user email {email}", "",trial=-1)
        db_user = email.split('@')[0]
        return db_user

    except Exception as e:
        print(f"Failed to auto-detect email: {e}")
        raise

@contextmanager
def cloud_sql_connect_smart():
    """
    Attempts to connect via Local Proxy first.
    If that fails, falls back to Google Python Connector.
    """
    global _DB_USER
    if _DB_USER is None:
        _DB_USER = get_credentials()

    conn = None
    connector = None  # Only initialized if we use the fallback method

    # ---------------------------------------------------------
    # Attempt 1: Primary (Local Proxy)
    # ---------------------------------------------------------
    try:
        conn = pymysql.connect(
            host="127.0.0.1",
            port=3306,
            database='ofg',
            user=_DB_USER,
            password="",
            ssl_disabled=True,
            connect_timeout=10
        )
    except Exception as proxy_e:
        _log_info(
            f"proxy connection failed: {proxy_e}",trial= 1 )

        # ---------------------------------------------------------
        # Attempt 2: Fallback (Google Connector)
        # ---------------------------------------------------------
        try:
            _log_info("fallback to connect with GSA account", trial= 1)
            connector = Connector(ip_type=IPTypes.PUBLIC, refresh_strategy="LAZY")
            conn = connector.connect(
                INSTANCE_CONNECTION_NAME,
                "pymysql",
                user=_DB_USER,
                db="ofg",
                enable_iam_auth=True
            )
        except Exception as connector_e:
            _log_info(f"Fallback connection also failed: {connector_e}", trial= 1)
            # If the connector was created but connect() failed, close it.
            if connector:
                connector.close()
            raise connector_e  # Raise the final error to the runner

    # ---------------------------------------------------------
    # Phase 3: Yield & Cleanup
    # ---------------------------------------------------------
    try:
        # Yield the successful connection (from either source) to the inner block
        yield conn
    finally:
        # Cleanup Connection
        if conn:
            conn.close()

        # Cleanup Connector (Only if it was initialized during fallback)
        if connector:
            connector.close()



def _prepare_normalized(query_error_text: str) -> Tuple[str, str]:
    raw = query_error_text or ""
    stderr_text = latest_stderr_block(raw) or raw
    normalized = normalize_err_text(stderr_text)
    if stderr_text and not normalized.strip():
        normalized = normalize_err_text_fallback(stderr_text)
    return stderr_text, normalized

def _embed_normalized(normalized:str, embedder: VertexEmbeddingModel) -> List[float]:
    """
        Embeds a single string using a pre-initialized embedder instance.
        """
    if not normalized.strip():
        return []
    # We call the method directly on the passed instance.
    # This reuses the logic and the cached connection inside the instance.
    vec_list = embedder.embed_texts_error_norm([normalized])

    return vec_list[0] or []


def _knn_search_error_full_core(
    normalized: str,
    top_k: int,
    embedder: VertexEmbeddingModel,
    trial: Optional[int] = None,
    confidence_levels: Optional[List[int]] = None
) -> List[Dict[str, Any]]:
    """Core KNN lookup given an already-normalized error string."""
    # Default to confidence levels 2 and 3 if not specified
    if confidence_levels is None:
        confidence_levels = [2, 3]

    if not normalized.strip():
        _log_info("[KNN] Empty normalized error → return [].", trial=trial)
        return []

    vec = _embed_normalized(normalized, embedder)
    if not vec:
        _log_info("[KNN] Embedding failed or returned empty vector.", trial=trial)
        return []

    vec_str = json.dumps(vec)
    _log_info("[KNN] Embedding vector prepared (len=%d).", len(vec), trial=trial)

    # Build placeholders for IN clause
    if not confidence_levels:
        # Fallback if someone passes empty list explicitly -> return nothing?
        _log_info("[KNN] No confidence levels provided → return [].", trial=trial)
        return []

    placeholders = ", ".join(["%s"] * len(confidence_levels))

    sql = f"""
        SELECT
          id,
          project,
          error_type,
          func_name,
          orig_build_script,
          orig_fuzz_target,
          patch_text,
          fix_action,
          confidence_level,
          cosine_distance(
            embedding,
            string_to_vector(%s)
          ) AS dist
        FROM entries
        WHERE confidence_level IN ({placeholders})
        ORDER BY dist ASC
        LIMIT %s
    """

    rows: List[Dict[str, Any]] = []
    with cloud_sql_connect_smart() as conn:
        with conn.cursor() as cur:
            _log_info("[KNN] Executing SQL top_k=%d, conf=%s", top_k, confidence_levels, trial=trial)
            # Param order: vector_json, *conf_levels, top_k
            params = [vec_str] + confidence_levels + [top_k]
            cur.execute(sql, params)
            fetched = cur.fetchall()
            _log_info("[KNN] SQL returned %d rows.", len(fetched), trial=trial)

            for (
                id_,
                project,
                error_type,
                func_name,
                orig_bs,
                orig_ft,
                patch_text,
                fix_action,
                conf_level,
                dist,
            ) in fetched:
                rows.append(
                    {
                        "id": id_,
                        "project": project,
                        "error_type": error_type,
                        "func_name": func_name,
                        "orig_build_script": orig_bs,
                        "orig_fuzz_target": orig_ft,
                        "patch_text": patch_text,
                        "fix_action": fix_action,
                        "confidence_level": conf_level,
                        "distance": float(dist),
                    }
                )

    _log_info("[KNN] Returning %d processed rows.", len(rows), trial=trial)
    return rows


def knn_search_error_full_with_norm(
    query_error_text: str,
    embedder: VertexEmbeddingModel,
    top_k: int = 5,
    trial: Optional[int] = None,
    confidence_levels: Optional[List[int]] = None
) -> Tuple[str, List[Dict[str, Any]]]:
    """KNN that returns BOTH the normalized error text and the hits.

    Usage:
        normalized, hits = knn_search_error_full_with_norm(query_text, top_k=5)
    """
    if Connector is None:
        _log_info(
            "Cloud SQL deps not available; "
            "knn_search_error_full_with_norm() returning ('', []).",
            trial=trial,
        )
        return "", []

    stderr_text, normalized = _prepare_normalized(query_error_text)

    _log_info("\n[KNN] Normalized error text being embedded:\n%s", normalized, trial=trial)
    _log_info("[KNN] %s", "=" * 80, trial=trial)

    rows = _knn_search_error_full_core(normalized, top_k=top_k, trial=trial, embedder=embedder, confidence_levels=confidence_levels)

    _log_info(
        "[KNN] Final result: normalized length=%d, hits=%d",
        len(normalized),
        len(rows),
        trial=trial,
    )

    return normalized, rows


def knn_search_error_full(
    query_error_text: str,
    embedder:VertexEmbeddingModel,
    top_k: int = 5,
    trial: Optional[int] = None,
    confidence_levels: Optional[List[int]] = None
) -> List[Dict[str, Any]]:
    """Legacy API: returns only the list of hits."""
    _, rows = knn_search_error_full_with_norm(
        query_error_text,
        top_k=top_k,
        trial=trial,
        embedder=embedder,
        confidence_levels=confidence_levels
    )
    return rows


def update_stats_from_buffer(
    stats_buffer: Dict[str, Dict[str, int]],
    trial: Optional[int] = None,
) -> None:
    """Apply buffered stats deltas into the `stats` table.

    `stats_buffer` is expected to have the shape:
        {
          "<entry_id>": {
            "retrieved": int,
            "attempted": int,
            "success": int,
            "retrieved_project": int,
            "attempted_project": int,
            "success_project": int,
          },
          ...
        }

    For each id, we upsert into `stats` and increment the counters.
    """

    if not stats_buffer:
        _log_info(
            "update_stats_from_buffer: empty buffer, nothing to do.",
            trial=trial,
        )
        return

    if Connector is None:
        _log_info(
            "Cloud SQL deps not available; "
            "update_stats_from_buffer() will be a no-op.",
            trial=trial,
        )
        return

    # INSERT ... ON DUPLICATE KEY UPDATE pattern:
    #  - For a new row: counters are initialized from the deltas.
    #  - For an existing row: counters are incremented by the deltas.
    sql = """
        INSERT INTO stats (
          id,
          on_retrieved,
          on_attempted,
          on_success,
          on_retrieved_project,
          on_attempted_project,
          on_success_project,
          last_used_at
        )
        VALUES (
          %(id)s,
          %(retrieved)s,
          %(attempted)s,
          %(success)s,
          %(retrieved_project)s,
          %(attempted_project)s,
          %(success_project)s,
          UTC_TIMESTAMP()
        )
        ON DUPLICATE KEY UPDATE
          on_retrieved         = on_retrieved         + %(retrieved)s,
          on_attempted         = on_attempted         + %(attempted)s,
          on_success           = on_success           + %(success)s,
          on_retrieved_project = on_retrieved_project + %(retrieved_project)s,
          on_attempted_project = on_attempted_project + %(attempted_project)s,
          on_success_project   = on_success_project   + %(success_project)s,
          last_used_at         = UTC_TIMESTAMP()
    """

    with cloud_sql_connect_smart() as conn:
        with conn.cursor() as cur:
            for entry_id, deltas in sorted(stats_buffer.items()):
                # Skip pure-zero deltas to avoid useless writes.
                if not any(deltas.get(k, 0) for k in (
                    "retrieved",
                    "attempted",
                    "success",
                    "retrieved_project",
                    "attempted_project",
                    "success_project",
                )):
                    continue

                params = {
                    "id": str(entry_id),
                    "retrieved": int(deltas.get("retrieved", 0)),
                    "attempted": int(deltas.get("attempted", 0)),
                    "success": int(deltas.get("success", 0)),
                    "retrieved_project": int(deltas.get("retrieved_project", 0)),
                    "attempted_project": int(deltas.get("attempted_project", 0)),
                    "success_project": int(deltas.get("success_project", 0)),
                }

                _log_info(
                    "update_stats_from_buffer: updating stats for id=%s "
                    "(Δretrieved=%d, Δattempted=%d, Δsuccess=%d, "
                    "Δretrieved_project=%d, Δattempted_project=%d, "
                    "Δsuccess_project=%d)",
                    params["id"],
                    params["retrieved"],
                    params["attempted"],
                    params["success"],
                    params["retrieved_project"],
                    params["attempted_project"],
                    params["success_project"],
                    trial=trial,
                )

                cur.execute(sql, params)

        conn.commit()

    _log_info(
        "update_stats_from_buffer: flushed %d entries to stats table.",
        len(stats_buffer),
        trial=trial,
    )


def _derive_func_name_from_benchmark(benchmark: Any) -> str:
    """Best-effort extraction of function name from benchmark metadata."""
    # Most OFG benchmarks have a function_signature like:
    #   "int cJSON_Parse(const char* input)"
    sig = getattr(benchmark, "function_signature", "") or ""
    if sig and "(" in sig:
        before_paren = sig.split("(", 1)[0].strip()
        parts = before_paren.split()
        if parts:
            return parts[-1]

    # Fallback: if you have some other field like `function_under_test`
    fut = getattr(benchmark, "function_under_test", "") or ""
    return fut or ""


def maybe_register_successful_fix(
    *,
    raw_error_text: str,
    normalized_error_text: str,
    project: str,
    benchmark: Any,
    embedder: VertexEmbeddingModel,
    fuzz_target_source: str,
    build_script_source: str,
    fix_action_text: str = "",
    patch_text: str = "",
    llm_model: str = "",
    trial: Optional[int] = None
) -> None:
    """Best-effort updater: register a new successful fix into `entries`.

    This is called when:
      - We have a stored (raw, normalized) error snapshot from the last
        failing round, and
      - A subsequent round succeeded (with or without using memory).

    We:
      1) Compute an embedding for the normalized error text.
      2) Check if a very similar entry already exists for this project.
      3) If not, insert a new row into `entries` with:
           - project, error_type, func_name
           - orig_build_script, orig_fuzz_target
           - patch_text, fix_action
           - error_text_norm, embedding
           - llm_model (the model that produced this fix)
    """
    if Connector is None:
        _log_info(
            "Cloud SQL deps not available; maybe_register_successful_fix() no-op.",
            trial=trial,
        )
        return

    # 1) Normalize / embedding
    normalized = normalized_error_text or ""
    if not normalized.strip():
        # Fallback: recompute from raw_error_text if needed.
        _, recomputed = _prepare_normalized(raw_error_text)
        normalized = recomputed

    if not normalized.strip():
        _log_info(
            "maybe_register_successful_fix: empty normalized text, skip.",
            trial=trial,
        )
        return

    vec = _embed_normalized(normalized, embedder)
    if not vec:
        _log_info(
            "maybe_register_successful_fix: embedding empty/failed, skip.",
            trial=trial,
        )
        return

    vec_str = json.dumps(vec)

    # 2) Classify error type from RAW error text (pattern-based).
    error_type = "UNKNOWN"
    if raw_error_text:
        try:
            cls = classify_error(raw_error_text, trial=trial)
            if cls and cls.get("type"):
                error_type = str(cls["type"])
        except Exception as exc:  # noqa: BLE001
            _log_warning(
                "maybe_register_successful_fix: classify_error failed: %s",
                exc,
                trial=trial,
            )

    func_name = _derive_func_name_from_benchmark(benchmark)

    # 3) Deduplicate: check if a very similar entry already exists for this project.
    DEDUP_THRESHOLD = 0.04  # tune as needed

    with cloud_sql_connect_smart() as conn:
        with conn.cursor() as cur:
            dedup_sql = """
                SELECT
                  id,
                  cosine_distance(
                    embedding,
                    string_to_vector(%s)
                  ) AS dist
                FROM entries
                WHERE project = %s
                ORDER BY dist ASC
                LIMIT 1
            """
            cur.execute(dedup_sql, (vec_str, project))
            row = cur.fetchone()

            if row is not None:
                existing_id, dist = row[0], float(row[1])
                _log_info(
                    "maybe_register_successful_fix: nearest existing entry id=%s, dist=%.6f",
                    existing_id,
                    dist,
                    trial=trial,
                )
                if dist <= DEDUP_THRESHOLD:
                    _log_info(
                        "maybe_register_successful_fix: similar entry already in DB, skip insert.",
                        trial=trial,
                    )
                    return

            # 4) Insert new entry.
            new_id = str(uuid.uuid4())
            insert_sql = """
                INSERT INTO entries (
                  id,
                  project,
                  error_type,
                  func_name,
                  orig_build_script,
                  orig_fuzz_target,
                  patch_text,
                  fix_action,
                  error_text_norm,
                  embedding,
                  llm_model
                )
                VALUES (
                  %(id)s,
                  %(project)s,
                  %(error_type)s,
                  %(func_name)s,
                  %(orig_build_script)s,
                  %(orig_fuzz_target)s,
                  %(patch_text)s,
                  %(fix_action)s,
                  %(error_text_norm)s,
                  string_to_vector(%(embedding_json)s),
                  %(llm_model)s
                )
            """
            params = {
                "id": new_id,
                "project": project or "",
                "error_type": error_type,
                "func_name": func_name,
                # These should be the *original* versions from the failing round,
                # as computed by MemoryPrototyper._compute_patch_fields_for_success.
                "orig_build_script": build_script_source or "",
                "orig_fuzz_target": fuzz_target_source or "",
                # Runtime info:
                "patch_text": patch_text or "",
                "fix_action": fix_action_text or "",
                "error_text_norm": normalized,
                "embedding_json": vec_str,
                "llm_model": llm_model or "",
            }

            _log_info(
                "maybe_register_successful_fix: inserting new entry id=%s (project=%s, error_type=%s, func_name=%s, llm_model=%s)",
                new_id,
                params["project"],
                params["error_type"],
                params["func_name"],
                params["llm_model"],
                trial=trial,
            )
            cur.execute(insert_sql, params)

        conn.commit()

    _log_info(
        "maybe_register_successful_fix: successfully inserted new entry.",
        trial=trial,
    )
