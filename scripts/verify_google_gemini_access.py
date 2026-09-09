#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
"""Verify Google Gemini access with an API key or Vertex AI ADC.

Usage examples:

  GEMINI_API_KEY=... .venv/bin/python scripts/verify_google_gemini_access.py

  .venv/bin/python scripts/verify_google_gemini_access.py \
      --api-key "$GEMINI_API_KEY" \
      --model gemini-2.5-flash

  .venv/bin/python scripts/verify_google_gemini_access.py \
      --vertex-project my-gcp-project \
      --vertex-location us-central1 \
      --model gemini-2.5-flash
"""

import argparse
import os
import sys
from typing import Optional

from google import genai


def _short_error(exc: Exception) -> str:
  message = str(exc).strip()
  if len(message) > 2000:
    return message[:2000] + "\n... truncated ..."
  return message


def _test_gemini_api_key(api_key: str, model: str) -> bool:
  """Tests Gemini Developer API / Google AI Studio API-key access."""
  print("[1/2] Testing Gemini API key access...")
  if not api_key:
    print("SKIP: No API key provided via --api-key, GEMINI_API_KEY, or "
          "GOOGLE_API_KEY.")
    return False

  try:
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents="Reply with exactly: ok",
    )
    text = (response.text or "").strip()
    print(
        f"PASS: Gemini API key works with model '{model}'. Response: {text!r}")
    return True
  except Exception as exc:  # pylint: disable=broad-exception-caught
    print(f"FAIL: Gemini API key test failed:\n{_short_error(exc)}")
    return False


def _test_vertex_ai(project: Optional[str], location: str, model: str) -> bool:
  """Tests Vertex AI Gemini access using Application Default Credentials."""
  print("[2/2] Testing Vertex AI Gemini access with ADC...")
  if not project:
    print("SKIP: No --vertex-project provided. Vertex AI does not use an API "
          "key here.")
    return False

  try:
    client = genai.Client(vertexai=True, project=project, location=location)
    response = client.models.generate_content(
        model=model,
        contents="Reply with exactly: ok",
    )
    text = (response.text or "").strip()
    print(f"PASS: Vertex AI Gemini works with project '{project}', "
          f"location '{location}', model '{model}'. Response: {text!r}")
    return True
  except Exception as exc:  # pylint: disable=broad-exception-caught
    print(f"FAIL: Vertex AI Gemini test failed:\n{_short_error(exc)}")
    return False


def parse_args() -> argparse.Namespace:
  """Parses command-line arguments."""
  parser = argparse.ArgumentParser(
      description="Verify Gemini API-key access and optional Vertex AI access.")
  parser.add_argument(
      "--api-key",
      default=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "",
      help="Gemini API / AI Studio key. Defaults to GEMINI_API_KEY or "
      "GOOGLE_API_KEY.",
  )
  parser.add_argument(
      "--model",
      default="gemini-2.5-flash",
      help="Gemini model to test. Default: gemini-2.5-flash.",
  )
  parser.add_argument(
      "--vertex-project",
      default=os.getenv("GOOGLE_CLOUD_PROJECT", ""),
      help="GCP project ID for Vertex AI ADC test. Defaults to "
      "GOOGLE_CLOUD_PROJECT.",
  )
  parser.add_argument(
      "--vertex-location",
      default=os.getenv("VERTEX_AI_LOCATION") or "us-central1",
      help="Vertex AI location. Default: us-central1.",
  )
  parser.add_argument(
      "--skip-vertex",
      action="store_true",
      help="Only test Gemini API-key access.",
  )
  return parser.parse_args()


def main() -> int:
  args = parse_args()

  api_key_ok = _test_gemini_api_key(args.api_key, args.model)
  vertex_ok = False
  if not args.skip_vertex:
    vertex_ok = _test_vertex_ai(args.vertex_project, args.vertex_location,
                                args.model)

  print("\nSummary:")
  print(f"- Gemini API / AI Studio key: "
        f"{'OK' if api_key_ok else 'NOT OK or not tested'}")
  print(f"- Vertex AI Gemini / ADC: "
        f"{'OK' if vertex_ok else 'NOT OK or not tested'}")

  if api_key_ok or vertex_ok:
    return 0
  return 1


if __name__ == "__main__":
  sys.exit(main())
