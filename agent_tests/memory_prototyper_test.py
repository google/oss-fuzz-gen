"""Focused tests for error-memory selection ablations."""

import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

# Keep these unit tests independent of optional Cloud SQL client dependencies.
# All database operations are mocked below.
try:
  import pymysql  # pylint: disable=unused-import
except ImportError:
  sys.modules["pymysql"] = types.ModuleType("pymysql")

try:
  from google.cloud.sql import connector as _connector  # pylint: disable=unused-import
except ImportError:
  sql_module = types.ModuleType("google.cloud.sql")
  connector_module = types.ModuleType("google.cloud.sql.connector")
  connector_module.Connector = mock.Mock
  connector_module.IPTypes = SimpleNamespace(PUBLIC="PUBLIC")
  sql_module.connector = connector_module
  sys.modules["google.cloud.sql"] = sql_module
  sys.modules["google.cloud.sql.connector"] = connector_module

import run_all_experiments
from agent import memory_prototyper as memory_module
from agent.memory_prototyper import MemoryPrototyper
from memory_helper import cloudsql


def _hit(entry_id: int, project: str = "other") -> dict:
  return {
      "id": entry_id,
      "project": project,
      "error_type": f"error-{entry_id}",
      "func_name": f"function-{entry_id}",
      "distance": entry_id / 100,
      "confidence_level": 3,
      "fix_action": f"fix-{entry_id}",
      "patch_text": f"patch-{entry_id}",
  }


def _agent(mode: str, *, seed: int = 7, scope: str = "all"):
  agent = MemoryPrototyper.__new__(MemoryPrototyper)
  agent.args = SimpleNamespace(
      memory_selection_mode=mode,
      memory_random_seed=seed,
      memory_project_filter=scope,
      memory_model_filter=None,
      memory_created_before_or_on="2026-01-02T03:04:05Z",
  )
  agent.text_embedding_model = object()
  agent._online_update_enabled = False
  agent._stats_buffer = {}
  agent._chat_blocks = []
  agent._last_attempted_entry_id = None
  agent._last_attempted_project_match = False
  agent._last_round_had_hits = False
  agent._last_raw_error_text = ""
  agent._last_normalized_error = ""
  agent._prev_fuzz_target_for_diff = ""
  agent._prev_build_script_for_diff = ""
  return agent


def _result(project: str = "current"):
  bench = SimpleNamespace(
      id="current-target",
      project=project,
      language="c++",
      target_name="target",
      function_signature="void target()",
  )
  return SimpleNamespace(
      compile_error="undefined reference",
      compile_log="compile log",
      benchmark=bench,
      trial=1,
      fuzz_target_source="fuzz source",
      build_script_source="build source",
      binary_exists=False,
      compiles=False,
      chat_history={},
  )


class MemorySelectionTest(unittest.TestCase):

  def test_cli_default_remains_planner(self):
    argv = [
        "run_all_experiments.py", "--benchmarks-directory",
        "benchmark-sets/balanced"
    ]
    with mock.patch.object(sys, "argv", argv):
      args = run_all_experiments.parse_args()
    self.assertEqual("planner", args.memory_selection_mode)
    self.assertEqual(0, args.memory_random_seed)

  def test_planner_calls_planner_and_returns_its_choice(self):
    agent = _agent("planner")
    hits = [_hit(i) for i in range(1, 6)]
    agent._llm_choose_action_plan = mock.Mock(return_value=hits[2])
    with mock.patch.object(memory_module, "knn_search_error_full_with_norm",
                           return_value=("normalized", hits)):
      _, selected = agent._maybe_get_memory_references(_result())
    agent._llm_choose_action_plan.assert_called_once()
    self.assertEqual([3], [entry["id"] for entry in selected])

  def test_top_1_bypasses_planner_and_injects_first_rank(self):
    agent = _agent("top-1")
    hits = [_hit(i) for i in range(1, 6)]
    agent._llm_choose_action_plan = mock.Mock()
    with mock.patch.object(memory_module, "knn_search_error_full_with_norm",
                           return_value=("normalized", hits)):
      _, selected = agent._maybe_get_memory_references(_result())
    agent._llm_choose_action_plan.assert_not_called()
    self.assertEqual([1], [entry["id"] for entry in selected])

  def test_top_5_bypasses_planner_and_preserves_rank_order(self):
    agent = _agent("top-5")
    hits = [_hit(i) for i in range(1, 6)]
    agent._llm_choose_action_plan = mock.Mock()
    with mock.patch.object(memory_module, "knn_search_error_full_with_norm",
                           return_value=("normalized", hits)):
      _, selected = agent._maybe_get_memory_references(_result())
    agent._llm_choose_action_plan.assert_not_called()
    self.assertEqual([1, 2, 3, 4, 5],
                     [entry["id"] for entry in selected])
    prompt = agent._format_reference_solutions(selected)
    self.assertLess(prompt.index('rank="1"'), prompt.index('rank="5"'))
    self.assertEqual(5, prompt.count("<reference_solution rank="))

  def test_top_5_accepts_fewer_than_five_eligible_entries(self):
    agent = _agent("top-5")
    hits = [_hit(i) for i in range(1, 4)]
    agent._llm_choose_action_plan = mock.Mock()
    with mock.patch.object(memory_module, "knn_search_error_full_with_norm",
                           return_value=("normalized", hits)):
      _, selected = agent._maybe_get_memory_references(_result())
    self.assertEqual([1, 2, 3], [entry["id"] for entry in selected])
    self.assertEqual(3, agent._format_reference_solutions(selected).count(
        "<reference_solution rank="))

  def test_random_1_is_single_deterministic_and_not_knn(self):
    agent = _agent("random-1", seed=123)
    selected_hit = _hit(17)
    agent._llm_choose_action_plan = mock.Mock()
    seeds = []

    def fake_random(*args, **kwargs):
      seeds.append(kwargs["random_seed"])
      return "normalized", [selected_hit], 40

    with mock.patch.object(memory_module,
                           "random_search_error_full_with_norm",
                           side_effect=fake_random), mock.patch.object(
                               memory_module,
                               "knn_search_error_full_with_norm") as knn:
      _, first = agent._maybe_get_memory_references(_result())
      _, second = agent._maybe_get_memory_references(_result())
    knn.assert_not_called()
    agent._llm_choose_action_plan.assert_not_called()
    self.assertEqual([17], [entry["id"] for entry in first])
    self.assertEqual([17], [entry["id"] for entry in second])
    self.assertEqual(seeds[0], seeds[1])

  def test_cutoff_and_project_filters_are_forwarded_unchanged(self):
    for scope, expected in (("all", (None, None)),
                            ("only-current", ("current", None)),
                            ("exclude-current", (None, "current"))):
      agent = _agent("top-1", scope=scope)
      agent._llm_choose_action_plan = mock.Mock()
      with mock.patch.object(
          memory_module,
          "knn_search_error_full_with_norm",
          return_value=("normalized", [_hit(1)]),
      ) as search:
        agent._maybe_get_memory_references(_result())
      kwargs = search.call_args.kwargs
      self.assertEqual(expected, (kwargs["include_project"],
                                  kwargs["exclude_project"]))
      self.assertEqual("2026-01-02T03:04:05Z",
                       kwargs["created_before_or_on"])

  def test_read_only_disables_confidence_2_and_3_writes(self):
    agent = _agent("planner")
    successful = _result()
    successful.success = True
    with mock.patch.object(memory_module,
                           "maybe_register_fix_episode") as register, \
         mock.patch.object(memory_module,
                           "update_stats_from_buffer") as update:
      agent._flush_stats_on_success(successful)
      agent._maybe_register_progress_fix(successful)
    register.assert_not_called()
    update.assert_not_called()

  def test_exact_cutoff_uses_timestamp_comparison_in_utc(self):
    clause, value = cloudsql._created_at_cutoff_clause(  # pylint: disable=protected-access
        "2026-01-02T14:04:05+11:00")
    self.assertEqual("created_at <= %s", clause)
    self.assertEqual("2026-01-02 03:04:05", value)

    date_clause, date_value = cloudsql._created_at_cutoff_clause(  # pylint: disable=protected-access
        "2026-01-02")
    self.assertEqual("DATE(created_at) <= %s", date_clause)
    self.assertEqual("2026-01-02", date_value)


if __name__ == "__main__":
  unittest.main()
