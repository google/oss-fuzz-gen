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
"""Tests for build-repair report evidence formatting."""

# pylint: disable=protected-access

import unittest

from report import fix_build


class FixBuildReportTest(unittest.TestCase):
  """Checks evidence filtering and PR-ready summaries."""

  def setUp(self):
    self.trace = {
        'nodes': [{
            'action_and_intent': {
                'root_cause_commit_sha': 'None',
                'repair_strategy': 'Initial baseline state configuration.',
            },
            'semantic_memory': {
                'unsolved_problems':
                    'Meson rejected -Dnamed-lto=off.',
                'reflection_analysis':
                    ('Meson only accepts disabled, auto, thin, or full for '
                     'named-lto. The invalid value stops configuration before '
                     'compilation.'),
            },
        }, {
            'action_and_intent': {
                'repair_strategy':
                    ('Method: Replaced -Dnamed-lto=off with '
                     '-Dnamed-lto=disabled in build.sh. Reasoning: The '
                     'supported value allows Meson configuration to complete '
                     'and the fuzz targets to build.'),
            },
            'semantic_memory': {
                'unsolved_problems':
                    ('The patch.diff failed to apply due to context mismatch.'),
                'reflection_analysis': 'None',
            },
        }]
    }

  def test_trace_uses_unverified_for_none_commit(self):
    root_cause, evolution, root_status = fix_build._trace_summary(self.trace)

    self.assertEqual(root_status, 'Unverified')
    self.assertNotIn('patch.diff', evolution)
    self.assertIn('invalid value stops configuration', evolution)
    self.assertNotEqual(root_cause, 'None')

  def test_pr_summary_describes_cause_and_fix(self):
    root_cause, _, _ = fix_build._trace_summary(self.trace)

    summary = fix_build._pr_summary('bind9', 'Success', root_cause, self.trace)

    self.assertIn("Resolves bind9's OSS-Fuzz build failure", summary)
    self.assertIn('-Dnamed-lto=disabled', summary)
    self.assertNotIn('Final validation', summary)
    self.assertNotIn('step_1', summary)


if __name__ == '__main__':
  unittest.main()
