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
"""Offline tests for Vertex rate-limit handling."""

import asyncio
import os
import sys
import unittest
from unittest import mock

os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')
sys.path.insert(0, os.path.dirname(__file__))

from google.adk.agents.invocation_context import InvocationContext
from google.adk.models import LlmRequest
from google.adk.sessions import InMemorySessionService

import agent


class _FailingAgent(agent.BaseAgent):
  """Agent that raises the supplied error when run."""

  def __init__(self, error):
    super().__init__(name='failing_agent')
    self._error = error

  async def _run_async_impl(self, context):
    raise self._error
    yield

  async def _test_context(self):
    session_service = InMemorySessionService()
    session = await session_service.create_session(app_name='test',
                                                   user_id='user',
                                                   session_id='session')
    return InvocationContext(
        invocation_id='invocation',
        session_service=session_service,
        session=session,
        agent=self,
    )


class VertexRateLimitTest(unittest.TestCase):
  """Tests process-local Vertex request pacing and quota recovery."""

  def test_litellm_builtin_retries_are_disabled(self):
    self.assertEqual(agent.litellm.num_retries, 0)

  def test_limiter_enforces_single_flight_and_interval(self):

    async def test():
      limiter = agent._VertexRequestLimiter()
      starts = []

      async def request(index):
        async with limiter.request_slot():
          starts.append((index, asyncio.get_running_loop().time()))
          await asyncio.sleep(0.01)

      await asyncio.gather(*(request(index) for index in range(3)))
      return starts

    starts = asyncio.run(test())
    self.assertEqual([index for index, _ in starts], [0, 1, 2])
    self.assertGreaterEqual(starts[1][1] - starts[0][1], 0.01)
    self.assertGreaterEqual(starts[2][1] - starts[1][1], 0.01)

  def test_rate_limit_is_retried_after_shared_cooldown(self):
    request_times = []

    async def fake_generate(self, llm_request, stream=False):
      request_times.append(asyncio.get_running_loop().time())
      if len(request_times) == 1:
        raise RuntimeError('429 Too Many Requests')
      yield 'response'

    async def test():
      model = agent.VertexRateLimitedLiteLlm(model='vertex_ai/gemini-test')
      responses = []
      async for response in model.generate_content_async(
          LlmRequest(model='vertex_ai/gemini-test')):
        responses.append(response)
      return responses

    with mock.patch.object(agent.LiteLlm, 'generate_content_async',
                           fake_generate), \
         mock.patch.object(agent, 'VERTEX_REQUEST_LIMITER',
                           agent._VertexRequestLimiter()), \
         mock.patch.object(agent, 'VERTEX_REQUEST_INTERVAL_SECONDS', 0), \
         mock.patch.object(agent, 'VERTEX_RATE_LIMIT_DELAYS_SECONDS', (0.02,)), \
         mock.patch.object(agent.random, 'uniform', lambda _, high: high):
      responses = asyncio.run(test())

    self.assertEqual(responses, ['response'])
    self.assertEqual(len(request_times), 2)
    self.assertGreaterEqual(request_times[1] - request_times[0], 0.02)

  def test_non_rate_limit_errors_are_not_retried(self):
    request_count = 0

    async def fake_generate(self, llm_request, stream=False):
      nonlocal request_count
      request_count += 1
      raise ValueError('invalid request')
      yield

    async def test():
      model = agent.VertexRateLimitedLiteLlm(model='vertex_ai/gemini-test')
      async for _ in model.generate_content_async(
          LlmRequest(model='vertex_ai/gemini-test')):
        pass

    with mock.patch.object(agent.LiteLlm, 'generate_content_async',
                           fake_generate), \
         mock.patch.object(agent, 'VERTEX_REQUEST_LIMITER',
                           agent._VertexRequestLimiter()), \
         mock.patch.object(agent, 'VERTEX_REQUEST_INTERVAL_SECONDS', 0), \
         mock.patch.object(agent, 'VERTEX_RATE_LIMIT_DELAYS_SECONDS', (0.02,)):
      with self.assertRaisesRegex(ValueError, 'invalid request'):
        asyncio.run(test())
    self.assertEqual(request_count, 1)

  def test_exhausted_rate_limit_errors_are_routed(self):
    error = agent.VertexRateLimitExhaustedError('retries exhausted')
    routing_agent = agent.RateLimitRoutingAgent(
        name='failing_agent', subject_agent=_FailingAgent(error))
    failing_agent = routing_agent.subject_agent

    async def test():
      context = await failing_agent._test_context()
      return [event async for event in routing_agent._run_async_impl(context)]

    events = asyncio.run(test())
    self.assertEqual(len(events), 1)
    self.assertEqual(events[0].actions.state_delta,
                     {'rate_limit_exhausted_agent': 'failing_agent'})
    self.assertEqual(events[0].actions.route, 'rate_limit')


if __name__ == '__main__':
  unittest.main()
