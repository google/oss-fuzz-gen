// Copyright 2023 The Pigweed Authors
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

#include <fuzzer/FuzzedDataProvider.h>
#include <pw_async/fake_dispatcher.h>

#include <algorithm>
#include <limits>

#include "pw_bluetooth_sapphire/internal/host/common/byte_buffer.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/enhanced_retransmission_mode_engines.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/fragmenter.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/l2cap_defs.h"

constexpr static bt::hci_spec::ConnectionHandle kTestHandle = 0x0001;
constexpr bt::l2cap::ChannelId kTestChannelId = 0x0001;

void NoOpTxCallback(bt::ByteBufferPtr) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  pw::async::test::FakeDispatcher dispatcher;

  uint8_t tx_window = std::max(provider.ConsumeIntegral<uint8_t>(), static_cast<uint8_t>(1u));

  uint8_t max_transmissions = provider.ConsumeIntegral<uint8_t>();
  uint16_t max_tx_sdu_size = std::max(provider.ConsumeIntegral<uint16_t>(), bt::l2cap::kMinACLMTU);

  bool failure = false;
  auto failure_cb = [&failure] { failure = true; };

  auto [rx_engine, tx_engine] = bt::l2cap::internal::MakeLinkedEnhancedRetransmissionModeEngines(kTestChannelId, max_tx_sdu_size, max_transmissions, tx_window, NoOpTxCallback, failure_cb, dispatcher);

  // In the real stack, the engines are shut down on failure, so we do the same
  // here.
  while (provider.remaining_bytes() > 0 && !failure) {
    bool tx = provider.ConsumeBool();
    if (tx) {
      auto n_bytes = provider.ConsumeIntegral<uint16_t>();
      auto bytes = provider.ConsumeBytes<uint8_t>(n_bytes);
      tx_engine->QueueSdu(std::make_unique<bt::DynamicByteBuffer>(bt::BufferView(bytes)));
    } else {
      bt::l2cap::Fragmenter fragmenter(kTestHandle);
      auto n_bytes = provider.ConsumeIntegral<uint16_t>();
      auto bytes = provider.ConsumeBytes<uint8_t>(n_bytes);
      bool append_fcs = provider.ConsumeBool();
      if (append_fcs) {
        const size_t bounded_size = std::min(bytes.size(), std::numeric_limits<uint16_t>::max() - sizeof(bt::l2cap::FrameCheckSequence));
        bytes.resize(bounded_size);
      }
      auto fcs_option = append_fcs ? bt::l2cap::FrameCheckSequenceOption::kIncludeFcs : bt::l2cap::FrameCheckSequenceOption::kNoFcs;
      auto pdu = fragmenter.BuildFrame(kTestChannelId, bt::BufferView(bytes), fcs_option);
      rx_engine->ProcessPdu(std::move(pdu));
    }

    // Run for 0-255 seconds, which is enough to trigger poll timer and monitor
    // timer.
    auto run_duration = std::chrono::seconds(provider.ConsumeIntegral<uint8_t>());
    dispatcher.RunFor(run_duration);
  }

  return 0;
}
