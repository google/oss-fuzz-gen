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
#include <pw_random/fuzzer.h>

#include "pw_bluetooth_sapphire/internal/host/common/byte_buffer.h"
#include "pw_bluetooth_sapphire/internal/host/hci-spec/protocol.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/bredr_dynamic_channel.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/bredr_signaling_channel.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/fake_channel.h"

constexpr static bt::hci_spec::ConnectionHandle kTestHandle = 0x0001;

bt::l2cap::ChannelParameters ConsumeChannelParameters(FuzzedDataProvider &provider) {
  bt::l2cap::ChannelParameters params;

  bool use_defaults = provider.ConsumeBool();
  if (use_defaults) {
    return params;
  }

  params.mode = provider.ConsumeBool() ? bt::l2cap::RetransmissionAndFlowControlMode::kBasic : bt::l2cap::RetransmissionAndFlowControlMode::kEnhancedRetransmission;
  params.max_rx_sdu_size = provider.ConsumeIntegral<uint16_t>();
  return params;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  pw::random::FuzzerRandomGenerator rng(&provider);
  bt::set_random_generator(&rng);

  // Dispatcher needed for signaling channel response timeout.
  pw::async::test::FakeDispatcher dispatcher;

  auto fake_chan = std::make_unique<bt::l2cap::testing::FakeChannel>(bt::l2cap::kSignalingChannelId, bt::l2cap::kSignalingChannelId, kTestHandle, bt::LinkType::kACL);

  bt::l2cap::internal::BrEdrSignalingChannel sig_chan(fake_chan->GetWeakPtr(), pw::bluetooth::emboss::ConnectionRole::CENTRAL, dispatcher);

  auto open_cb = [](auto chan) {};
  auto close_cb = [](auto chan) {};
  auto service_chan_cb = [](auto chan) {};

  auto service_cb = [&](auto psm) {
    // Reject some PSMs.
    if (provider.ConsumeBool()) {
      return std::optional<bt::l2cap::internal::DynamicChannelRegistry::ServiceInfo>();
    }

    auto params = ConsumeChannelParameters(provider);
    return std::optional(bt::l2cap::internal::DynamicChannelRegistry::ServiceInfo(params, service_chan_cb));
  };
  bt::l2cap::internal::BrEdrDynamicChannelRegistry registry(&sig_chan, close_cb, service_cb,
                                                            /*random_channel_ids=*/true);

  while (provider.remaining_bytes() > 0) {
    // Receive an l2cap packet.
    uint16_t data_size = provider.ConsumeIntegral<uint16_t>();
    auto packet = provider.ConsumeBytes<uint8_t>(data_size);
    fake_chan->Receive(bt::BufferView(packet.data(), packet.size()));

    if (provider.ConsumeBool()) {
      registry.OpenOutbound(bt::l2cap::kAVDTP, ConsumeChannelParameters(provider), open_cb);
    }

    if (provider.ConsumeBool()) {
      dispatcher.RunFor(std::chrono::seconds(1));
    }
  }

  bt::set_random_generator(nullptr);
  return 0;
}
