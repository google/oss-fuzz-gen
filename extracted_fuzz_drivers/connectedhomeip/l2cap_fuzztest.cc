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
#include <pw_random/fuzzer.h>

#include "pw_bluetooth_sapphire/internal/host/common/byte_buffer.h"
#include "pw_bluetooth_sapphire/internal/host/common/random.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/channel.h"
#include "pw_bluetooth_sapphire/internal/host/l2cap/channel_manager.h"
#include "pw_bluetooth_sapphire/internal/host/testing/controller_test.h"
#include "pw_bluetooth_sapphire/internal/host/testing/controller_test_double_base.h"

namespace bt::testing {

// ACL Buffer Info
constexpr size_t kMaxDataPacketLength = 64;
// Ensure outbound ACL packets aren't queued.
constexpr size_t kBufferMaxNumPackets = 1000;

// If the packet size is too large, we consume too much of the fuzzer data per
// packet without much benefit.
constexpr uint16_t kMaxAclPacketSize = 100;

constexpr hci_spec::ConnectionHandle kHandle = 0x0001;

// Don't toggle connection too often or else l2cap won't get very far.
constexpr float kToggleConnectionChance = 0.04;

class FuzzerController : public ControllerTestDoubleBase, public WeakSelf<FuzzerController> {
public:
  explicit FuzzerController(pw::async::Dispatcher &pw_dispatcher) : ControllerTestDoubleBase(pw_dispatcher), WeakSelf(this) {}
  ~FuzzerController() override = default;

private:
  // Controller overrides:
  void SendCommand(pw::span<const std::byte> command) override {}
  void SendAclData(pw::span<const std::byte> data) override {}
  void SendScoData(pw::span<const std::byte> data) override {}
};

// Reuse ControllerTest test fixture code even though we're not using gtest.
using TestingBase = FakeDispatcherControllerTest<FuzzerController>;
class DataFuzzTest : public TestingBase {
public:
  DataFuzzTest(const uint8_t *data, size_t size) : data_(data, size), rng_(&data_) {
    set_random_generator(&rng_);
    TestingBase::SetUp();
    const auto bredr_buffer_info = hci::DataBufferInfo(kMaxDataPacketLength, kBufferMaxNumPackets);
    InitializeACLDataChannel(bredr_buffer_info);

    channel_manager_ = l2cap::ChannelManager::Create(transport()->acl_data_channel(), transport()->command_channel(),
                                                     /*random_channel_ids=*/true, dispatcher());
  }

  ~DataFuzzTest() override {
    channel_manager_ = nullptr;
    bt::set_random_generator(nullptr);
    TestingBase::TearDown();
  }

  void TestBody() override {
    RegisterService();

    while (data_.remaining_bytes() > 0) {
      bool run_loop = data_.ConsumeBool();
      if (run_loop) {
        RunUntilIdle();
      }

      if (!SendAclPacket()) {
        break;
      }

      if (data_.ConsumeProbability<float>() < kToggleConnectionChance) {
        ToggleConnection();
      }
    }

    RunUntilIdle();
  }

  bool SendAclPacket() {
    if (data_.remaining_bytes() < sizeof(uint64_t)) {
      return false;
    }
    // Consumes 8 bytes.
    auto packet_size = data_.ConsumeIntegralInRange<uint16_t>(sizeof(hci_spec::ACLDataHeader), std::min(static_cast<size_t>(kMaxAclPacketSize), data_.remaining_bytes()));

    auto packet_data = data_.ConsumeBytes<uint8_t>(packet_size);
    if (packet_data.size() < packet_size) {
      // Check if we ran out of fuzzer data.
      return false;
    }

    MutableBufferView packet_view(packet_data.data(), packet_data.size());

    // Use correct length so packets aren't rejected for invalid length.
    packet_view.AsMutable<hci_spec::ACLDataHeader>()->data_total_length = htole16(packet_view.size() - sizeof(hci_spec::ACLDataHeader));

    // Use correct connection handle so packets aren't rejected/queued for
    // invalid handle.
    uint16_t handle_and_flags = packet_view.ReadMember<&hci_spec::ACLDataHeader::handle_and_flags>();
    handle_and_flags &= 0xF000; // Keep flags, clear handle.
    handle_and_flags |= kHandle;
    packet_view.AsMutable<hci_spec::ACLDataHeader>()->handle_and_flags = handle_and_flags;

    BT_ASSERT(test_device()->SendACLDataChannelPacket(packet_view));
    return true;
  }

  void RegisterService() {
    channel_manager_->RegisterService(l2cap::kAVDTP, l2cap::ChannelParameters(), [this](l2cap::Channel::WeakPtr chan) {
      if (!chan.is_alive()) {
        return;
      }
      chan->Activate(/*rx_callback=*/[](auto) {}, /*closed_callback=*/
                     [this, id = chan->id()] { channels_.erase(id); });
      channels_.emplace(chan->id(), std::move(chan));
    });
  }

  void ToggleConnection() {
    if (connection_) {
      channel_manager_->RemoveConnection(kHandle);
      connection_ = false;
      return;
    }

    channel_manager_->AddACLConnection(
        kHandle, pw::bluetooth::emboss::ConnectionRole::CENTRAL,
        /*link_error_callback=*/[] {},
        /*security_callback=*/[](auto, auto, auto) {});
    connection_ = true;
  }

private:
  FuzzedDataProvider data_;
  pw::random::FuzzerRandomGenerator rng_;
  std::unique_ptr<l2cap::ChannelManager> channel_manager_;
  bool connection_ = false;
  std::unordered_map<l2cap::ChannelId, l2cap::Channel::WeakPtr> channels_;
};

} // namespace bt::testing

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bt::testing::DataFuzzTest fuzz(data, size);
  fuzz.TestBody();
  return 0;
}
