// Copyright 2021 The Pigweed Authors
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

#include <cstddef>

#include "pw_bluetooth_hci/packet.h"
#include "pw_bluetooth_hci/uart_transport.h"
#include "pw_bytes/span.h"
#include "pw_span/span.h"
#include "pw_status/status_with_size.h"
#include "pw_stream/null_stream.h"

namespace pw::bluetooth_hci {
namespace {

// A very simple structure unaware fuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  DecodedPacketCallback packet_callback = [](const Packet &packet) {
    // Instead of doing nothing with the random packet content, attempt to
    // consume the entire packet API by streaming it into the null stream.
    stream::Writer &stream = stream::NullStream::Instance();

    switch (packet.type()) {
    case Packet::Type::kCommandPacket: {
      const CommandPacket &command_packet = packet.command_packet();

      const uint16_t opcode = command_packet.opcode();
      stream.Write(as_bytes(span<const uint16_t>(&opcode, 1))).IgnoreError();

      const uint16_t opcode_command_field = command_packet.opcode_command_field();
      stream.Write(as_bytes(span<const uint16_t>(&opcode_command_field, 1))).IgnoreError();

      const uint8_t opcode_group_field = command_packet.opcode_group_field();
      stream.Write(as_bytes(span<const uint8_t>(&opcode_group_field, 1))).IgnoreError();

      stream.Write(command_packet.parameters()).IgnoreError();
      return;
    }

    case Packet::Type::kAsyncDataPacket: {
      const AsyncDataPacket &async_data_packet = packet.async_data_packet();

      const uint16_t handle_and_fragmentation_bits = async_data_packet.handle_and_fragmentation_bits();
      stream.Write(as_bytes(span<const uint16_t>(&handle_and_fragmentation_bits, 1))).IgnoreError();

      const uint16_t handle = async_data_packet.handle();
      stream.Write(as_bytes(span<const uint16_t>(&handle, 1))).IgnoreError();

      const uint8_t pb_flag = async_data_packet.pb_flag();
      stream.Write(as_bytes(span<const uint8_t>(&pb_flag, 1))).IgnoreError();

      const uint8_t bc_flag = async_data_packet.bc_flag();
      stream.Write(as_bytes(span<const uint8_t>(&bc_flag, 1))).IgnoreError();

      stream.Write(async_data_packet.data()).IgnoreError();
      return;
    }

    case Packet::Type::kSyncDataPacket: {
      const SyncDataPacket &sync_data_packet = packet.sync_data_packet();

      const uint16_t handle_and_status_bits = sync_data_packet.handle_and_status_bits();
      stream.Write(as_bytes(span<const uint16_t>(&handle_and_status_bits, 1))).IgnoreError();

      const uint16_t handle = sync_data_packet.handle();
      stream.Write(as_bytes(span<const uint16_t>(&handle, 1))).IgnoreError();

      const uint8_t packet_status_flag = sync_data_packet.packet_status_flag();
      stream.Write(as_bytes(span<const uint8_t>(&packet_status_flag, 1))).IgnoreError();

      stream.Write(sync_data_packet.data()).IgnoreError();
      return;
    }

    case Packet::Type::kEventPacket: {
      const EventPacket &event_packet = packet.event_packet();

      const uint8_t event_code = event_packet.event_code();
      stream.Write(as_bytes(span<const uint8_t>(&event_code, 1))).IgnoreError();

      stream.Write(event_packet.parameters()).IgnoreError();
      return;
    }

    default:
      return;
    }
  };

  const StatusWithSize result = DecodeHciUartData(as_bytes(span(data, size)), packet_callback);
  result.status().IgnoreError();
  return 0;
}

} // namespace
} // namespace pw::bluetooth_hci
