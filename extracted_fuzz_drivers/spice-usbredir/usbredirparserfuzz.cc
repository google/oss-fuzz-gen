/* usbredirparserfuzz.cc -- fuzzing for usbredirparser

   Copyright 2021 Michael Hanselmann

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <algorithm>
#include <array>
#include <memory>
#include <type_traits>

#include <cassert>
#include <cinttypes>
#include <cstring>
#include <limits>

#include <sys/types.h>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>

#include "usbredirfilter.h"
#include "usbredirparser.h"

namespace {
struct ParserDeleter {
  void operator()(struct usbredirparser *p) { usbredirparser_destroy(p); }
};

std::unique_ptr<struct usbredirparser, ParserDeleter> parser;
std::unique_ptr<FuzzedDataProvider> fdp;

void parser_log(void *priv, int level, const char *msg) {}

int wobbly_read_write_count(int count) {
  if (count > (1024 * 1024)) {
    return count;
  }

  return std::min(count, fdp->ConsumeIntegralInRange(1, 4 * count));
}

int parser_read(void *priv, uint8_t *data, int count) {
  // Simulate short reads
  return fdp->ConsumeData(data, wobbly_read_write_count(count));
}

// Read over complete input buffer to detect buffer overflows
void read_all(const void *data, size_t count) {
#ifdef __cpp_lib_smart_ptr_for_overwrite
  const auto buf = std::make_unique_for_overwrite<uint8_t[]>(count);
#else
  const auto buf = std::make_unique<uint8_t[]>(count);
#endif

  memcpy(buf.get(), data, count);
}

template <typename T, typename = std::enable_if_t<std::is_class<T>::value>> void read_all(const T *ptr) { read_all(ptr, sizeof(T)); }

int parser_write(void *priv, uint8_t *data, int count) {
  // Simulate short writes
  count = wobbly_read_write_count(count);

  read_all(data, count);

  return count;
}

void parser_device_connect(void *priv, struct usb_redir_device_connect_header *device_connect) {}

void parser_device_disconnect(void *priv) {}

void parser_reset(void *priv) {}

void parser_interface_info(void *priv, struct usb_redir_interface_info_header *info) {}

void parser_ep_info(void *priv, struct usb_redir_ep_info_header *ep_info) {}

void parser_set_configuration(void *priv, uint64_t id, struct usb_redir_set_configuration_header *set_configuration) {}

void parser_get_configuration(void *priv, uint64_t id) {}

void parser_configuration_status(void *priv, uint64_t id, struct usb_redir_configuration_status_header *config_status) {}

void parser_set_alt_setting(void *priv, uint64_t id, struct usb_redir_set_alt_setting_header *set_alt_setting) {}

void parser_get_alt_setting(void *priv, uint64_t id, struct usb_redir_get_alt_setting_header *get_alt_setting) {}

void parser_alt_setting_status(void *priv, uint64_t id, struct usb_redir_alt_setting_status_header *alt_setting_status) {}

void parser_start_iso_stream(void *priv, uint64_t id, struct usb_redir_start_iso_stream_header *start_iso_stream) {}

void parser_stop_iso_stream(void *priv, uint64_t id, struct usb_redir_stop_iso_stream_header *stop_iso_stream) {}

void parser_iso_stream_status(void *priv, uint64_t id, struct usb_redir_iso_stream_status_header *iso_stream_status) {}

void parser_start_interrupt_receiving(void *priv, uint64_t id, struct usb_redir_start_interrupt_receiving_header *start_interrupt_receiving) {}

void parser_stop_interrupt_receiving(void *priv, uint64_t id, struct usb_redir_stop_interrupt_receiving_header *stop_interrupt_receiving) {}

void parser_interrupt_receiving_status(void *priv, uint64_t id, struct usb_redir_interrupt_receiving_status_header *interrupt_receiving_status) {}

void parser_alloc_bulk_streams(void *priv, uint64_t id, struct usb_redir_alloc_bulk_streams_header *alloc_bulk_streams) {}

void parser_free_bulk_streams(void *priv, uint64_t id, struct usb_redir_free_bulk_streams_header *free_bulk_streams) {}

void parser_bulk_streams_status(void *priv, uint64_t id, struct usb_redir_bulk_streams_status_header *bulk_streams_status) {}

void parser_cancel_data_packet(void *priv, uint64_t id) {}

void parser_filter_reject(void *priv) {}

void parser_filter_filter(void *priv, struct usbredirfilter_rule *rules, int rules_count) { usbredirfilter_free(rules); }

void parser_control_packet(void *priv, uint64_t id, struct usb_redir_control_packet_header *control_packet, uint8_t *data, int data_len) {
  read_all(control_packet);
  read_all(data, data_len);
  usbredirparser_free_packet_data(parser.get(), data);
}

void parser_bulk_packet(void *priv, uint64_t id, struct usb_redir_bulk_packet_header *bulk_packet, uint8_t *data, int data_len) {
  read_all(bulk_packet);
  read_all(data, data_len);
  usbredirparser_free_packet_data(parser.get(), data);
}

void parser_iso_packet(void *priv, uint64_t id, struct usb_redir_iso_packet_header *iso_packet, uint8_t *data, int data_len) {
  read_all(iso_packet);
  read_all(data, data_len);
  usbredirparser_free_packet_data(parser.get(), data);
}

void parser_interrupt_packet(void *priv, uint64_t id, struct usb_redir_interrupt_packet_header *interrupt_packet, uint8_t *data, int data_len) {
  read_all(interrupt_packet);
  read_all(data, data_len);
  usbredirparser_free_packet_data(parser.get(), data);
}

void parser_buffered_bulk_packet(void *priv, uint64_t id, struct usb_redir_buffered_bulk_packet_header *buffered_bulk_header, uint8_t *data, int data_len) {
  read_all(buffered_bulk_header);
  read_all(data, data_len);
  usbredirparser_free_packet_data(parser.get(), data);
}

void *parser_alloc_lock() { return nullptr; }

void parser_lock(void *lock) {}

void parser_unlock(void *lock) {}

void parser_free_lock(void *lock) {}

void parser_hello(void *priv, struct usb_redir_hello_header *h) {}

void parser_device_disconnect_ack(void *priv) {}

void parser_start_bulk_receiving(void *priv, uint64_t id, struct usb_redir_start_bulk_receiving_header *start_bulk_receiving) { read_all(start_bulk_receiving); }

void parser_stop_bulk_receiving(void *priv, uint64_t id, struct usb_redir_stop_bulk_receiving_header *stop_bulk_receiving) { read_all(stop_bulk_receiving); }

void parser_bulk_receiving_status(void *priv, uint64_t id, struct usb_redir_bulk_receiving_status_header *bulk_receiving_status) { read_all(bulk_receiving_status); }

int try_unserialize(struct usbredirparser *parser, FuzzedDataProvider *fdp) {
  std::vector<uint8_t> state;
  size_t len = fdp->ConsumeIntegralInRange<size_t>(1, 64 * 1024);

  state.reserve(len);

  if (len >= 4) {
    const uint32_t magic = USBREDIRPARSER_SERIALIZE_MAGIC;
    assert(state.empty());
    state.resize(sizeof(magic));
    memcpy(state.data(), &magic, sizeof(magic));

    len -= 4;
  }

  if (len > 0) {
    const std::vector<uint8_t> payload{fdp->ConsumeBytes<uint8_t>(len)};

    state.insert(state.end(), payload.cbegin(), payload.cend());
  }

  if (state.empty()) {
    return 0;
  }

  state.shrink_to_fit();

  return usbredirparser_unserialize(parser, &state[0], state.size());
}

int try_serialize(struct usbredirparser *parser) {
  uint8_t *state = nullptr;
  int len = 0;
  int ret;

  ret = usbredirparser_serialize(parser, &state, &len);

  if (ret == 0) {
    free(state);
  }

  return ret;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::array<uint32_t, USB_REDIR_CAPS_SIZE> caps = {0};
  int ret;

  fdp = std::make_unique<FuzzedDataProvider>(data, size);

  parser.reset(usbredirparser_create());
  if (parser == nullptr) {
    return 1;
  }

  parser->log_func = parser_log;
  parser->read_func = parser_read;
  parser->write_func = parser_write;
  parser->device_connect_func = parser_device_connect;
  parser->device_disconnect_func = parser_device_disconnect;
  parser->reset_func = parser_reset;
  parser->interface_info_func = parser_interface_info;
  parser->ep_info_func = parser_ep_info;
  parser->set_configuration_func = parser_set_configuration;
  parser->get_configuration_func = parser_get_configuration;
  parser->configuration_status_func = parser_configuration_status;
  parser->set_alt_setting_func = parser_set_alt_setting;
  parser->get_alt_setting_func = parser_get_alt_setting;
  parser->alt_setting_status_func = parser_alt_setting_status;
  parser->start_iso_stream_func = parser_start_iso_stream;
  parser->stop_iso_stream_func = parser_stop_iso_stream;
  parser->iso_stream_status_func = parser_iso_stream_status;
  parser->start_interrupt_receiving_func = parser_start_interrupt_receiving;
  parser->stop_interrupt_receiving_func = parser_stop_interrupt_receiving;
  parser->interrupt_receiving_status_func = parser_interrupt_receiving_status;
  parser->alloc_bulk_streams_func = parser_alloc_bulk_streams;
  parser->free_bulk_streams_func = parser_free_bulk_streams;
  parser->bulk_streams_status_func = parser_bulk_streams_status;
  parser->cancel_data_packet_func = parser_cancel_data_packet;
  parser->control_packet_func = parser_control_packet;
  parser->bulk_packet_func = parser_bulk_packet;
  parser->iso_packet_func = parser_iso_packet;
  parser->interrupt_packet_func = parser_interrupt_packet;
  parser->alloc_lock_func = parser_alloc_lock;
  parser->lock_func = parser_lock;
  parser->unlock_func = parser_unlock;
  parser->free_lock_func = parser_free_lock;
  parser->hello_func = parser_hello;
  parser->filter_reject_func = parser_filter_reject;
  parser->filter_filter_func = parser_filter_filter;
  parser->device_disconnect_ack_func = parser_device_disconnect_ack;
  parser->start_bulk_receiving_func = parser_start_bulk_receiving;
  parser->stop_bulk_receiving_func = parser_stop_bulk_receiving;
  parser->bulk_receiving_status_func = parser_bulk_receiving_status;
  parser->buffered_bulk_packet_func = parser_buffered_bulk_packet;

  for (uint32_t &cap : caps) {
    cap = fdp->ConsumeIntegral<decltype(caps)::value_type>();
  }

  const int init_flags = fdp->ConsumeIntegral<uint8_t>() & (usbredirparser_fl_usb_host | usbredirparser_fl_no_hello);

  usbredirparser_init(parser.get(), "fuzzer", caps.data(), caps.size(), init_flags);

  if (fdp->ConsumeBool() && try_unserialize(parser.get(), fdp.get()) != 0) {
    goto out;
  }

  while (fdp->remaining_bytes() > 0 || usbredirparser_has_data_to_write(parser.get())) {
    if (fdp->ConsumeBool() && try_serialize(parser.get()) != 0) {
      goto out;
    }

    if (fdp->remaining_bytes() > 0) {
      ret = usbredirparser_do_read(parser.get());

      switch (ret) {
      case usbredirparser_read_parse_error:
        // Keep reading
        break;
      default:
        goto out;
      }

      if (fdp->ConsumeBool() && try_serialize(parser.get()) != 0) {
        goto out;
      }
    }

    while (usbredirparser_has_data_to_write(parser.get())) {
      ret = usbredirparser_do_write(parser.get());
      if (ret < 0) {
        goto out;
      }
    }
  }

out:
  parser.reset();

  return 0;
}

/* vim: set sw=4 sts=4 et : */
