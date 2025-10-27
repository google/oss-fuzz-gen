//
// Copyright (C) 2018 Red Hat, Inc.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Authors: Allen Webb <allenwebb@google.com>
//
#include <unistd.h>

#include <cstdint>
#include <sstream>
#include <stdexcept>

#include <usbguard/Exception.hpp>
#include <usbguard/USB.hpp>

using namespace usbguard;

namespace {

class DummyHooks : public USBDescriptorParserHooks {
public:
  void loadUSBDescriptor(USBDescriptorParser *parser, const USBDescriptor *descriptor) override {
    (void)parser;
    (void)descriptor;
  }
};
} // namespace

// Silence warning
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  DummyHooks hooks;
  USBDescriptorParser parser(hooks);
  std::istringstream data_stream(std::string(data, data + size));

  try {
    parser.parse(data_stream);
  } catch (const std::runtime_error &ex) {
    // Parser errors are ok.
  } catch (const usbguard::Exception &ex) {
    // Parser errors are ok.
  }

  return 0;
}

/* vim: set ts=2 sw=2 et */
