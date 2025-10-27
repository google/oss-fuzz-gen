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

#include <tao/pegtl.hpp>
#if TAO_PEGTL_VERSION_MAJOR >= 3
#include <tao/pegtl/contrib/trace.hpp>
#else
#include <tao/pegtl/contrib/tracer.hpp>
#endif
#include <usbguard/Rule.hpp>
#include <usbguard/RuleParser.hpp>

using namespace usbguard;

// Silence warning
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string rule_spec(data, data + size);

  try {
    auto rule = parseRuleFromString(rule_spec, "fuzzer_input", 0, false /*trace*/);
  } catch (const RuleParserError &ex) {
    // An invalid rule is ok.
  }

  return 0;
}

/* vim: set ts=2 sw=2 et */
