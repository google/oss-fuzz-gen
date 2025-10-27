/* usbredirfilterfuzz.cc -- fuzzing for usbredirfilter

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

#include <cstdio>
#include <limits>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "usbredirfilter.h"

namespace {
struct FilterDeleter {
  void operator()(void *ptr) { usbredirfilter_free(ptr); }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static FILE *dev_null = nullptr;

  if (dev_null == nullptr) {
    dev_null = fopen("/dev/null", "wb");
    if (dev_null == nullptr) {
      perror("open /dev/null");
      abort();
    }
  }

  FuzzedDataProvider fdp{data, size};
  std::unique_ptr<usbredirfilter_rule, FilterDeleter> rules;
  int ret, rules_count;

  const std::string token_sep = fdp.ConsumeBytesAsString(1), rule_sep = fdp.ConsumeBytesAsString(1);

  {
    usbredirfilter_rule *rules_ptr = nullptr;

    ret = usbredirfilter_string_to_rules(fdp.ConsumeRandomLengthString().c_str(), token_sep.c_str(), rule_sep.c_str(), &rules_ptr, &rules_count);

    if (ret != 0 || rules_ptr == nullptr) {
      return 1;
    }

    rules.reset(rules_ptr);
  }

  usbredirfilter_verify(rules.get(), rules_count);
  usbredirfilter_print(rules.get(), rules_count, dev_null);

  {
    std::unique_ptr<char, FilterDeleter> str;

    str.reset(usbredirfilter_rules_to_string(rules.get(), rules_count, token_sep.c_str(), rule_sep.c_str()));
  }

  {
    const int interface_count = fdp.ConsumeIntegralInRange(1, 128);
    std::vector<uint8_t> interface_class = fdp.ConsumeBytes<uint8_t>(interface_count), interface_subclass = fdp.ConsumeBytes<uint8_t>(interface_count), interface_protocol = fdp.ConsumeBytes<uint8_t>(interface_count);

    // Fill with zeros up to the desired length
    interface_class.resize(interface_count, 0);
    interface_subclass.resize(interface_count, 0);
    interface_protocol.resize(interface_count, 0);

    usbredirfilter_check(rules.get(), rules_count, fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(), &interface_class[0], &interface_subclass[0], &interface_protocol[0], interface_count, fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint8_t>());
  }

  return 0;
}

/* vim: set sw=4 sts=4 et : */
