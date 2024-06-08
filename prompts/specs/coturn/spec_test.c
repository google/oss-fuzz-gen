#include <fuzzer/FuzzedDataProvider.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apputils.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider stream(data, size);
    // follow the spec within the comments
    // precondition: @size > 10 and @size < 5120, and @data is a valid buffer, and @size is the size of the buffer
    // ensure: the function should call the `stun_is_command_message_full_check_str` function by passing the following parameters:
        // 1. the data buffer: this para needs to be mutated by the fuzzer
        // 2. the size of the data buffer: this para needs to be mutated by the fuzzer, and should be the same as the size of the data buffer
        // 3. must_check_fingerprint: 1
        // 4. fingerprint_present: NULL
    // postcondition: the function should return 0
    
  return 0;
}