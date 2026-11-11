#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the correct header file for get_diversion_param function
#include "/src/kamailio/src/core/parser/parse_diversion.h"

// Include the necessary header for the sip_msg structure
#include "/src/kamailio/src/core/sr_module.h"

// Include C++ compatibility for the fuzzer function
#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize sip_msg structure
    struct sip_msg msg;
    memset(&msg, 0, sizeof(msg));

    // Initialize str structure
    str param;
    param.s = (char *)data; // Cast data to char* for str structure
    param.len = size;

    // Call the function under test
    str *result = get_diversion_param(&msg, &param);

    // In a real fuzzing scenario, you might want to check the result or further process it
    // For now, we just ensure the function is called with non-NULL arguments

    return 0;
}

#ifdef __cplusplus
}
#endif