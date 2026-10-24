#include <stddef.h>
#include <stdint.h>

extern int run_last_command();

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Since run_last_command does not take any parameters, we can directly call it.
    run_last_command();

    return 0;
}