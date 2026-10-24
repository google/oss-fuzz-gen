#include <stdint.h>
#include <stdio.h>

// Assume the function is defined somewhere
int interactive();

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // The function interactive() does not take any parameters, 
    // so we can call it directly.
    interactive();
    
    return 0;
}