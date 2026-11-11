#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

extern JanetFiber *janet_loop1(void);

int LLVMFuzzerTestOneInput_497(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a Janet array from the input data
    JanetArray *array = janet_array(size);
    for (size_t i = 0; i < size; i++) {
        janet_array_push(array, janet_wrap_integer(data[i]));
    }

    // Call the janet_loop1 function
    JanetFiber *fiber = janet_loop1();

    // Perform additional operations if needed
    if (fiber != NULL) {
        // Example: interact with the fiber using the array
        Janet result;
        JanetSignal status = janet_continue(fiber, janet_wrap_array(array), &result);
        
        // Check the status of the fiber execution
        if (status == JANET_SIGNAL_OK) {
            // Optionally, perform further operations with the result
        }
    }

    // Clean up the Janet environment
    janet_deinit();

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_497(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
