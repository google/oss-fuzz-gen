#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Declare the function-under-test
JanetFiber * janet_loop1();

int LLVMFuzzerTestOneInput_263(const uint8_t *data, size_t size) {
    // Fuzz the janet_loop1 function
    JanetFiber *fiber = janet_loop1();

    // Perform any additional checks or operations on the returned fiber
    if (fiber != NULL) {
        // Example operation: check the status of the fiber
        JanetFiberStatus status = janet_fiber_status(fiber);
        // You can add more operations or checks here if needed
    }

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

    LLVMFuzzerTestOneInput_263(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
