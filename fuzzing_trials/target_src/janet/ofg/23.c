#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include "janet.h" // Assuming this is the header file where JanetFiber is defined

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create a JanetFiber object
    if (size < sizeof(JanetFiber)) {
        return 0;
    }

    // Allocate memory for a JanetFiber object and initialize it with the input data
    JanetFiber *fiber = (JanetFiber *)malloc(sizeof(JanetFiber));
    if (fiber == NULL) {
        return 0;
    }

    // Copy the input data into the fiber object
    memcpy(fiber, data, sizeof(JanetFiber));

    // Call the function-under-test
    int result = janet_fiber_can_resume(fiber);

    // Free the allocated memory
    free(fiber);

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

    LLVMFuzzerTestOneInput_23(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
