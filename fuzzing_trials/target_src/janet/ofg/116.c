#include <stdint.h>
#include <stddef.h>
#include <janet.h> // Assuming this header file contains the definition for JanetAtomicInt

// Function-under-test
// Correct the type of the function parameter to match the declaration in janet.h
JANET_API JanetAtomicInt janet_atomic_dec(JanetAtomicInt volatile *x);

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize the atomic integer
    if (size < sizeof(JanetAtomicInt)) {
        return 0;
    }

    // Initialize the atomic integer with some data
    JanetAtomicInt atomicInt = *((JanetAtomicInt *)data);

    // Call the function-under-test
    JanetAtomicInt result = janet_atomic_dec(&atomicInt);

    // Use the result in some way to prevent optimization out
    if (result != atomicInt) {
        // Perform some operation or logging
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_116(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
