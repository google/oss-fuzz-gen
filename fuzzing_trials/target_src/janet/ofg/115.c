#include <stdint.h>
#include <stddef.h>

// Assuming the definition of JanetAtomicInt and DW_TAG_volatile_typeJanetAtomicInt
typedef int32_t JanetAtomicInt;
typedef volatile JanetAtomicInt DW_TAG_volatile_typeJanetAtomicInt;

// Function-under-test
JanetAtomicInt janet_atomic_dec_115(DW_TAG_volatile_typeJanetAtomicInt *atomicInt) {
    // Decrement the atomic integer
    return --(*atomicInt);
}

int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize the atomic integer
    if (size < sizeof(DW_TAG_volatile_typeJanetAtomicInt)) {
        return 0;
    }

    // Initialize the atomic integer with data from the input
    DW_TAG_volatile_typeJanetAtomicInt atomicInt;
    memcpy(&atomicInt, data, sizeof(DW_TAG_volatile_typeJanetAtomicInt));

    // Call the function-under-test
    JanetAtomicInt result = janet_atomic_dec_115(&atomicInt);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_115(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
