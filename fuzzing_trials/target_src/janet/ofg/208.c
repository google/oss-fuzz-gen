#include <stdint.h>
#include <stddef.h>

// Assuming JanetAtomicInt is a typedef for an integer type
typedef int JanetAtomicInt;

// Assuming DW_TAG_volatile_typeJanetAtomicInt is a struct containing a volatile JanetAtomicInt
typedef struct {
    volatile JanetAtomicInt value;
} DW_TAG_volatile_typeJanetAtomicInt;

// Function-under-test
JanetAtomicInt janet_atomic_load(DW_TAG_volatile_typeJanetAtomicInt *atomicInt);

int LLVMFuzzerTestOneInput_208(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize a JanetAtomicInt
    if (size < sizeof(JanetAtomicInt)) {
        return 0;
    }

    // Initialize a DW_TAG_volatile_typeJanetAtomicInt with data
    DW_TAG_volatile_typeJanetAtomicInt atomicInt;
    atomicInt.value = *(const JanetAtomicInt *)data;

    // Call the function-under-test
    JanetAtomicInt result = janet_atomic_load(&atomicInt);

    // Use the result in some way to prevent optimizations from removing the call
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

    LLVMFuzzerTestOneInput_208(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
