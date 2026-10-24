#include <stdint.h>
#include <stddef.h>

// Assuming JanetAtomicInt is defined as an integer type
typedef int JanetAtomicInt;

// Assuming DW_TAG_volatile_typeJanetAtomicInt is defined as a volatile type
typedef volatile JanetAtomicInt DW_TAG_volatile_typeJanetAtomicInt;

// Function-under-test declaration
JanetAtomicInt janet_atomic_inc(DW_TAG_volatile_typeJanetAtomicInt *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to be used as an integer
    if (size < sizeof(JanetAtomicInt)) {
        return 0;
    }

    // Initialize a JanetAtomicInt variable from the input data
    JanetAtomicInt atomicInt = *((const JanetAtomicInt *)data);

    // Declare a volatile pointer to the JanetAtomicInt variable
    DW_TAG_volatile_typeJanetAtomicInt *volatilePtr = &atomicInt;

    // Call the function-under-test
    JanetAtomicInt result = janet_atomic_inc(volatilePtr);

    // Use the result to prevent optimization
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

    LLVMFuzzerTestOneInput_125(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
