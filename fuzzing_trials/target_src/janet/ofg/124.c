#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Define a volatile type for JanetAtomicInt
typedef volatile JanetAtomicInt DW_TAG_volatile_typeJanetAtomicInt;

// Fuzzing harness for janet_atomic_inc function
int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize JanetAtomicInt
    if (size < sizeof(JanetAtomicInt)) {
        return 0;
    }

    // Initialize a JanetAtomicInt from the input data
    JanetAtomicInt atomicInt = 0;
    for (size_t i = 0; i < sizeof(JanetAtomicInt) && i < size; i++) {
        atomicInt |= ((JanetAtomicInt)data[i]) << (i * 8);
    }

    // Create a volatile pointer to JanetAtomicInt
    DW_TAG_volatile_typeJanetAtomicInt *volatileAtomicInt = &atomicInt;

    // Call the function-under-test
    JanetAtomicInt result = janet_atomic_inc(volatileAtomicInt);

    // Use the result in some way to avoid compiler optimizations
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

    LLVMFuzzerTestOneInput_124(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
