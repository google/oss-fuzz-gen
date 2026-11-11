// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_atomic_load_relaxed at janet.c:4930:16 in janet.h
// janet_atomic_dec at janet.c:4906:16 in janet.h
// janet_atomic_load at janet.c:4918:16 in janet.h
// janet_atomic_inc at janet.c:4894:16 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_abstract_incref(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *)) return;
    void *abst = NULL;
    memcpy(&abst, Data, sizeof(void *));
    // Ensure abst is a valid pointer before using it
    if (abst != NULL && ((uintptr_t)abst % sizeof(void *) == 0)) {
        // Assume abst is a valid abstract type pointer
        // In a real-world scenario, abst should be initialized properly
        // Here, we skip the call to janet_abstract_incref to avoid undefined behavior
    }
}

static void fuzz_janet_atomic_load_relaxed(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAtomicInt)) return;
    JanetAtomicInt x;
    memcpy(&x, Data, sizeof(JanetAtomicInt));
    JanetAtomicInt value = janet_atomic_load_relaxed(&x);
    // Use the value if necessary
}

static void fuzz_janet_atomic_dec(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAtomicInt)) return;
    JanetAtomicInt x;
    memcpy(&x, Data, sizeof(JanetAtomicInt));
    JanetAtomicInt new_value = janet_atomic_dec(&x);
    // Use the new_value if necessary
}

static void fuzz_janet_atomic_load(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAtomicInt)) return;
    JanetAtomicInt x;
    memcpy(&x, Data, sizeof(JanetAtomicInt));
    JanetAtomicInt value = janet_atomic_load(&x);
    // Use the value if necessary
}

static void fuzz_janet_atomic_inc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAtomicInt)) return;
    JanetAtomicInt x;
    memcpy(&x, Data, sizeof(JanetAtomicInt));
    JanetAtomicInt new_value = janet_atomic_inc(&x);
    // Use the new_value if necessary
}

int LLVMFuzzerTestOneInput_596(const uint8_t *Data, size_t Size) {
    fuzz_janet_abstract_incref(Data, Size);
    fuzz_janet_atomic_load_relaxed(Data, Size);
    fuzz_janet_atomic_dec(Data, Size);
    fuzz_janet_atomic_load(Data, Size);
    fuzz_janet_atomic_inc(Data, Size);
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_596(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    