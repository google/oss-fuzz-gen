#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_array_pop(JanetArray *array) {
    janet_array_pop(array);
}

static void fuzz_janet_array_n(const Janet *elements, int32_t n) {
    if (n >= 0 && elements != NULL) {
        janet_array_n(elements, n);
    }
}

static void fuzz_janet_array_push(JanetArray *array, Janet x) {
    janet_array_push(array, x);
}

static void fuzz_janet_array_peek(JanetArray *array) {
    janet_array_peek(array);
}

static void fuzz_janet_array(int32_t capacity) {
    if (capacity >= 0) {
        JanetArray *array = janet_array(capacity);
        if (array) {
            janet_array_pop(array);
            janet_array_peek(array);
            janet_array_push(array, (Janet){.i64 = 42});
        }
    }
}

static void fuzz_janet_unwrap_array(Janet x) {
    janet_unwrap_array(x);
}

int LLVMFuzzerTestOneInput_986(const uint8_t *Data, size_t Size) {
    // Initialize the Janet VM
    janet_init();

    if (Size < sizeof(Janet) + sizeof(int32_t)) {
        janet_deinit();
        return 0;
    }

    const Janet *elements = (const Janet *)Data;
    int32_t n = *(int32_t *)(Data + sizeof(Janet));
    int32_t capacity = n;

    // Ensure n does not exceed the number of available elements in Data
    if (capacity >= 0 && Size >= sizeof(Janet) * (size_t)n + sizeof(int32_t)) {
        JanetArray *array = janet_array(capacity);
        if (array) {
            fuzz_janet_array_n(elements, n);
            fuzz_janet_array_pop(array);
            fuzz_janet_array_peek(array);

            if (Size >= sizeof(Janet) + sizeof(int32_t) + sizeof(Janet)) {
                Janet x = *(Janet *)(Data + sizeof(Janet) + sizeof(int32_t));
                fuzz_janet_array_push(array, x);
            }
        }
    }

    if (Size >= sizeof(Janet)) {
        Janet x = *(Janet *)Data;
        fuzz_janet_unwrap_array(x);
    }

    // Clean up the Janet VM
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

    LLVMFuzzerTestOneInput_986(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
