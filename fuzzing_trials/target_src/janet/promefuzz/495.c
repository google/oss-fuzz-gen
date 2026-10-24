// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_abstract_begin at janet.c:1330:7 in janet.h
// janet_abstract_end at janet.c:1338:7 in janet.h
// janet_tuple_begin at tuple.c:34:8 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_wrap_u64 at inttypes.c:186:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet_runtime() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_abstract_end(const uint8_t *data, size_t size) {
    if (size < sizeof(void *)) return;

    // Allocate memory using Janet's memory management functions
    JanetAbstract abstractTemplate = janet_abstract_begin(NULL, size);
    if (!abstractTemplate) return;

    // Copy data into the allocated abstract template
    memcpy(abstractTemplate, data, size);

    // Call the target function
    janet_abstract_end(abstractTemplate);
}

static void fuzz_janet_tuple_begin(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t)) return;
    int32_t length = *((int32_t *)data);
    if (length < 0 || length > 1000) return; // Arbitrary upper limit
    Janet *tuple = janet_tuple_begin(length);
    janet_gcpressure(sizeof(Janet) * length);
}

static void fuzz_janet_wrap_u64(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) return;
    uint64_t value = *((uint64_t *)data);
    Janet wrapped = janet_wrap_u64(value);
    (void)wrapped; // Suppress unused variable warning
}

static void fuzz_janet_gcpressure(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) return;
    size_t pressure = *((size_t *)data);
    janet_gcpressure(pressure);
}

static void fuzz_janet_wrap_integer(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t)) return;
    int32_t value = *((int32_t *)data);
    Janet wrapped = janet_wrap_integer(value);
    (void)wrapped; // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_495(const uint8_t *Data, size_t Size) {
    initialize_janet_runtime();

    fuzz_janet_abstract_end(Data, Size);
    fuzz_janet_tuple_begin(Data, Size);
    fuzz_janet_wrap_u64(Data, Size);
    fuzz_janet_gcpressure(Data, Size);
    fuzz_janet_wrap_integer(Data, Size);

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

        LLVMFuzzerTestOneInput_495(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    