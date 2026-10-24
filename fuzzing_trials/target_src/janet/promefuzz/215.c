// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_optnat at janet.c:4850:9 in janet.h
// janet_optpointer at janet.c:4536:1 in janet.h
// janet_opttuple at janet.c:4527:1 in janet.h
// janet_getstartrange at janet.c:4704:9 in janet.h
// janet_getendrange at janet.c:4711:9 in janet.h
// janet_getargindex at janet.c:4718:9 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static int32_t random_int32(const uint8_t **data, size_t *size) {
    if (*size < sizeof(int32_t)) return 0;
    int32_t result;
    memcpy(&result, *data, sizeof(int32_t));
    *data += sizeof(int32_t);
    *size -= sizeof(int32_t);
    return result;
}

static void *random_pointer(const uint8_t **data, size_t *size) {
    if (*size < sizeof(void *)) return NULL;
    void *result;
    memcpy(&result, *data, sizeof(void *));
    *data += sizeof(void *);
    *size -= sizeof(void *);
    return result;
}

static Janet random_janet(const uint8_t **data, size_t *size) {
    Janet janet;
    if (*size < sizeof(Janet)) {
        janet.u64 = 0;
    } else {
        memcpy(&janet, *data, sizeof(Janet));
        *data += sizeof(Janet);
        *size -= sizeof(Janet);
    }
    return janet;
}

int LLVMFuzzerTestOneInput_215(const uint8_t *Data, size_t Size) {
    const uint8_t *data = Data;
    size_t size = Size;

    int32_t argc = random_int32(&data, &size);
    if (argc < 0) argc = 0; // Ensure argc is non-negative
    Janet *argv = malloc(argc * sizeof(Janet));
    for (int32_t i = 0; i < argc; i++) {
        argv[i] = random_janet(&data, &size);
    }

    int32_t index = random_int32(&data, &size);
    int32_t dflt_nat = random_int32(&data, &size);
    void *dflt_ptr = random_pointer(&data, &size);
    JanetTuple dflt_tuple = (JanetTuple)random_pointer(&data, &size);
    int32_t length = random_int32(&data, &size);

    if (index >= 0 && index < argc) {
        janet_optnat(argv, argc, index, dflt_nat);
        janet_optpointer(argv, argc, index, dflt_ptr);
        janet_opttuple(argv, argc, index, dflt_tuple);
        janet_getstartrange(argv, argc, index, length);
        janet_getendrange(argv, argc, index, length);
    }
    if (index >= -length && index < length) {
        janet_getargindex(argv, index, length, "test");
    }

    free(argv);
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

        LLVMFuzzerTestOneInput_215(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    