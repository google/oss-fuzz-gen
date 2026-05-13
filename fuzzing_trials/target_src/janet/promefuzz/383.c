// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_array at janet.c:1562:13 in janet.h
// janet_getarray at janet.c:4512:1 in janet.h
// janet_array_ensure at janet.c:1589:6 in janet.h
// janet_array_weak at janet.c:1569:13 in janet.h
// janet_optarray at janet.c:4540:1 in janet.h
// janet_array_setcount at janet.c:1606:6 in janet.h
// janet_array at janet.c:1562:13 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <janet.h>

static JanetArray *create_dummy_janet_array(int32_t capacity) {
    JanetArray *array = janet_array(capacity);
    for (int32_t i = 0; i < capacity; i++) {
        array->data[i].u64 = (uint64_t)i;
    }
    array->count = capacity;
    return array;
}

static void fuzz_janet_getarray(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t)) return;
    const Janet *argv = (const Janet *) Data;
    int32_t n = *(int32_t *)(Data + sizeof(Janet));
    JanetArray *array = create_dummy_janet_array(10);
    janet_getarray(argv, n % array->count);
    free(array);
}

static void fuzz_janet_array_ensure(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 2) return;
    int32_t capacity = *(int32_t *)Data;
    int32_t growth = *(int32_t *)(Data + sizeof(int32_t));
    JanetArray *array = create_dummy_janet_array(10);
    janet_array_ensure(array, capacity, growth);
    free(array);
}

static void fuzz_janet_array_weak(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity = *(int32_t *)Data;
    JanetArray *array = janet_array_weak(capacity);
    free(array);
}

static void fuzz_janet_optarray(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 2 + sizeof(int32_t) * 2) return;
    const Janet *argv = (const Janet *) Data;
    int32_t argc = *(int32_t *)(Data + sizeof(Janet) * 2);
    int32_t n = *(int32_t *)(Data + sizeof(Janet) * 2 + sizeof(int32_t));
    int32_t dflt_len = *(int32_t *)(Data + sizeof(Janet) * 2 + sizeof(int32_t) * 2);
    JanetArray *array = janet_optarray(argv, argc, n, dflt_len);
    free(array);
}

static void fuzz_janet_array_setcount(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t count = *(int32_t *)Data;
    JanetArray *array = create_dummy_janet_array(10);
    janet_array_setcount(array, count);
    free(array);
}

static void fuzz_janet_array(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity = *(int32_t *)Data;
    JanetArray *array = janet_array(capacity);
    free(array);
}

int LLVMFuzzerTestOneInput_383(const uint8_t *Data, size_t Size) {
    // Initialize Janet VM before using any Janet functions
    janet_init();

    fuzz_janet_getarray(Data, Size);
    fuzz_janet_array_ensure(Data, Size);
    fuzz_janet_array_weak(Data, Size);
    fuzz_janet_optarray(Data, Size);
    fuzz_janet_array_setcount(Data, Size);
    fuzz_janet_array(Data, Size);

    // Cleanup Janet VM after use
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_383(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    