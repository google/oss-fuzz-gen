// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_marshal at marsh.c:688:6 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_optbuffer at janet.c:4538:1 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_description_b at janet.c:28645:6 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet_vm() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_unwrap_buffer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x;
    memcpy(&x, Data, sizeof(Janet));

    // Ensure x is a buffer before calling janet_unwrap_buffer
    if (janet_checktype(x, JANET_BUFFER)) {
        janet_unwrap_buffer(x);
    }
}

static void fuzz_janet_marshal(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10);

    Janet x;
    memcpy(&x, Data, sizeof(Janet));

    JanetKV kv;
    kv.key = janet_wrap_nil();
    kv.value = janet_wrap_nil();

    JanetTable rreg;
    rreg.data = &kv;
    rreg.count = 1;
    rreg.capacity = 1;
    rreg.deleted = 0;
    rreg.proto = NULL;

    // Ensure x is a valid type before calling janet_marshal
    if (janet_checktype(x, JANET_BUFFER) || janet_checktype(x, JANET_STRING) || janet_checktype(x, JANET_TABLE)) {
        janet_marshal(&buffer, x, &rreg, 0);
    }
    janet_buffer_deinit(&buffer);
}

static void fuzz_janet_optbuffer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 2) return;
    Janet argv[2];
    memcpy(argv, Data, sizeof(Janet) * 2);

    // Ensure the arguments are valid before calling janet_optbuffer
    if (janet_checktype(argv[0], JANET_BUFFER) || janet_checktype(argv[1], JANET_NIL)) {
        janet_optbuffer(argv, 2, 0, 10);
    }
}

static void fuzz_janet_wrap_buffer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetBuffer)) return;
    JanetBuffer buffer;
    memcpy(&buffer, Data, sizeof(JanetBuffer));

    // Ensure buffer is properly initialized before wrapping
    if (buffer.data && buffer.capacity >= 0) {
        janet_wrap_buffer(&buffer);
    }
}

static void fuzz_janet_description_b(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10);

    Janet x;
    memcpy(&x, Data, sizeof(Janet));

    // Ensure x is a valid type before calling janet_description_b
    if (janet_checktype(x, JANET_BUFFER) || janet_checktype(x, JANET_STRING) || janet_checktype(x, JANET_SYMBOL)) {
        janet_description_b(&buffer, x);
    }
    janet_buffer_deinit(&buffer);
}

static void fuzz_janet_buffer_init(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity;
    memcpy(&capacity, Data, sizeof(int32_t));

    if (capacity >= 0) {
        JanetBuffer buffer;
        janet_buffer_init(&buffer, capacity);
        janet_buffer_deinit(&buffer);
    }
}

int LLVMFuzzerTestOneInput_578(const uint8_t *Data, size_t Size) {
    initialize_janet_vm();
    fuzz_janet_unwrap_buffer(Data, Size);
    fuzz_janet_marshal(Data, Size);
    fuzz_janet_optbuffer(Data, Size);
    fuzz_janet_wrap_buffer(Data, Size);
    fuzz_janet_description_b(Data, Size);
    fuzz_janet_buffer_init(Data, Size);
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

        LLVMFuzzerTestOneInput_578(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    