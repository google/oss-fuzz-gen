// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_wrap_s64 at inttypes.c:180:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
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

static int64_t read_int64(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) {
        return 0;
    }
    int64_t value;
    memcpy(&value, Data, sizeof(int64_t));
    return value;
}

static void* read_pointer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void*)) {
        return NULL;
    }
    void *pointer;
    memcpy(&pointer, Data, sizeof(void*));
    return pointer;
}

int LLVMFuzzerTestOneInput_672(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Fuzz janet_wrap_s64
    int64_t int64_value = read_int64(Data, Size);
    Janet wrapped_int64 = janet_wrap_s64(int64_value);

    // Fuzz janet_wrap_pointer
    void *pointer_value = read_pointer(Data, Size);
    Janet wrapped_pointer = janet_wrap_pointer(pointer_value);

    // Fuzz janet_wrap_nil
    Janet wrapped_nil = janet_wrap_nil();

    // Use the wrapped values to prevent optimization removal
    (void)wrapped_int64;
    (void)wrapped_pointer;
    (void)wrapped_nil;

    // Cleanup the Janet environment
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

        LLVMFuzzerTestOneInput_672(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    