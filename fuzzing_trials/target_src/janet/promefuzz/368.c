// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_mark at gc.c:57:6 in janet.h
// janet_mark at gc.c:57:6 in janet.h
// janet_mark at gc.c:57:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <janet.h>

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_368(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *) + sizeof(uint64_t)) {
        return 0;
    }

    void *ptr = (void *)(Data);
    uint64_t tagmask = *((uint64_t *)(Data + sizeof(void *)));

    // Test janet_wrap_pointer
    Janet wrapped_ptr = janet_wrap_pointer(ptr);

    // Test janet_nanbox_from_pointer
    Janet nanboxed_ptr = janet_nanbox_from_pointer(ptr, tagmask);

    // Test janet_nanbox_to_pointer
    void *unwrapped_ptr = janet_nanbox_to_pointer(nanboxed_ptr);

    // Test janet_nanbox_from_cpointer
    Janet cptr_nanbox = janet_nanbox_from_cpointer(ptr, tagmask);

    // Test janet_unwrap_pointer
    void *unwrapped_cptr = janet_unwrap_pointer(cptr_nanbox);

    // Test janet_mark
    janet_mark(wrapped_ptr);
    janet_mark(nanboxed_ptr);
    janet_mark(cptr_nanbox);

    // Write data to dummy file if necessary
    prepare_dummy_file(Data, Size);

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

        LLVMFuzzerTestOneInput_368(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    