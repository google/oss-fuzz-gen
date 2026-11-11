// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_gettuple at janet.c:4513:1 in janet.h
// janet_getarray at janet.c:4512:1 in janet.h
// janet_get at value.c:514:7 in janet.h
// janet_indexed_view at janet.c:34464:5 in janet.h
// janet_getpointer at janet.c:4524:1 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_722(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 2) return 0;

    prepare_dummy_file(Data, Size);

    // Initialize Janet VM
    janet_init();

    // Ensure Data is aligned and large enough
    if (Size % sizeof(Janet) != 0) return 0;

    Janet *argv = (Janet *)malloc(Size);
    if (!argv) return 0;
    memcpy(argv, Data, Size);

    int32_t index = (int32_t)(Data[Size - 1] % (Size / sizeof(Janet)));

    // Fuzz janet_gettuple
    if (index >= 0 && index < (Size / sizeof(Janet))) {
        JanetTuple tuple = janet_gettuple(argv, index);
        (void)tuple; // Use the result to avoid unused variable warning
    }

    // Fuzz janet_getarray
    if (index >= 0 && index < (Size / sizeof(Janet))) {
        JanetArray *array = janet_getarray(argv, index);
        (void)array; // Use the result to avoid unused variable warning
    }

    // Fuzz janet_get
    if (Size >= sizeof(Janet) * 2) {
        Janet ds = argv[0];
        Janet key = argv[1];
        Janet value = janet_get(ds, key);
        (void)value; // Use the result to avoid unused variable warning
    }

    // Fuzz janet_indexed_view
    const Janet *data;
    int32_t len;
    Janet seq = argv[0];
    int success = janet_indexed_view(seq, &data, &len);
    (void)success; // Use the result to avoid unused variable warning

    // Fuzz janet_getpointer
    if (index >= 0 && index < (Size / sizeof(Janet))) {
        void *pointer = janet_getpointer(argv, index);
        (void)pointer; // Use the result to avoid unused variable warning
    }

    // Free allocated memory
    free(argv);

    // Deinitialize Janet VM
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

        LLVMFuzzerTestOneInput_722(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    