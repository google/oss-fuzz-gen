// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_cstring at string.c:88:16 in janet.h
// janet_keyeq at janet.c:4618:5 in janet.h
// janet_symeq at janet.c:4626:5 in janet.h
// janet_getcstring at janet.c:4553:13 in janet.h
// janet_streq at janet.c:4622:5 in janet.h
// janet_cstrcmp at janet.c:34043:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_164(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Ensure the input data is null-terminated for C string operations
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) return 0;
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    // Initialize the Janet VM before using any Janet functions
    janet_init();

    // Fuzz janet_cstring
    JanetString jstr = janet_cstring(null_terminated_data);

    // Fuzz janet_keyeq
    Janet janet_value;
    janet_value.u64 = 0; // Initialize Janet union
    int keyeq_result = janet_keyeq(janet_value, null_terminated_data);

    // Fuzz janet_symeq
    int symeq_result = janet_symeq(janet_value, null_terminated_data);

    // Fuzz janet_getcstring
    Janet janet_array[1];
    janet_array[0].pointer = (void *)jstr;
    const char *cstring_result = NULL;
    if (Size > 1) {
        int32_t index = Data[0] % 1; // Ensure index is within bounds
        cstring_result = janet_getcstring(janet_array, index);
    }

    // Fuzz janet_streq
    int streq_result = janet_streq(janet_value, null_terminated_data);

    // Fuzz janet_cstrcmp
    int cstrcmp_result = janet_cstrcmp(jstr, null_terminated_data);

    // Write to dummy file if needed
    write_dummy_file(Data, Size);

    // Clean up
    free(null_terminated_data);

    // Deinitialize the Janet VM
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

        LLVMFuzzerTestOneInput_164(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    