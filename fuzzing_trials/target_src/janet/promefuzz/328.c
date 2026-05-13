// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_cstring at string.c:88:16 in janet.h
// janet_getcbytes at janet.c:4560:13 in janet.h
// janet_optcbytes at janet.c:4589:13 in janet.h
// janet_optcstring at janet.c:4542:13 in janet.h
// janet_getcstring at janet.c:4553:13 in janet.h
// janet_streq at janet.c:4622:5 in janet.h
// janet_cstrcmp at janet.c:34043:5 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static Janet create_janet_string(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for safe string operations
    char *str = malloc(size + 1);
    if (!str) return janet_wrap_nil();
    memcpy(str, data, size);
    str[size] = '\0';
    Janet result = janet_cstringv(str);
    free(str);
    return result;
}

static void fuzz_janet_getcbytes(const Janet *argv, int32_t argc) {
    if (argc > 0) {
        int32_t n = rand() % argc;
        const char *result = janet_getcbytes(argv, n);
        if (result) {
            printf("janet_getcbytes: %s\n", result);
        }
    }
}

static void fuzz_janet_optcbytes(const Janet *argv, int32_t argc) {
    int32_t n = rand() % (argc + 2); // Allow out of bounds
    const char *dflt = "default";
    const char *result = janet_optcbytes(argv, argc, n, dflt);
    printf("janet_optcbytes: %s\n", result);
}

static void fuzz_janet_optcstring(const Janet *argv, int32_t argc) {
    int32_t n = rand() % (argc + 2); // Allow out of bounds
    const char *dflt = "default";
    const char *result = janet_optcstring(argv, argc, n, dflt);
    printf("janet_optcstring: %s\n", result);
}

static void fuzz_janet_getcstring(const Janet *argv, int32_t argc) {
    if (argc > 0) {
        int32_t n = rand() % argc;
        const char *result = janet_getcstring(argv, n);
        if (result) {
            printf("janet_getcstring: %s\n", result);
        }
    }
}

static void fuzz_janet_streq(Janet *argv, int32_t argc) {
    if (argc > 0) {
        const char *cstring = "test";
        int result = janet_streq(argv[0], cstring);
        printf("janet_streq: %d\n", result);
    }
}

static void fuzz_janet_cstrcmp(Janet *argv, int32_t argc) {
    if (argc > 0) {
        const char *cstring = "test";
        if (janet_checktype(argv[0], JANET_STRING)) {
            int result = janet_cstrcmp(janet_unwrap_string(argv[0]), cstring);
            printf("janet_cstrcmp: %d\n", result);
        }
    }
}

int LLVMFuzzerTestOneInput_328(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet VM
    janet_init();

    Janet argv[5];
    int32_t argc = Size > 5 ? 5 : Size;

    for (int32_t i = 0; i < argc; i++) {
        argv[i] = create_janet_string(Data, Size);
    }

    fuzz_janet_getcbytes(argv, argc);
    fuzz_janet_optcbytes(argv, argc);
    fuzz_janet_optcstring(argv, argc);
    fuzz_janet_getcstring(argv, argc);
    fuzz_janet_streq(argv, argc);
    fuzz_janet_cstrcmp(argv, argc);

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

        LLVMFuzzerTestOneInput_328(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    