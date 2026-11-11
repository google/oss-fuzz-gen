// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_cstring at string.c:88:16 in janet.h
// janet_cstring at string.c:88:16 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
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

static JanetString create_janet_string(const uint8_t *data, size_t size) {
    char *temp = (char *)malloc(size + 1);
    if (!temp) return NULL;
    memcpy(temp, data, size);
    temp[size] = '\0';
    JanetString jstr = janet_cstring(temp);
    free(temp);
    return jstr;
}

static Janet create_janet_keyword_or_symbol(const uint8_t *data, size_t size) {
    char *temp = (char *)malloc(size + 1);
    if (!temp) return (Janet){0};
    memcpy(temp, data, size);
    temp[size] = '\0';
    Janet x;
    x.pointer = janet_cstring(temp);
    free(temp);
    return x;
}

int LLVMFuzzerTestOneInput_503(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize the Janet VM
    janet_init();

    // Fuzz janet_cstring
    JanetString jstr = create_janet_string(Data, Size);
    if (!jstr) {
        janet_deinit();
        return 0;
    }

    // Fuzz janet_keyeq
    Janet x = create_janet_keyword_or_symbol(Data, Size);
    if (x.pointer) {
        janet_keyeq(x, (const char *)Data);

        // Fuzz janet_symeq
        janet_symeq(x, (const char *)Data);

        // Prepare a dummy Janet array for janet_getcstring
        Janet array[1];
        array[0] = x;
        if (janet_checktype(array[0], JANET_STRING)) {
            janet_getcstring(array, 0);
        }

        // Fuzz janet_streq
        janet_streq(x, (const char *)Data);
    }

    // Ensure that the C string is null-terminated for janet_cstrcmp
    char *cstr = (char *)malloc(Size + 1);
    if (cstr) {
        memcpy(cstr, Data, Size);
        cstr[Size] = '\0';
        janet_cstrcmp(jstr, cstr);
        free(cstr);
    }

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

        LLVMFuzzerTestOneInput_503(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    