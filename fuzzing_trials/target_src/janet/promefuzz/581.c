// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_string at string.c:49:16 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_string_compare at string.c:60:5 in janet.h
// janet_string_equal at string.c:82:5 in janet.h
// janet_cstrcmp at janet.c:34043:5 in janet.h
// janet_string_equalconst at string.c:71:5 in janet.h
// janet_getstring at janet.c:4516:1 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetString create_janet_string(const uint8_t *data, int32_t len) {
    if (len < 0 || !data) return NULL;
    return janet_string(data, len);
}

int LLVMFuzzerTestOneInput_581(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet VM
    janet_init();

    int32_t len1 = Size / 2;
    int32_t len2 = Size - len1;

    JanetString str1 = create_janet_string(Data, len1);
    JanetString str2 = create_janet_string(Data + len1, len2);

    if (str1 && str2) {
        janet_string_compare(str1, str2);
        janet_string_equal(str1, str2);

        // Ensure the C string is null-terminated
        char *cstr = (char *)malloc(len2 + 1);
        if (cstr) {
            memcpy(cstr, Data + len1, len2);
            cstr[len2] = '\0'; // Null-terminate the C string
            janet_cstrcmp(str1, cstr);
            free(cstr);
        }

        int32_t rlen = len2;
        int32_t rhash = 0; // Simplified hash for demonstration
        janet_string_equalconst(str1, Data + len1, rlen, rhash);
    }

    if (Size >= sizeof(Janet) + sizeof(int32_t)) {
        const Janet *argv = (const Janet *)Data;
        int32_t index = *(int32_t *)(Data + sizeof(Janet));
        
        // Ensure index is within bounds
        int32_t argc = (Size - sizeof(int32_t)) / sizeof(Janet);
        if (index >= 0 && index < argc && janet_checktype(argv[index], JANET_STRING)) {
            janet_getstring(argv, index);
        }
    }

    // Cleanup Janet VM
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

        LLVMFuzzerTestOneInput_581(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    