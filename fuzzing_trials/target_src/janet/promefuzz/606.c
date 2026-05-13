// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static JanetString generate_janet_string(const uint8_t *Data, size_t Size) {
    return (JanetString)Data;
}

static JanetStruct generate_janet_struct(const uint8_t *Data, size_t Size) {
    return (JanetStruct)Data;
}

static JanetSymbol generate_janet_symbol(const uint8_t *Data, size_t Size) {
    return (JanetSymbol)Data;
}

static JanetKeyword generate_janet_keyword(const uint8_t *Data, size_t Size) {
    return (JanetKeyword)Data;
}

int LLVMFuzzerTestOneInput_606(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    JanetString jstring = generate_janet_string(Data, Size);
    JanetStruct jstruct = generate_janet_struct(Data, Size);
    JanetSymbol jsymbol = generate_janet_symbol(Data, Size);
    JanetKeyword jkeyword = generate_janet_keyword(Data, Size);

    // Fuzz janet_wrap_string
    Janet wrapped_string = janet_wrap_string(jstring);

    // Fuzz janet_wrap_struct
    Janet wrapped_struct = janet_wrap_struct(jstruct);

    // Fuzz janet_wrap_symbol
    Janet wrapped_symbol = janet_wrap_symbol(jsymbol);

    // Fuzz janet_wrap_keyword
    Janet wrapped_keyword = janet_wrap_keyword(jkeyword);

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

        LLVMFuzzerTestOneInput_606(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    