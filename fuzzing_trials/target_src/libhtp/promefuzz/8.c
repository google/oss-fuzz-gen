// This fuzz driver is generated for library libhtp, aiming to fuzz the following functions:
// bstr_chr at bstr.c:194:5 in bstr.h
// bstr_char_at_end at bstr.c:180:5 in bstr.h
// bstr_char_at at bstr.c:172:5 in bstr.h
// bstr_dup_ex at bstr.c:246:7 in bstr.h
// bstr_to_lowercase at bstr.c:334:7 in bstr.h
// bstr_add_c at bstr.c:58:7 in bstr.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "bstr.h"

static bstr *create_bstr(const uint8_t *Data, size_t Size) {
    if (Size == 0) return NULL;

    bstr *b = malloc(sizeof(bstr));
    if (!b) return NULL;

    b->len = Size;
    b->size = Size;
    b->realptr = malloc(Size);
    if (!b->realptr) {
        free(b);
        return NULL;
    }

    memcpy(b->realptr, Data, Size);
    return b;
}

static void free_bstr(bstr *b) {
    if (b) {
        free(b->realptr);
        free(b);
    }
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    bstr *b = create_bstr(Data, Size);
    if (!b) return 0;

    // Test bstr_chr
    int search_byte = Data[0];
    int index = bstr_chr(b, search_byte);

    // Test bstr_char_at_end
    size_t pos_from_end = Size / 2;
    int char_at_end = bstr_char_at_end(b, pos_from_end);

    // Test bstr_char_at
    size_t pos_from_start = Size / 2;
    int char_at_start = bstr_char_at(b, pos_from_start);

    // Test bstr_dup_ex
    if (Size > 1) {
        size_t offset = 1;
        size_t len = Size - 1;
        bstr *duplicate = bstr_dup_ex(b, offset, len);
        free_bstr(duplicate);
    }

    // Test bstr_to_lowercase
    bstr *lowercase = bstr_to_lowercase(b);

    // Test bstr_add_c
    const char *cstr = "additional string";
    bstr *appended = bstr_add_c(b, cstr);

    free_bstr(appended);
    free_bstr(b);

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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    