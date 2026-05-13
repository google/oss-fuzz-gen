// This fuzz driver is generated for library libhtp, aiming to fuzz the following functions:
// bstr_dup_c at bstr.c:242:7 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
// bstr_dup_mem at bstr.c:258:7 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
// bstr_dup at bstr.c:238:7 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
// bstr_dup_lower at bstr.c:254:7 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
// bstr_add_mem at bstr.c:66:7 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bstr.h"

static bstr *create_bstr_from_data(const uint8_t *Data, size_t Size) {
    if (Size == 0) return NULL;

    bstr *b = (bstr *)malloc(sizeof(bstr));
    if (!b) return NULL;

    b->len = Size;
    b->size = Size + 1; // Ensure space for null terminator
    b->realptr = (unsigned char *)malloc(b->size);
    if (!b->realptr) {
        free(b);
        return NULL;
    }

    memcpy(b->realptr, Data, Size);
    b->realptr[Size] = '\0'; // Null-terminate
    return b;
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    // Test bstr_dup_c
    char *cstr = (char *)malloc(Size + 1);
    if (cstr) {
        memcpy(cstr, Data, Size);
        cstr[Size] = '\0';
        bstr *dup_c = bstr_dup_c(cstr);
        bstr_free(dup_c);
        free(cstr);
    }

    // Test bstr_dup_mem
    bstr *dup_mem = bstr_dup_mem(Data, Size);
    bstr_free(dup_mem);

    // Test bstr_dup
    bstr *original_bstr = create_bstr_from_data(Data, Size);
    if (original_bstr) {
        bstr *dup_bstr = bstr_dup(original_bstr);
        bstr_free(dup_bstr);

        // Test bstr_dup_lower
        bstr *dup_lower = bstr_dup_lower(original_bstr);
        bstr_free(dup_lower);

        // Test bstr_add_mem
        bstr *added_mem = bstr_add_mem(original_bstr, Data, Size);
        if (added_mem != original_bstr) {
            bstr_free(original_bstr);
            original_bstr = added_mem;
        }
        bstr_free(original_bstr);
    }

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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    