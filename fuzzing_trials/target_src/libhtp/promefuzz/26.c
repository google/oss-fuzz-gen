// This fuzz driver is generated for library libhtp, aiming to fuzz the following functions:
// bstr_wrap_mem at bstr.c:630:7 in bstr.h
// bstr_adjust_len at bstr.c:102:6 in bstr.h
// bstr_alloc at bstr.c:43:7 in bstr.h
// bstr_chop at bstr.c:188:6 in bstr.h
// bstr_expand at bstr.c:266:7 in bstr.h
// bstr_chop at bstr.c:188:6 in bstr.h
// bstr_expand at bstr.c:266:7 in bstr.h
// bstr_dup_ex at bstr.c:246:7 in bstr.h
// bstr_chop at bstr.c:188:6 in bstr.h
// bstr_expand at bstr.c:266:7 in bstr.h
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

static bstr* create_bstr_with_data(const uint8_t *Data, size_t Size) {
    if (Size == 0) return NULL;
    bstr *b = bstr_wrap_mem(Data, Size);
    if (b) {
        bstr_adjust_len(b, Size);
    }
    return b;
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz bstr_alloc
    size_t alloc_size = Data[0];
    bstr *b_alloc = bstr_alloc(alloc_size);
    if (b_alloc) {
        bstr_chop(b_alloc);
        b_alloc = bstr_expand(b_alloc, alloc_size + 1);
        if (b_alloc) {
            free(b_alloc->realptr);
        }
    }
    
    // Fuzz bstr_wrap_mem
    bstr *b_wrap = create_bstr_with_data(Data, Size);
    if (b_wrap) {
        bstr_chop(b_wrap);
        b_wrap = bstr_expand(b_wrap, Size + 1);
        if (b_wrap) {
            free(b_wrap->realptr);
        }
    }
    
    // Fuzz bstr_dup_ex safely
    if (b_wrap && b_wrap->len > 0) {
        size_t copy_len = (Size - 1 < b_wrap->len) ? (Size - 1) : b_wrap->len;
        bstr *b_dup = bstr_dup_ex(b_wrap, 0, copy_len);
        if (b_dup) {
            bstr_chop(b_dup);
            b_dup = bstr_expand(b_dup, Size);
            if (b_dup) {
                free(b_dup->realptr);
            }
        }
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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    