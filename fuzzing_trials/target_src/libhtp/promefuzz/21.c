// This fuzz driver is generated for library libhtp, aiming to fuzz the following functions:
// bstr_chop at bstr.c:188:6 in bstr.h
// bstr_adjust_realptr at bstr.c:106:6 in bstr.h
// bstr_wrap_c at bstr.c:626:7 in bstr.h
// bstr_add_c_noex at bstr.c:62:7 in bstr.h
// bstr_add_noex at bstr.c:98:7 in bstr.h
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

static void fuzz_bstr_chop(bstr *b) {
    if (b && b->len > 0) {
        bstr_chop(b);
    }
}

static void fuzz_bstr_adjust_realptr(bstr *b, void *newrealptr) {
    if (b) {
        bstr_adjust_realptr(b, newrealptr);
    }
}

static bstr* fuzz_bstr_wrap_c(const char *cstr) {
    return bstr_wrap_c(cstr);
}

static bstr* fuzz_bstr_add_c_noex(bstr *b, const char *cstr) {
    if (b && cstr) {
        return bstr_add_c_noex(b, cstr);
    }
    return NULL;
}

static bstr* fuzz_bstr_add_noex(bstr *bdestination, const bstr *bsource) {
    if (bdestination && bsource) {
        return bstr_add_noex(bdestination, bsource);
    }
    return NULL;
}

static bstr* fuzz_bstr_add_c(bstr *b, const char *cstr) {
    if (b && cstr) {
        return bstr_add_c(b, cstr);
    }
    return NULL;
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a dummy bstr
    bstr *b = (bstr *)malloc(sizeof(bstr));
    if (!b) return 0;
    b->len = Size > 10 ? 10 : Size; // Ensure len does not exceed initial allocation
    b->size = Size + 10; // Assume some extra space
    b->realptr = (unsigned char *)malloc(b->size);
    if (!b->realptr) {
        free(b);
        return 0;
    }
    memcpy(b->realptr, Data, b->len);

    // Fuzz each function
    fuzz_bstr_chop(b);

    // Allocate new_realptr and use it with adjust_realptr
    void *new_realptr = malloc(Size + 10); // Ensure enough space
    if (new_realptr) {
        fuzz_bstr_adjust_realptr(b, new_realptr);
        // Ensure not to use new_realptr after free
        // Do not free new_realptr here as it is used by bstr
    }

    char *cstr = (char *)malloc(Size + 1);
    if (cstr) {
        memcpy(cstr, Data, Size);
        cstr[Size] = '\0';
        bstr *wrapped_bstr = fuzz_bstr_wrap_c(cstr);
        if (wrapped_bstr) {
            // Free wrapped_bstr if allocated
            free(wrapped_bstr);
        }
        fuzz_bstr_add_c_noex(b, cstr);
        fuzz_bstr_add_c(b, cstr);
        free(cstr);
    }

    bstr *source_bstr = (bstr *)malloc(sizeof(bstr));
    if (source_bstr) {
        source_bstr->len = Size > 10 ? 10 : Size; // Ensure len does not exceed initial allocation
        source_bstr->size = Size + 10;
        source_bstr->realptr = (unsigned char *)malloc(source_bstr->size);
        if (source_bstr->realptr) {
            memcpy(source_bstr->realptr, Data, source_bstr->len);
            fuzz_bstr_add_noex(b, source_bstr);
            free(source_bstr->realptr);
        }
        free(source_bstr);
    }

    // Cleanup
    free(b->realptr);
    free(b);

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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    