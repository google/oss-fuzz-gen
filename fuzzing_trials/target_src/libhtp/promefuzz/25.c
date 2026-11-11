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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bstr.h"

static void initialize_bstr(bstr *b, size_t size) {
    b->len = 0;
    b->size = size;
    b->realptr = (unsigned char *)malloc(size);
    if (b->realptr) {
        memset(b->realptr, 0, size);
    }
}

static void cleanup_bstr(bstr *b) {
    if (b->realptr) {
        free(b->realptr);
        b->realptr = NULL;
    }
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Initialize bstring
    bstr b;
    initialize_bstr(&b, Size);

    // Test bstr_chop
    if (b.len > 0) {
        bstr_chop(&b);
    }

    // Test bstr_adjust_realptr
    if (b.realptr && Size > sizeof(void *)) {
        bstr_adjust_realptr(&b, (void *)(Data + Size - sizeof(void *)));
    }

    // Test bstr_wrap_c
    char *cstr = (char *)malloc(Size + 1);
    if (cstr) {
        memcpy(cstr, Data, Size);
        cstr[Size] = '\0';
        bstr *wrapped_bstr = bstr_wrap_c(cstr);
        if (wrapped_bstr) {
            // No need to call cleanup_bstr on wrapped_bstr, as it does not own the memory
            free(wrapped_bstr);
        }
        // Free only the cstr as it is not managed by wrapped_bstr
        free(cstr);
    }

    // Test bstr_add_c_noex
    if (b.realptr && Size > 0) {
        const char *append_cstr = (const char *)Data;
        bstr_add_c_noex(&b, append_cstr);
    }

    // Test bstr_add_noex
    bstr source_b;
    initialize_bstr(&source_b, Size);
    if (source_b.realptr) {
        bstr_add_noex(&b, &source_b);
        cleanup_bstr(&source_b);
    }

    // Test bstr_add_c
    if (b.realptr && Size > 0) {
        const char *append_cstr = (const char *)Data;
        bstr *new_b = bstr_add_c(&b, append_cstr);
        if (new_b != &b) {
            cleanup_bstr(&b);
            b = *new_b;
        }
    }

    // Cleanup
    cleanup_bstr(&b);

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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    