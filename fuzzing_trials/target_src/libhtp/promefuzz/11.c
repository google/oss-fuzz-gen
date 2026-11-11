// This fuzz driver is generated for library libhtp, aiming to fuzz the following functions:
// bstr_dup_c at bstr.c:242:7 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
// bstr_adjust_realptr at bstr.c:106:6 in bstr.h
// bstr_util_strdup_to_c at bstr.c:621:7 in bstr.h
// bstr_dup_mem at bstr.c:258:7 in bstr.h
// bstr_free at bstr.c:285:6 in bstr.h
// bstr_adjust_size at bstr.c:110:6 in bstr.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "bstr.h"

static void fuzz_bstr_dup_c(const uint8_t *Data, size_t Size) {
    char *cstr = (char *)malloc(Size + 1);
    if (cstr == NULL) {
        return;
    }
    memcpy(cstr, Data, Size);
    cstr[Size] = '\0';
    bstr *b = bstr_dup_c(cstr);
    free(cstr);
    bstr_free(b);
}

static void fuzz_bstr_adjust_realptr(bstr *b, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *)) return;
    void *new_realptr = (void *)Data;
    bstr_adjust_realptr(b, new_realptr);
}

static void fuzz_bstr_util_strdup_to_c(bstr *b) {
    char *cstr = bstr_util_strdup_to_c(b);
    free(cstr);
}

static void fuzz_bstr_dup_mem(const uint8_t *Data, size_t Size) {
    bstr *b = bstr_dup_mem(Data, Size);
    bstr_free(b);
}

static void fuzz_bstr_adjust_size(bstr *b, size_t Size) {
    bstr_adjust_size(b, Size);
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    fuzz_bstr_dup_c(Data, Size);

    bstr b;
    b.realptr = NULL;
    b.len = 0;
    b.size = 0;

    fuzz_bstr_adjust_realptr(&b, Data, Size);
    fuzz_bstr_util_strdup_to_c(&b);
    fuzz_bstr_dup_mem(Data, Size);
    fuzz_bstr_adjust_size(&b, Size);

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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    