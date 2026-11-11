// This fuzz driver is generated for library libhtp, aiming to fuzz the following functions:
// bstr_util_cmp_mem_nocasenorzero at bstr.c:399:5 in bstr.h
// bstr_begins_with_mem_nocase at bstr.c:151:5 in bstr.h
// bstr_util_cmp_mem at bstr.c:349:5 in bstr.h
// bstr_index_of_mem_nocase at bstr.c:310:5 in bstr.h
// bstr_cmp_mem_nocase at bstr.c:230:5 in bstr.h
// bstr_util_cmp_mem_nocase at bstr.c:374:5 in bstr.h
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

static void fuzz_bstr_begins_with_mem_nocase(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(bstr) + 1) return;

    bstr bhaystack;
    bhaystack.len = (size_t)Data[0];
    bhaystack.size = (size_t)Data[1];

    if (Size < 2 + bhaystack.len) return;

    bhaystack.realptr = (unsigned char *)&Data[2];

    const void *mem_data = &Data[2 + bhaystack.len];
    size_t mem_len = Size - (2 + bhaystack.len);

    bstr_begins_with_mem_nocase(&bhaystack, mem_data, mem_len);
}

static void fuzz_bstr_util_cmp_mem(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    size_t len1 = (size_t)Data[0];
    size_t len2 = (size_t)Data[1];
    
    if (Size < 2 + len1 + len2) return;

    const void *data1 = &Data[2];
    const void *data2 = &Data[2 + len1];

    bstr_util_cmp_mem(data1, len1, data2, len2);
}

static void fuzz_bstr_index_of_mem_nocase(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(bstr) + 1) return;

    bstr bhaystack;
    bhaystack.len = (size_t)Data[0];
    bhaystack.size = (size_t)Data[1];

    if (Size < 2 + bhaystack.len) return;

    bhaystack.realptr = (unsigned char *)&Data[2];

    const void *mem_data = &Data[2 + bhaystack.len];
    size_t mem_len = Size - (2 + bhaystack.len);

    bstr_index_of_mem_nocase(&bhaystack, mem_data, mem_len);
}

static void fuzz_bstr_cmp_mem_nocase(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(bstr) + 1) return;

    bstr b;
    b.len = (size_t)Data[0];
    b.size = (size_t)Data[1];

    if (Size < 2 + b.len) return;

    b.realptr = (unsigned char *)&Data[2];

    const void *mem_data = &Data[2 + b.len];
    size_t mem_len = Size - (2 + b.len);

    bstr_cmp_mem_nocase(&b, mem_data, mem_len);
}

static void fuzz_bstr_util_cmp_mem_nocase(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    size_t len1 = (size_t)Data[0];
    size_t len2 = (size_t)Data[1];
    
    if (Size < 2 + len1 + len2) return;

    const void *data1 = &Data[2];
    const void *data2 = &Data[2 + len1];

    bstr_util_cmp_mem_nocase(data1, len1, data2, len2);
}

static void fuzz_bstr_util_cmp_mem_nocasenorzero(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    size_t len1 = (size_t)Data[0];
    size_t len2 = (size_t)Data[1];
    
    if (Size < 2 + len1 + len2) return;

    const void *data1 = &Data[2];
    const void *data2 = &Data[2 + len1];

    bstr_util_cmp_mem_nocasenorzero(data1, len1, data2, len2);
}

int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    fuzz_bstr_begins_with_mem_nocase(Data, Size);
    fuzz_bstr_util_cmp_mem(Data, Size);
    fuzz_bstr_index_of_mem_nocase(Data, Size);
    fuzz_bstr_cmp_mem_nocase(Data, Size);
    fuzz_bstr_util_cmp_mem_nocase(Data, Size);
    fuzz_bstr_util_cmp_mem_nocasenorzero(Data, Size);
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

        LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    