// This fuzz driver is generated for library libhtp, aiming to fuzz the following functions:
// bstr_util_mem_index_of_mem at bstr.c:493:5 in bstr.h
// bstr_util_mem_index_of_mem_nocase at bstr.c:516:5 in bstr.h
// bstr_index_of_mem_nocase at bstr.c:310:5 in bstr.h
// bstr_index_of_mem at bstr.c:306:5 in bstr.h
// bstr_index_of at bstr.c:290:5 in bstr.h
// bstr_util_mem_index_of_mem_nocasenorzero at bstr.c:539:5 in bstr.h
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

static void fuzz_bstr_index_of_mem_nocase(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t haystack_len = *((size_t *)Data);
    size_t needle_len = *((size_t *)(Data + sizeof(size_t)));
    Data += 2 * sizeof(size_t);
    Size -= 2 * sizeof(size_t);

    if (haystack_len > Size || needle_len > Size - haystack_len) return;

    bstr bhaystack;
    bhaystack.len = haystack_len;
    bhaystack.size = haystack_len;
    bhaystack.realptr = (unsigned char *)Data;

    const void *needle = Data + haystack_len;

    bstr_index_of_mem_nocase(&bhaystack, needle, needle_len);
}

static void fuzz_bstr_index_of_mem(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t haystack_len = *((size_t *)Data);
    size_t needle_len = *((size_t *)(Data + sizeof(size_t)));
    Data += 2 * sizeof(size_t);
    Size -= 2 * sizeof(size_t);

    if (haystack_len > Size || needle_len > Size - haystack_len) return;

    bstr bhaystack;
    bhaystack.len = haystack_len;
    bhaystack.size = haystack_len;
    bhaystack.realptr = (unsigned char *)Data;

    const void *needle = Data + haystack_len;

    bstr_index_of_mem(&bhaystack, needle, needle_len);
}

static void fuzz_bstr_index_of(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t haystack_len = *((size_t *)Data);
    size_t needle_len = *((size_t *)(Data + sizeof(size_t)));
    Data += 2 * sizeof(size_t);
    Size -= 2 * sizeof(size_t);

    if (haystack_len > Size || needle_len > Size - haystack_len) return;

    bstr bhaystack;
    bhaystack.len = haystack_len;
    bhaystack.size = haystack_len;
    bhaystack.realptr = (unsigned char *)Data;

    bstr bneedle;
    bneedle.len = needle_len;
    bneedle.size = needle_len;
    bneedle.realptr = (unsigned char *)(Data + haystack_len);

    bstr_index_of(&bhaystack, &bneedle);
}

static void fuzz_bstr_util_mem_index_of_mem_nocasenorzero(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t haystack_len = *((size_t *)Data);
    size_t needle_len = *((size_t *)(Data + sizeof(size_t)));
    Data += 2 * sizeof(size_t);
    Size -= 2 * sizeof(size_t);

    if (haystack_len > Size || needle_len > Size - haystack_len) return;

    const void *haystack = Data;
    const void *needle = Data + haystack_len;

    bstr_util_mem_index_of_mem_nocasenorzero(haystack, haystack_len, needle, needle_len);
}

static void fuzz_bstr_util_mem_index_of_mem(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t haystack_len = *((size_t *)Data);
    size_t needle_len = *((size_t *)(Data + sizeof(size_t)));
    Data += 2 * sizeof(size_t);
    Size -= 2 * sizeof(size_t);

    if (haystack_len > Size || needle_len > Size - haystack_len) return;

    const void *haystack = Data;
    const void *needle = Data + haystack_len;

    bstr_util_mem_index_of_mem(haystack, haystack_len, needle, needle_len);
}

static void fuzz_bstr_util_mem_index_of_mem_nocase(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t haystack_len = *((size_t *)Data);
    size_t needle_len = *((size_t *)(Data + sizeof(size_t)));
    Data += 2 * sizeof(size_t);
    Size -= 2 * sizeof(size_t);

    if (haystack_len > Size || needle_len > Size - haystack_len) return;

    const void *haystack = Data;
    const void *needle = Data + haystack_len;

    bstr_util_mem_index_of_mem_nocase(haystack, haystack_len, needle, needle_len);
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    fuzz_bstr_index_of_mem_nocase(Data, Size);
    fuzz_bstr_index_of_mem(Data, Size);
    fuzz_bstr_index_of(Data, Size);
    fuzz_bstr_util_mem_index_of_mem_nocasenorzero(Data, Size);
    fuzz_bstr_util_mem_index_of_mem(Data, Size);
    fuzz_bstr_util_mem_index_of_mem_nocase(Data, Size);
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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    