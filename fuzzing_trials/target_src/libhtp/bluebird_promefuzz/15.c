#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/bstr.h"

static void fuzz_bstr_begins_with_mem(const bstr *bhaystack, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        bstr_begins_with_mem(bhaystack, Data, Size);
    }
}

static void fuzz_bstr_begins_with_mem_nocase(const bstr *bhaystack, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        bstr_begins_with_mem_nocase(bhaystack, Data, Size);
    }
}

static void fuzz_bstr_cmp_mem(const bstr *b, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        bstr_cmp_mem(b, Data, Size);
    }
}

static void fuzz_bstr_index_of_mem(const bstr *bhaystack, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        bstr_index_of_mem(bhaystack, Data, Size);
    }
}

static void fuzz_bstr_util_cmp_mem(const uint8_t *Data, size_t Size) {
    if (Size > 1) {
        size_t len1 = Size / 2;
        size_t len2 = Size - len1;
        bstr_util_cmp_mem(Data, len1, Data + len1, len2);
    }
}

static void fuzz_bstr_cmp_mem_nocase(const bstr *b, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        bstr_cmp_mem_nocase(b, Data, Size);
    }
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(bstr)) {
        return 0;
    }

    bstr bhaystack;
    bhaystack.len = Size / 2;
    bhaystack.size = Size;
    bhaystack.realptr = (unsigned char *)Data;

    fuzz_bstr_begins_with_mem(&bhaystack, Data, Size);
    fuzz_bstr_begins_with_mem_nocase(&bhaystack, Data, Size);
    fuzz_bstr_cmp_mem(&bhaystack, Data, Size);
    fuzz_bstr_index_of_mem(&bhaystack, Data, Size);
    fuzz_bstr_util_cmp_mem(Data, Size);
    fuzz_bstr_cmp_mem_nocase(&bhaystack, Data, Size);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
