#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "/src/libhtp/htp/bstr.h"

static bstr *create_bstr_from_data(const uint8_t *Data, size_t Size) {
    bstr *b = bstr_dup_mem(Data, Size);
    return b;
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Ensure null-terminated string for bstr_dup_c
    char *cstr = (char *)malloc(Size + 1);
    if (!cstr) return 0;
    memcpy(cstr, Data, Size);
    cstr[Size] = '\0';

    // Test bstr_dup_c
    bstr *b_cstr = bstr_dup_c(cstr);
    free(cstr);

    // Test bstr_dup_mem
    bstr *b_mem = bstr_dup_mem(Data, Size);

    // Test bstr_dup
    bstr *b_dup = bstr_dup(b_mem);

    // Test bstr_add
    bstr *b_add = bstr_add(b_cstr, b_mem);
    if (b_add != NULL) {
        b_cstr = b_add;  // Update b_cstr if bstr_add was successful
    }

    // Test bstr_add_mem
    bstr *b_add_mem = bstr_add_mem(b_cstr, Data, Size);
    if (b_add_mem != NULL) {
        b_cstr = b_add_mem;  // Update b_cstr if bstr_add_mem was successful
    }

    // Cleanup
    bstr_free(b_cstr);
    bstr_free(b_mem);
    bstr_free(b_dup);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
