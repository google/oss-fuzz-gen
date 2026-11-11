#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/bstr.h"

static bstr *create_bstr_from_data(const uint8_t *Data, size_t Size) {
    if (Size == 0) return NULL;
    
    bstr *b = (bstr *)malloc(sizeof(bstr) + Size);
    if (b == NULL) return NULL;
    
    b->len = Size;
    b->size = Size;
    b->realptr = NULL;
    memcpy((unsigned char *)(b + 1), Data, Size);
    
    return b;
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a bstring from the input data
    bstr *b1 = create_bstr_from_data(Data, Size);
    if (b1 == NULL) return 0;

    // Create a second bstring for comparison
    bstr *b2 = create_bstr_from_data(Data, Size / 2);
    if (b2 == NULL) {
        free(b1);
        return 0;
    }

    // Create a C string from part of the input data
    char *cstr = (char *)malloc(Size + 1);
    if (cstr == NULL) {
        free(b1);
        free(b2);
        return 0;
    }
    memcpy(cstr, Data, Size);
    cstr[Size] = '\0';

    // Test bstr_cmp_c
    bstr_cmp_c(b1, cstr);

    // Test bstr_cmp_c_nocase
    bstr_cmp_c_nocase(b1, cstr);

    // Test bstr_cmp_nocase
    bstr_cmp_nocase(b1, b2);

    // Test bstr_dup
    bstr *b_dup = bstr_dup(b1);
    if (b_dup != NULL) {
        free(b_dup);
    }

    // Test bstr_begins_with
    bstr_begins_with(b1, b2);

    // Test bstr_cmp
    bstr_cmp(b1, b2);

    // Cleanup
    free(b1);
    free(b2);
    free(cstr);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
