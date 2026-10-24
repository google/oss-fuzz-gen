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

static bstr *create_bstr(const uint8_t *Data, size_t Size) {
    bstr *b = malloc(sizeof(bstr));
    if (b == NULL) {
        return NULL;
    }
    b->len = Size;
    b->size = Size;
    b->realptr = malloc(Size);
    if (b->realptr == NULL) {
        free(b);
        return NULL;
    }
    memcpy(b->realptr, Data, Size);
    return b;
}

static void free_bstr(bstr *b) {
    if (b) {
        free(b->realptr);
        free(b);
    }
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a bstr from the input data
    bstr *b = create_bstr(Data, Size);
    if (b == NULL) return 0;

    // Ensure the C string is null-terminated
    char *cneedle = malloc(Size + 1);
    if (cneedle == NULL) {
        free_bstr(b);
        return 0;
    }
    memcpy(cneedle, Data, Size);
    cneedle[Size] = '\0';

    // Test bstr_rchr
    int c = Data[0];
    int rchr_result = bstr_rchr(b, c);

    // Test bstr_index_of_c
    int index_of_c_result = bstr_index_of_c(b, cneedle);

    // Test bstr_begins_with_c_nocase
    int begins_with_result = bstr_begins_with_c_nocase(b, cneedle);

    // Test bstr_cmp_c_nocase
    int cmp_c_nocase_result = bstr_cmp_c_nocase(b, cneedle);

    // Test bstr_index_of_c_nocase
    int index_of_c_nocase_result = bstr_index_of_c_nocase(b, cneedle);

    // Test bstr_add_c
    bstr *new_b = bstr_add_c(b, cneedle);
    if (new_b != b) {
        free_bstr(b);
    }
    b = new_b;

    // Cleanup
    free_bstr(b);
    free(cneedle);

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
