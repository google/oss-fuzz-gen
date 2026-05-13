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
#include <ctype.h>
#include "/src/libhtp/htp/bstr.h"

static void initialize_bstr(bstr *b, const uint8_t *data, size_t size) {
    b->len = size;
    b->size = size;
    b->realptr = (unsigned char *)malloc(size);
    if (b->realptr != NULL) {
        memcpy(b->realptr, data, size);
    }
}

static void cleanup_bstr(bstr *b) {
    if (b->realptr != NULL) {
        free(b->realptr);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare bstr for haystack
    bstr bhaystack;
    initialize_bstr(&bhaystack, Data, Size);

    // Prepare bstr for needle
    size_t needle_size = Size / 2;
    bstr bneedle;
    initialize_bstr(&bneedle, Data + needle_size, needle_size);

    // Prepare C-style needle and ensure it's null-terminated
    char *cneedle = (char *)malloc(needle_size + 1);
    if (cneedle == NULL) {
        cleanup_bstr(&bhaystack);
        cleanup_bstr(&bneedle);
        return 0;
    }
    memcpy(cneedle, Data + needle_size, needle_size);
    cneedle[needle_size] = '\0';

    // Fuzz bstr_index_of_mem_nocase
    if (Size > 1) {
        bstr_index_of_mem_nocase(&bhaystack, Data, needle_size);
    }

    // Fuzz bstr_cmp_nocase
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function bstr_cmp_nocase with bstr_index_of_nocase
    bstr_index_of_nocase(&bhaystack, &bneedle);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Fuzz bstr_begins_with_nocase
    bstr_begins_with_nocase(&bhaystack, &bneedle);

    // Fuzz bstr_index_of
    bstr_index_of(&bhaystack, &bneedle);

    // Fuzz bstr_begins_with
    bstr_begins_with(&bhaystack, &bneedle);

    // Fuzz bstr_index_of_c_nocase
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function bstr_index_of_c_nocase with bstr_begins_with_c
    bstr_begins_with_c(&bhaystack, cneedle);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Cleanup
    cleanup_bstr(&bhaystack);
    cleanup_bstr(&bneedle);
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
