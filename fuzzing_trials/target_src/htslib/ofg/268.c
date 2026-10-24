#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>
#include <htslib/kstring.h>

int LLVMFuzzerTestOneInput_268(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for extracting necessary data
    if (size < 4) {
        return 0;
    }

    // Initialize sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();
    if (!hdr) {
        return 0;
    }

    // Extract a string for 'type' from the input data
    size_t type_len = strnlen((const char *)data, size);
    char *type = strndup((const char *)data, type_len);
    if (!type) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Extract an integer 'id' from the input data
    int id = (int)data[0];

    // Extract a string for 'tag' from the input data
    const char *tag_data = (const char *)(data + 1);
    size_t tag_len = strnlen(tag_data, size - 1);
    char *tag = strndup(tag_data, tag_len);
    if (!tag) {
        free(type);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Initialize kstring_t object
    kstring_t ks;
    ks.l = 0;
    ks.m = 0;
    ks.s = NULL;

    // Call the function under test
    sam_hdr_find_tag_pos(hdr, type, id, tag, &ks);

    // Free any allocated memory
    if (ks.s != NULL) {
        free(ks.s);
    }
    free(type);
    free(tag);
    sam_hdr_destroy(hdr);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_268(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
