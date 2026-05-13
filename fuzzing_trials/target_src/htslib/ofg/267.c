#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/htslib/htslib/sam.h" // Correct path for the header file

int LLVMFuzzerTestOneInput_267(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Ensure that size is sufficient to extract at least a few characters for strings
    if (size < 6) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Extract strings and integer from the data
    const char *type = (const char *)data;
    const char *id = (const char *)(data + 2);
    int len = (int)data[4];
    kstring_t ks;
    ks.l = 0;
    ks.m = size - 5;
    ks.s = (char *)(data + 5);

    // Ensure strings are null-terminated for safety
    char type_buf[3] = {0};
    char id_buf[3] = {0};
    strncpy(type_buf, type, 2);
    strncpy(id_buf, id, 2);

    // Call the function-under-test
    int result = sam_hdr_find_tag_pos(hdr, type_buf, len, id_buf, &ks);

    // Clean up
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

    LLVMFuzzerTestOneInput_267(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
