#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>
#include <htslib/kstring.h>

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to split into meaningful parts
    if (size < 4) {
        return 0;
    }

    // Allocate and initialize a sam_hdr_t structure
    sam_hdr_t *hdr = sam_hdr_init();
    if (!hdr) {
        return 0;
    }

    // Split the input data into four parts for the string arguments
    size_t part_size = size / 4;
    const char *arg1 = (const char *)data;
    const char *arg2 = (const char *)(data + part_size);
    const char *arg3 = (const char *)(data + 2 * part_size);
    const char *arg4 = (const char *)(data + 3 * part_size);

    // Ensure null-termination of strings
    char *arg1_str = strndup(arg1, part_size);
    char *arg2_str = strndup(arg2, part_size);
    char *arg3_str = strndup(arg3, part_size);
    char *arg4_str = strndup(arg4, size - 3 * part_size);

    // Initialize kstring_t
    kstring_t ks;
    ks.l = ks.m = 0;
    ks.s = NULL;

    // Call the function-under-test
    sam_hdr_find_line_id(hdr, arg1_str, arg2_str, arg3_str, &ks);

    // Clean up
    free(arg1_str);
    free(arg2_str);
    free(arg3_str);
    free(arg4_str);
    sam_hdr_destroy(hdr);
    free(ks.s);

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

    LLVMFuzzerTestOneInput_143(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
