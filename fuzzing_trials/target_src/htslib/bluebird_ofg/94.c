#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming the necessary headers for sam_hdr_t and kstring_t are included
#include "htslib/sam.h"
#include "/src/htslib/htslib/kstring.h"

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to split into multiple strings
    if (size < 5) {
        return 0;
    }

    // Initialize sam_hdr_t
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Allocate memory for strings
    char *str1 = (char *)malloc(size + 1);
    char *str2 = (char *)malloc(size + 1);
    char *str3 = (char *)malloc(size + 1);
    char *str4 = (char *)malloc(size + 1);

    if (!str1 || !str2 || !str3 || !str4) {
        free(str1);
        free(str2);
        free(str3);
        free(str4);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Split the input data into four parts
    size_t part_size = size / 4;
    memcpy(str1, data, part_size);
    str1[part_size] = '\0';
    memcpy(str2, data + part_size, part_size);
    str2[part_size] = '\0';
    memcpy(str3, data + 2 * part_size, part_size);
    str3[part_size] = '\0';
    memcpy(str4, data + 3 * part_size, size - 3 * part_size);
    str4[size - 3 * part_size] = '\0';

    // Initialize kstring_t
    kstring_t ks;
    ks.s = NULL;
    ks.l = ks.m = 0;

    // Call the function-under-test
    sam_hdr_find_tag_id(hdr, str1, str2, str3, str4, &ks);

    // Clean up
    free(str1);
    free(str2);
    free(str3);
    free(str4);
    free(ks.s);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
