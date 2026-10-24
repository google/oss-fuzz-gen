#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>
#include <htslib/kstring.h>

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    if (size < 5) {
        return 0;
    }

    // Initialize sam_hdr_t
    sam_hdr_t *hdr = sam_hdr_init();
    if (!hdr) {
        return 0;
    }

    // Split the input data into parts for each string parameter
    size_t part_size = size / 5;
    const char *str1 = (const char *)data;
    const char *str2 = (const char *)(data + part_size);
    const char *str3 = (const char *)(data + 2 * part_size);
    const char *str4 = (const char *)(data + 3 * part_size);
    const char *str5 = (const char *)(data + 4 * part_size);

    // Ensure null-termination of each string
    char *str1_copy = (char *)malloc(part_size + 1);
    char *str2_copy = (char *)malloc(part_size + 1);
    char *str3_copy = (char *)malloc(part_size + 1);
    char *str4_copy = (char *)malloc(part_size + 1);
    char *str5_copy = (char *)malloc(part_size + 1);

    if (!str1_copy || !str2_copy || !str3_copy || !str4_copy || !str5_copy) {
        free(str1_copy);
        free(str2_copy);
        free(str3_copy);
        free(str4_copy);
        free(str5_copy);
        sam_hdr_destroy(hdr);
        return 0;
    }

    memcpy(str1_copy, str1, part_size);
    str1_copy[part_size] = '\0';

    memcpy(str2_copy, str2, part_size);
    str2_copy[part_size] = '\0';

    memcpy(str3_copy, str3, part_size);
    str3_copy[part_size] = '\0';

    memcpy(str4_copy, str4, part_size);
    str4_copy[part_size] = '\0';

    memcpy(str5_copy, str5, part_size);
    str5_copy[part_size] = '\0';

    // Initialize kstring_t
    kstring_t ks = {0, 0, NULL};

    // Call the function-under-test
    int result = sam_hdr_find_tag_id(hdr, str1_copy, str2_copy, str3_copy, str4_copy, &ks);

    // Clean up
    free(str1_copy);
    free(str2_copy);
    free(str3_copy);
    free(str4_copy);
    free(str5_copy);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_173(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
