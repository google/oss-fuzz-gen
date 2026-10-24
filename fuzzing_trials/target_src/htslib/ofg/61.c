#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming the required headers for sam_hdr_t and sam_hdr_remove_tag_id are included
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Initialize the sam_hdr_t structure
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Ensure data is large enough to create non-NULL strings
    if (size < 5) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Create strings from the data
    size_t part_size = size / 5;
    char *str1 = (char *)malloc(part_size + 1);
    char *str2 = (char *)malloc(part_size + 1);
    char *str3 = (char *)malloc(part_size + 1);
    char *str4 = (char *)malloc(part_size + 1);

    if (!str1 || !str2 || !str3 || !str4) {
        free(str1);
        free(str2);
        free(str3);
        free(str4);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Copy data into strings and null-terminate them
    memcpy(str1, data, part_size);
    str1[part_size] = '\0';
    memcpy(str2, data + part_size, part_size);
    str2[part_size] = '\0';
    memcpy(str3, data + 2 * part_size, part_size);
    str3[part_size] = '\0';
    memcpy(str4, data + 3 * part_size, part_size);
    str4[part_size] = '\0';

    // Call the function-under-test
    sam_hdr_remove_tag_id(hdr, str1, str2, str3, str4);

    // Clean up
    free(str1);
    free(str2);
    free(str3);
    free(str4);
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

    LLVMFuzzerTestOneInput_61(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
