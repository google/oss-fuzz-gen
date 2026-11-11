#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming the necessary header files for sam_hdr_t and kstring_t are included
#include <htslib/sam.h> // Hypothetical include for sam_hdr_t
#include <htslib/kstring.h> // Hypothetical include for kstring_t

int sam_hdr_find_line_id(sam_hdr_t *, const char *, const char *, const char *, kstring_t *);

// Remove the 'extern "C"' linkage specification which is not valid in C
int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Ensure there's enough data for the strings
    }

    // Initialize sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();
    if (!hdr) {
        return 0;
    }

    // Split the input data into parts for the strings
    size_t part_size = size / 4;
    char *str1 = (char *)malloc(part_size + 1);
    char *str2 = (char *)malloc(part_size + 1);
    char *str3 = (char *)malloc(part_size + 1);
    char *str4 = (char *)malloc(part_size + 1);

    if (!str1 || !str2 || !str3 || !str4) {
        sam_hdr_destroy(hdr);
        free(str1);
        free(str2);
        free(str3);
        free(str4);
        return 0;
    }

    memcpy(str1, data, part_size);
    str1[part_size] = '\0';

    memcpy(str2, data + part_size, part_size);
    str2[part_size] = '\0';

    memcpy(str3, data + 2 * part_size, part_size);
    str3[part_size] = '\0';

    memcpy(str4, data + 3 * part_size, part_size);
    str4[part_size] = '\0';

    // Initialize kstring_t object
    kstring_t ks;
    ks.s = NULL;
    ks.l = ks.m = 0;

    // Call the function-under-test
    sam_hdr_find_line_id(hdr, str1, str2, str3, &ks);

    // Clean up
    sam_hdr_destroy(hdr);
    free(str1);
    free(str2);
    free(str3);
    free(str4);
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

    LLVMFuzzerTestOneInput_144(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
