#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h" // Assuming the function is part of the htslib library

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0; // Exit if header initialization fails
    }

    // Ensure size is large enough for splitting into multiple strings
    if (size < 4) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Allocate memory for strings
    char *str1 = (char *)malloc(size / 4 + 1);
    char *str2 = (char *)malloc(size / 4 + 1);
    char *str3 = (char *)malloc(size / 4 + 1);
    char *str4 = (char *)malloc(size / 4 + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL || str4 == NULL) {
        free(str1);
        free(str2);
        free(str3);
        free(str4);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Copy parts of data into strings
    memcpy(str1, data, size / 4);
    str1[size / 4] = '\0';
    memcpy(str2, data + size / 4, size / 4);
    str2[size / 4] = '\0';
    memcpy(str3, data + 2 * (size / 4), size / 4);
    str3[size / 4] = '\0';
    memcpy(str4, data + 3 * (size / 4), size / 4);
    str4[size / 4] = '\0';

    // Call the function-under-test
    sam_hdr_update_line(hdr, str1, str2, str3, str4);

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

    LLVMFuzzerTestOneInput_50(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
