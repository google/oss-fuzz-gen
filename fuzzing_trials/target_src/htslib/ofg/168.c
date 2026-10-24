#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming sam_hdr_t is defined in the included headers
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for splitting into two strings
    if (size < 2) {
        return 0;
    }

    // Allocate memory for sam_hdr_t
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Split the data into two strings
    size_t split_point = size / 2;
    char *str1 = (char *)malloc(split_point + 1);
    char *str2 = (char *)malloc(size - split_point + 1);

    if (str1 == NULL || str2 == NULL) {
        free(str1);
        free(str2);
        sam_hdr_destroy(hdr);
        return 0;
    }

    memcpy(str1, data, split_point);
    str1[split_point] = '\0';
    memcpy(str2, data + split_point, size - split_point);
    str2[size - split_point] = '\0';

    // Call the function-under-test
    int result = sam_hdr_line_index(hdr, str1, str2);

    // Clean up
    free(str1);
    free(str2);
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

    LLVMFuzzerTestOneInput_168(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
