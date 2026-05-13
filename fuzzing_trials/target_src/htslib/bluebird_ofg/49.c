#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/sam.h" // Assuming the function is part of the HTSlib library

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Ensure that size is large enough to create valid strings
    if (size < 2) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Split the data into two parts for the two string arguments
    size_t mid = size / 2;
    char *str1 = (char *)malloc(mid + 1);
    char *str2 = (char *)malloc(size - mid + 1);

    if (str1 == NULL || str2 == NULL) {
        free(str1);
        free(str2);
        sam_hdr_destroy(hdr);
        return 0;
    }

    memcpy(str1, data, mid);
    str1[mid] = '\0';

    memcpy(str2, data + mid, size - mid);
    str2[size - mid] = '\0';

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
