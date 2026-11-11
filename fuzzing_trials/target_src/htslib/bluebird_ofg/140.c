#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    sam_hdr_t *header = NULL;
    char *region = NULL;
    int tid = 0;
    hts_pos_t beg = 0;
    hts_pos_t end = 0;
    int flags = 0;

    // Ensure the size is sufficient for a minimal test
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the region string and copy data into it
    region = (char *)malloc(size + 1);
    if (region == NULL) {
        return 0;
    }
    memcpy(region, data, size);
    region[size] = '\0'; // Null-terminate the string

    // Create a dummy header for testing
    header = sam_hdr_init();
    if (header == NULL) {
        free(region);
        return 0;
    }

    // Call the function-under-test
    const char *result = sam_parse_region(header, region, &tid, &beg, &end, flags);

    // Clean up
    sam_hdr_destroy(header);
    free(region);

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

    LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
