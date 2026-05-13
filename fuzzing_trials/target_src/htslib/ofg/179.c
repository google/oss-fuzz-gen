#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "htslib/sam.h"

// Mock function to create a sample sam_hdr_t object using fuzzing data
sam_hdr_t *create_sample_sam_hdr(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return NULL;
    }
    // Use the fuzzing data to add a line to the header
    // Interpret part of the data as a string and use it in the header
    char *line_data = malloc(size + 1);
    if (line_data == NULL) {
        sam_hdr_destroy(hdr);
        return NULL;
    }
    memcpy(line_data, data, size);
    line_data[size] = '\0'; // Ensure null-termination

    // Attempt to add a line to the header using the fuzzing data
    // Use a fixed format for the line to ensure it is valid
    if (sam_hdr_add_line(hdr, "HD", "VN", "1.0", "SO", line_data, NULL) < 0) {
        free(line_data);
        sam_hdr_destroy(hdr);
        return NULL;
    }

    free(line_data);
    return hdr;
}

int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    sam_hdr_t *hdr = create_sample_sam_hdr(data, size);
    if (hdr == NULL) {
        return 0;
    }

    // Call the function-under-test
    sam_hdr_t *dup_hdr = sam_hdr_dup(hdr);

    // Check if dup_hdr is not NULL to ensure the function-under-test is working
    if (dup_hdr != NULL) {
        // Optionally, perform additional operations on dup_hdr to increase code coverage
        sam_hdr_destroy(dup_hdr);
    }

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

    LLVMFuzzerTestOneInput_179(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
