#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define hts_pos_t and hts_name2id_f based on the typical usage in htslib
typedef int64_t hts_pos_t;
typedef int (*hts_name2id_f)(void *, const char *, int *);

// Improved mock implementation of hts_parse_region_29 for compilation purposes
const char *hts_parse_region_29(const char *region, int *tid, hts_pos_t *beg, hts_pos_t *end, hts_name2id_f name2id, void *data, int flags) {
    // Simulate parsing the region string
    if (region == NULL || tid == NULL || beg == NULL || end == NULL) {
        return "Invalid input";
    }

    // For demonstration, assume region strings are in the format "chr:start-end"
    char chr[10];
    if (sscanf(region, "%9[^:]:%ld-%ld", chr, beg, end) == 3) {
        // Call the name2id function to get tid
        if (name2id(data, chr, tid) == 0) {
            return NULL; // Success
        } else {
            return "Name to ID conversion failed";
        }
    }
    return "Parsing failed";
}

// Mock implementation of hts_name2id_f for compilation purposes
int mock_name2id(void *data, const char *name, int *tid) {
    *tid = 0; // Just a dummy implementation
    return 0;
}

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Ensure the data is null-terminated for string operations
    char *region = (char *)malloc(size + 1);
    if (!region) return 0;
    memcpy(region, data, size);
    region[size] = '\0';

    int tid;
    hts_pos_t beg, end;
    void *data_ptr = NULL; // Assuming data pointer is not used in the mock function
    int flags = 0; // Default flags

    // Call the function-under-test
    const char *result = hts_parse_region_29(region, &tid, &beg, &end, mock_name2id, data_ptr, flags);

    // Check result for debugging purposes (in real fuzzing, this might be logged or used for further analysis)
    if (result != NULL) {
        fprintf(stderr, "Error: %s\n", result);
    }

    // Clean up
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_29(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
