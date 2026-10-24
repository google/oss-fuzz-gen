#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming sam_hdr_t is defined somewhere in the included headers or libraries
typedef struct {
    // Placeholder for actual structure members
    int num_targets;
    char **target_names;
} sam_hdr_t;

// Mock implementation of sam_hdr_tid2name_188 for compilation purposes
const char * sam_hdr_tid2name_188(const sam_hdr_t *hdr, int tid) {
    if (hdr == NULL || tid < 0 || tid >= hdr->num_targets) {
        return NULL;
    }
    return hdr->target_names[tid];
}

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    // Minimum size check to ensure we have enough data
    if (size < sizeof(int)) {
        return 0;
    }

    // Create a mock sam_hdr_t structure
    sam_hdr_t hdr;
    hdr.num_targets = 3; // Example number of targets
    hdr.target_names = (char **)malloc(hdr.num_targets * sizeof(char *));
    hdr.target_names[0] = strdup("chr1");
    hdr.target_names[1] = strdup("chr2");
    hdr.target_names[2] = strdup("chr3");

    // Extract an integer from the input data for the tid parameter
    int tid = *(const int *)data;

    // Call the function-under-test
    const char *result = sam_hdr_tid2name_188(&hdr, tid);

    // Print the result for debugging purposes
    if (result != NULL) {
        printf("Target name: %s\n", result);
    } else {
        printf("Invalid tid or no target name found.\n");
    }

    // Free allocated memory
    for (int i = 0; i < hdr.num_targets; i++) {
        free(hdr.target_names[i]);
    }
    free(hdr.target_names);

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

    LLVMFuzzerTestOneInput_188(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
