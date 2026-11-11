#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h" // Correct path for bam1_t and related functions

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < 4) { // Adjusted to ensure we have at least 2 bytes for tag, 1 byte for len, and 1 byte for new_str
        return 0;
    }

    // Initialize bam1_t structure
    bam1_t bam;
    memset(&bam, 0, sizeof(bam1_t));

    // Extract parameters from the input data
    char tag[3] = {0}; // Ensure tag is null-terminated
    memcpy(tag, data, 2); // Use the first two bytes as tag

    int tag_size = 2;
    int len = data[tag_size]; // Use the next byte as the length

    // Ensure len does not exceed the remaining size
    if (len > size - (tag_size + 1)) {
        return 0;
    }

    const char *new_str = (const char *)(data + tag_size + 1); // Use the remaining data as the new string

    // Call the function under test
    bam_aux_update_str(&bam, tag, len, new_str);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
