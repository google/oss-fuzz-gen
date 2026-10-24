#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Include the correct header file for sam_hdr_t
#include "/src/htslib/htslib/sam.h"

// Remove the extern "C" linkage specification as it is not needed in C code
int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract meaningful strings
    if (size < 5) {
        return 0;
    }

    // Create and initialize a sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init(); // Assuming sam_hdr_init() initializes a sam_hdr_t object
    if (!hdr) {
        return 0; // Check if initialization was successful
    }

    // Extract strings from data
    size_t offset = 0;
    const char *arg1 = (const char *)(data + offset);
    size_t arg1_len = strnlen(arg1, size - offset);
    offset += arg1_len + 1;
    if (offset >= size) return 0;

    const char *arg2 = (const char *)(data + offset);
    size_t arg2_len = strnlen(arg2, size - offset);
    offset += arg2_len + 1;
    if (offset >= size) return 0;

    const char *arg3 = (const char *)(data + offset);
    size_t arg3_len = strnlen(arg3, size - offset);
    offset += arg3_len + 1;
    if (offset >= size) return 0;

    const char *arg4 = (const char *)(data + offset);
    size_t arg4_len = strnlen(arg4, size - offset);
    if (offset + arg4_len >= size) return 0;

    // Call the function under test
    int result = sam_hdr_remove_tag_id(hdr, arg1, arg2, arg3, arg4);

    // Clean up
    sam_hdr_destroy(hdr); // Assuming sam_hdr_destroy() cleans up a sam_hdr_t object

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

    LLVMFuzzerTestOneInput_60(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
