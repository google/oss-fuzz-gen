#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h>

// Remove 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_180(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for creating a sam_hdr_t object
    if (size < 1) {
        return 0;
    }

    // Create a sam_hdr_t object from the input data
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Initialize the sam_hdr_t object with the input data
    if (sam_hdr_add_lines(hdr, (const char *)data, size) < 0) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Call the function-under-test
    sam_hdr_t *dup_hdr = sam_hdr_dup(hdr);

    // Clean up
    sam_hdr_destroy(hdr);
    if (dup_hdr != NULL) {
        sam_hdr_destroy(dup_hdr);
    }

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

    LLVMFuzzerTestOneInput_180(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
