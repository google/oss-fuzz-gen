#include <stdint.h>
#include <stddef.h>
#include "/src/htslib/htslib/sam.h" // Correct path for sam.h

int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    // Call the function-under-test
    sam_hdr_t *hdr = sam_hdr_init();

    // Check if hdr is not NULL and perform any necessary operations
    if (hdr != NULL) {
        // Attempt to parse the input data as a SAM header
        if (size > 0) {
            // Correct the function call to match the expected parameters
            sam_hdr_t *parsed_hdr = sam_hdr_parse(size, (const char *)data);
            if (parsed_hdr != NULL) {
                // If parsing was successful, replace the original header
                sam_hdr_destroy(hdr);
                hdr = parsed_hdr;
            }
        }

        // Free or cleanup hdr if needed
        sam_hdr_destroy(hdr);
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

    LLVMFuzzerTestOneInput_67(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
