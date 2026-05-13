#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"  // Correct path for sam_hdr_t and sam_hdr_remove_lines

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Initialize a new sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();
    if (!hdr) {
        return 0; // Return if initialization fails
    }

    // Add a dummy header line to ensure hdr is not empty
    if (sam_hdr_add_line(hdr, "HD", "VN", "1.0", NULL) < 0) {
        sam_hdr_destroy(hdr);
        return 0; // Return if adding a line fails
    }

    // Example non-NULL strings for type and value
    const char *type = "HD";   // Header type
    const char *value = "VN";  // Header value

    // Call the function-under-test
    sam_hdr_remove_lines(hdr, type, value, NULL);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
