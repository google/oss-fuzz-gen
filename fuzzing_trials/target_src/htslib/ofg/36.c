#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/sam.h" // Assuming this is the correct header for sam_hdr_t

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0; // Failed to initialize header
    }

    // Ensure the data is null-terminated for string operations
    char *lines = (char *)malloc(size + 1);
    if (lines == NULL) {
        sam_hdr_destroy(hdr);
        return 0; // Memory allocation failed
    }
    memcpy(lines, data, size);
    lines[size] = '\0';

    // Call the function-under-test
    int result = sam_hdr_add_lines(hdr, lines, size);

    // Clean up
    free(lines);
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

    LLVMFuzzerTestOneInput_36(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
