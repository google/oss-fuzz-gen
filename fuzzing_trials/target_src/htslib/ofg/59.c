#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Initialize sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Ensure the data is not empty
    if (size == 0) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Create non-NULL strings from the provided data
    const char *arg1 = "HD";
    const char *arg2 = "VN";
    const char *arg3 = "1.0";

    // Copy some data into a buffer to use as a header text
    char *header_text = (char *)malloc(size + 1);
    if (header_text == NULL) {
        sam_hdr_destroy(hdr);
        return 0;
    }
    memcpy(header_text, data, size);
    header_text[size] = '\0';

    // Add the header text to the sam_hdr_t object
    if (sam_hdr_add_lines(hdr, header_text, size) < 0) {
        free(header_text);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Call the function-under-test
    sam_hdr_remove_except(hdr, arg1, arg2, arg3);

    // Clean up
    free(header_text);
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

    LLVMFuzzerTestOneInput_59(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
