#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_218(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = NULL;
    char *header_text = NULL;

    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for header text
    header_text = (char *)malloc(size + 1);
    if (header_text == NULL) {
        return 0;
    }

    // Copy data to header text and null-terminate it
    memcpy(header_text, data, size);
    header_text[size] = '\0';

    // Parse the header text into a sam_hdr_t structure
    hdr = sam_hdr_parse(size, header_text);
    if (hdr == NULL) {
        free(header_text);
        return 0;
    }

    // Call the function-under-test
    int nref = sam_hdr_nref(hdr);

    // Clean up
    sam_hdr_destroy(hdr);
    free(header_text);

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

    LLVMFuzzerTestOneInput_218(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
