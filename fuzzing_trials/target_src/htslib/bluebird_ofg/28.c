#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"  // Assuming the sam_hdr_t type is defined here

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = NULL;
    char *text = NULL;

    // Allocate and initialize text
    text = (char *)malloc(size + 1);
    if (text == NULL) {
        return 0;
    }
    memcpy(text, data, size);
    text[size] = '\0';  // Null-terminate the string

    // Initialize hdr with the text data
    hdr = sam_hdr_parse(size, text);
    if (hdr == NULL) {
        free(text);
        return 0;
    }

    // Call the function-under-test
    int result = sam_hdr_count_lines(hdr, "SQ");

    // Clean up
    free(text);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
