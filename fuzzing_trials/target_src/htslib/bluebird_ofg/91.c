#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"
#include "/src/htslib/htslib/kstring.h"

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    sam_hdr_t *hdr = sam_hdr_init();
    const char *type = "HD"; // Assuming a default type for testing
    int pos = 0; // Starting position
    kstring_t ks;
    ks.l = 0;
    ks.m = size;
    ks.s = (char *)malloc(size + 1);

    if (hdr == NULL || ks.s == NULL) {
        sam_hdr_destroy(hdr);
        free(ks.s);
        return 0;
    }

    // Copy data to kstring_t
    memcpy(ks.s, data, size);
    ks.s[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    sam_hdr_find_line_pos(hdr, type, pos, &ks);

    // Clean up
    sam_hdr_destroy(hdr);
    free(ks.s);

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

    LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
