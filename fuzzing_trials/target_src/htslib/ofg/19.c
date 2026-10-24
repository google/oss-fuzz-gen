#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h>  // Include the necessary header for sam_parse1

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Initialize kstring_t
    kstring_t ks;
    ks.l = size;
    ks.m = size + 1;  // Allocate extra space for null-termination
    ks.s = (char *)malloc(ks.m);
    if (ks.s == NULL) {
        return 0;  // Memory allocation failed
    }
    memcpy(ks.s, data, size);
    ks.s[size] = '\0';  // Null-terminate the string

    // Initialize sam_hdr_t
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        free(ks.s);
        return 0;  // Memory allocation failed
    }

    // Initialize bam1_t
    bam1_t *b = bam_init1();
    if (b == NULL) {
        sam_hdr_destroy(hdr);
        free(ks.s);
        return 0;  // Memory allocation failed
    }

    // Call the function-under-test
    int result = sam_parse1(&ks, hdr, b);

    // Clean up resources
    bam_destroy1(b);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_19(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
