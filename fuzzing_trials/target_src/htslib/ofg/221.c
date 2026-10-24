#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/kstring.h"
#include "htslib/sam.h"

extern int bam_plp_insertion(const bam_pileup1_t *pl, kstring_t *ks, int *oplen);

int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    if (size < sizeof(bam_pileup1_t)) {
        return 0;
    }

    // Initialize bam_pileup1_t with data from the input
    bam_pileup1_t pl;
    memcpy(&pl, data, sizeof(bam_pileup1_t));

    // Initialize kstring_t
    kstring_t ks;
    ks.l = 0;
    ks.m = 256; // Initial capacity
    ks.s = (char *)malloc(ks.m);
    if (ks.s == NULL) {
        return 0;
    }

    // Ensure that kstring is null-terminated
    ks.s[0] = '\0';

    // Initialize int
    int oplen = 0;

    // Check if the bam_pileup1_t structure is valid and contains necessary data
    if (pl.indel < 0 || pl.indel > ks.m) {
        free(ks.s);
        return 0;
    }

    // Call the function-under-test
    int result = bam_plp_insertion(&pl, &ks, &oplen);

    // Clean up
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

    LLVMFuzzerTestOneInput_221(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
