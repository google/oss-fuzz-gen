#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>
#include <htslib/regidx.h>  // Include this for hts_reglist_t and hts_reglist_free

int LLVMFuzzerTestOneInput_208(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < sizeof(hts_reglist_t)) {
        return 0;
    }

    // Allocate memory for hts_reglist_t
    hts_reglist_t *reglist = (hts_reglist_t *)malloc(sizeof(hts_reglist_t));
    if (reglist == NULL) {
        return 0;
    }

    // Initialize hts_reglist_t with data
    memset(reglist, 0, sizeof(hts_reglist_t));
    memcpy(reglist, data, size < sizeof(hts_reglist_t) ? size : sizeof(hts_reglist_t));

    // Use a fixed value for the int parameter
    int some_int = 1;

    // Ensure reglist is properly initialized to avoid crash
    reglist->reg = strdup("chr1");  // Assign a valid string to reg
    reglist->intervals = (hts_pair_pos_t *)malloc(sizeof(hts_pair_pos_t));
    if (reglist->intervals == NULL) {
        free(reglist->reg);
        free(reglist);
        return 0;
    }
    reglist->count = 1;

    // Simulate some operations on intervals
    reglist->intervals[0].beg = 0;
    reglist->intervals[0].end = 100;

    // Now free the reglist using hts_reglist_free which handles the intervals
    hts_reglist_free(reglist, some_int);

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

    LLVMFuzzerTestOneInput_208(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
