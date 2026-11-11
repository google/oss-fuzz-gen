#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "htslib/sam.h"

static int dummy_func(void *data, const bam1_t *b, bam_pileup_cd *cd) {
    // Dummy function for bam_plp_init
    return 0;
}

static int dummy_constructor(void *data, const bam1_t *b, bam_pileup_cd *cd) {
    // Dummy constructor function for bam_plp_constructor
    return 0;
}

static int dummy_destructor(void *data, const bam1_t *b, bam_pileup_cd *cd) {
    // Dummy destructor function for bam_plp_destructor
    return 0;
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int maxcnt = *(int *)Data;
    Data += sizeof(int);
    Size -= sizeof(int);

    // Initialize a bam_plp_t iterator with dummy function
    bam_plp_t iter = bam_plp_init(dummy_func, NULL);
    if (!iter) return 0;

    // Set a max count for the iterator
    bam_plp_set_maxcnt(iter, maxcnt);

    // Set constructor and destructor
    bam_plp_constructor(iter, dummy_constructor);
    bam_plp_destructor(iter, dummy_destructor);

    // Reset the iterator
    bam_plp_reset(iter);

    // Destroy the iterator, cleaning up resources
    bam_plp_destroy(iter);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
