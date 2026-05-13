#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "htslib/sam.h"
#include "htslib/hts.h"
#include "/src/htslib/htslib/bgzf.h" // Include necessary library for BGZF

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    // Initialize variables
    bam_plp_t plp = NULL; // Assuming bam_plp_t is a pointer type
    int ref_id = 0;
    int pos = 0;
    int n_plp = 0;

    // Create a dummy BAM file in memory using BGZF
    BGZF *bgzf = bgzf_open("/dev/null", "w");
    if (bgzf == NULL) {
        return 0;
    }

    // Write the input data to the BGZF file
    if (bgzf_write(bgzf, data, size) < 0) {
        bgzf_close(bgzf);
        return 0;
    }

    // Rewind the BGZF file to the beginning for reading
    if (bgzf_flush(bgzf) < 0 || bgzf_seek(bgzf, 0, SEEK_SET) < 0) {
        bgzf_close(bgzf);
        return 0;
    }

    // Create a BAM file header
    bam_hdr_t *header = bam_hdr_init();
    if (header == NULL) {
        bgzf_close(bgzf);
        return 0;
    }

    // Initialize the pileup iterator with the BGZF file and header
    plp = bam_plp_init((bam_plp_auto_f)bam_read1, bgzf);
    if (plp == NULL) {
        bam_hdr_destroy(header);
        bgzf_close(bgzf);
        return 0;
    }

    // Call the function-under-test
    const bam_pileup1_t *result = bam_plp_auto(plp, &ref_id, &pos, &n_plp);

    // Clean up
    bam_plp_destroy(plp);
    bam_hdr_destroy(header);
    bgzf_close(bgzf);

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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
