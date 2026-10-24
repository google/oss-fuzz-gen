#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <htslib/hts.h>
#include <htslib/hts_defs.h>
#include <htslib/bgzf.h> // Include BGZF for file operations
#include <htslib/sam.h>  // Include SAM for BAM/CRAM operations
#include "/src/htslib/hts_internal.h" // Correct path for the internal header

int LLVMFuzzerTestOneInput_215(const uint8_t *data, size_t size) {
    hts_idx_t *idx = NULL;
    BGZF *fp = NULL;
    int result = 0;

    // Create a temporary file to hold the input data
    char tmp_filename[] = "/tmp/fuzz_input.bam";
    fp = bgzf_open(tmp_filename, "w");
    if (fp == NULL) {
        return 0;
    }

    // Write the fuzzer input data to the temporary file
    if (bgzf_write(fp, data, size) < 0) {
        bgzf_close(fp);
        return 0;
    }

    // Close the file to flush data
    bgzf_close(fp);

    // Open the file for reading
    fp = bgzf_open(tmp_filename, "r");
    if (fp == NULL) {
        return 0;
    }

    // Initialize the index
    idx = hts_idx_init(HTS_FMT_CSI, 0, 0, 0, 0);
    if (idx == NULL) {
        bgzf_close(fp);
        return 0;
    }

    // Simulate reading from the file and indexing
    bam_hdr_t *header = bam_hdr_read(fp);
    if (header != NULL) {
        bam1_t *b = bam_init1();
        while (bam_read1(fp, b) >= 0) {
            // Corrected function call with appropriate number of arguments
            hts_idx_push(idx, b->core.tid, b->core.pos, b->core.pos + b->core.l_qseq, fp->block_address, 1);
        }
        bam_destroy1(b);
        bam_hdr_destroy(header);
    }

    // Finalize the index
    hts_idx_finish(idx, 0LL);

    // Call the function-under-test
    result = hts_idx_fmt(idx);

    // Clean up
    hts_idx_destroy(idx);
    bgzf_close(fp);

    return result;
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

    LLVMFuzzerTestOneInput_215(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
