#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>      // Include for close() and unlink()
#include <fcntl.h>       // Include for mkstemp()
#include "htslib/sam.h"
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    htsFile *hts_file = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Open the temporary file using hts_open
    hts_file = hts_open(tmpl, "r");
    if (hts_file == NULL) {
        return 0;
    }

    // Define non-NULL strings for the second and third parameters

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from hts_open to sam_write1
    sam_hdr_t* ret_sam_hdr_init_nitcw = sam_hdr_init();
    if (ret_sam_hdr_init_nitcw == NULL){
    	return 0;
    }
    bam1_t bxgmmmgx;
    memset(&bxgmmmgx, 0, sizeof(bxgmmmgx));
    bam1_t* ret_bam_dup1_aqpww = bam_dup1(&bxgmmmgx);
    if (ret_bam_dup1_aqpww == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!hts_file) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sam_hdr_init_nitcw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_dup1_aqpww) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bam_dup1 to bam_parse_basemod
    hts_base_mod_state* ret_hts_base_mod_state_alloc_ikdgb = hts_base_mod_state_alloc();
    if (ret_hts_base_mod_state_alloc_ikdgb == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_dup1_aqpww) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_hts_base_mod_state_alloc_ikdgb) {
    	return 0;
    }
    int ret_bam_parse_basemod_dcshi = bam_parse_basemod(ret_bam_dup1_aqpww, ret_hts_base_mod_state_alloc_ikdgb);
    if (ret_bam_parse_basemod_dcshi < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int ret_sam_write1_nqilr = sam_write1(hts_file, ret_sam_hdr_init_nitcw, ret_bam_dup1_aqpww);
    if (ret_sam_write1_nqilr < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    const char *fnidx = "index_file";
    const char *fnref = "reference_file";

    // Call the function-under-test
    hts_idx_t *index = sam_index_load3(hts_file, fnidx, fnref, 0);

    // Clean up
    if (index != NULL) {
        hts_idx_destroy(index);
    }
    hts_close(hts_file);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
