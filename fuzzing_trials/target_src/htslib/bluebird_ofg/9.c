#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>      // Include for close() and unlink()
#include <fcntl.h>       // Include for mkstemp()
#include "htslib/sam.h"
#include "htslib/hts.h"

int jtvvnpmy(void*, const char*){
	return NULL;
}
int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from hts_open to hts_reglist_create
    char* ret_bam_flag2str_gmmqc = bam_flag2str(HTS_RESIZE_CLEAR);
    if (ret_bam_flag2str_gmmqc == NULL){
    	return 0;
    }
    bam1_t drrjznuq;
    memset(&drrjznuq, 0, sizeof(drrjznuq));
    hts_pos_t ret_bam_endpos_abvzv = bam_endpos(&drrjznuq);
    if (ret_bam_endpos_abvzv < 0){
    	return 0;
    }
    unsigned int ret_hts_features_kuxcg = hts_features();
    if (ret_hts_features_kuxcg < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_gmmqc) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!hts_file) {
    	return 0;
    }
    hts_reglist_t* ret_hts_reglist_create_maagg = hts_reglist_create(&ret_bam_flag2str_gmmqc, (int )ret_bam_endpos_abvzv, (int *)&ret_hts_features_kuxcg, (void *)hts_file, jtvvnpmy);
    if (ret_hts_reglist_create_maagg == NULL){
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
