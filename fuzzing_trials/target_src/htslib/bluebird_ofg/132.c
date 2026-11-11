#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>      // Include for close() and unlink()
#include <fcntl.h>       // Include for mkstemp()
#include "htslib/sam.h"
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
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
    const char *fnidx = "index_file";
    const char *fnref = "reference_file";

    // Call the function-under-test
    hts_idx_t *index = sam_index_load3(hts_file, fnidx, fnref, 0);

    // Clean up
    if (index != NULL) {
        hts_idx_destroy(index);
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_index_load3 to sam_hdr_set
    // Ensure dataflow is valid (i.e., non-null)
    if (!hts_file) {
    	return 0;
    }
    sam_hdr_t* ret_sam_hdr_read_nknct = sam_hdr_read(hts_file);
    if (ret_sam_hdr_read_nknct == NULL){
    	return 0;
    }
    bam1_t srmkkdap;
    memset(&srmkkdap, 0, sizeof(srmkkdap));
    hts_pos_t ret_bam_endpos_ygpnl = bam_endpos(&srmkkdap);
    if (ret_bam_endpos_ygpnl < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!hts_file) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sam_hdr_read_nknct) {
    	return 0;
    }
    int ret_sam_hdr_set_lhanu = sam_hdr_set(hts_file, ret_sam_hdr_read_nknct, (int )ret_bam_endpos_ygpnl);
    if (ret_sam_hdr_set_lhanu < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
