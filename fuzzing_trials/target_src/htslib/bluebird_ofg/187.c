#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"
#include "htslib/hts.h"
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for meaningful processing
    if (size < 4) {
        return 0;
    }

    char tmpl1[] = "/tmp/fuzzfile1XXXXXX";
    char tmpl2[] = "/tmp/fuzzfile2XXXXXX";
    int fd1 = mkstemp(tmpl1);
    int fd2 = mkstemp(tmpl2);

    if (fd1 == -1 || fd2 == -1) {
        if (fd1 != -1) {
                close(fd1);
        }
        if (fd2 != -1) {
                close(fd2);
        }
        return 0;
    }

    // Write the fuzzing data to the first temporary file
    if (write(fd1, data, size) != size) {
        close(fd1);
        close(fd2);
        unlink(tmpl1);
        unlink(tmpl2);
        return 0;
    }
    close(fd1);

    // Open the file using htslib
    htsFile *hts_file = hts_open(tmpl1, "r");
    if (!hts_file) {
        unlink(tmpl1);
        unlink(tmpl2);
        return 0;
    }

    // Check if the file is a valid SAM/BAM format
    bam_hdr_t *header = sam_hdr_read(hts_file);
    if (!header) {
        hts_close(hts_file);
        unlink(tmpl1);
        unlink(tmpl2);
        return 0;
    }

    // Attempt to read the first alignment

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_hdr_read to sam_idx_init
    // Ensure dataflow is valid (i.e., non-null)
    if (!hts_file) {
    	return 0;
    }
    sam_hdr_t* ret_sam_hdr_get_ejwkb = sam_hdr_get(hts_file);
    if (ret_sam_hdr_get_ejwkb == NULL){
    	return 0;
    }
    const uint8_t ribzbnsd = size;
    uint32_t ret_bam_auxB_len_uflnm = bam_auxB_len(&ribzbnsd);
    if (ret_bam_auxB_len_uflnm < 0){
    	return 0;
    }
    char* ret_bam_flag2str_luiqw = bam_flag2str(BAM_FQCFAIL);
    if (ret_bam_flag2str_luiqw == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!hts_file) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!header) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_luiqw) {
    	return 0;
    }
    int ret_sam_idx_init_wline = sam_idx_init(hts_file, header, (int )ret_bam_auxB_len_uflnm, ret_bam_flag2str_luiqw);
    if (ret_sam_idx_init_wline < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    bam1_t *aln = bam_init1();
    if (sam_read1(hts_file, header, aln) < 0) {
        bam_destroy1(aln);
        bam_hdr_destroy(header);
        hts_close(hts_file);
        unlink(tmpl1);
        unlink(tmpl2);
        return 0;
    }

    // Call the function-under-test
    hts_idx_t *index = sam_index_load2(hts_file, tmpl1, tmpl2);

    // Ensure that the index is valid before proceeding
    if (index) {
        // Perform additional operations if needed
        hts_idx_destroy(index);
    }

    // Clean up
    bam_destroy1(aln);
    bam_hdr_destroy(header);
    hts_close(hts_file);
    unlink(tmpl1);
    unlink(tmpl2);

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

    LLVMFuzzerTestOneInput_187(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
