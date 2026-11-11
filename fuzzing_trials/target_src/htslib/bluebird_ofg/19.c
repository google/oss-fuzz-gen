#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "htslib/hts.h"
#include "htslib/sam.h"

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        remove(tmpl);
        return 0;
    }
    close(fd);

    // Open the file using hts_open
    htsFile *file = hts_open(tmpl, "r");
    if (file == NULL) {
        remove(tmpl);
        return 0;
    }

    // Ensure the file is a valid SAM/BAM/CRAM file
    bam_hdr_t *header = sam_hdr_read(file);
    if (header == NULL) {
        hts_close(file);
        remove(tmpl);
        return 0;
    }

    // Read a record to ensure the file is properly formatted

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_hdr_read to sam_hdr_remove_except
    char* ret_bam_flag2str_pfmkm = bam_flag2str(HTS_IDX_NOCOOR);
    if (ret_bam_flag2str_pfmkm == NULL){
    	return 0;
    }
    char* ret_bam_flag2str_zbfuc = bam_flag2str(SAM_FORMAT_VERSION);
    if (ret_bam_flag2str_zbfuc == NULL){
    	return 0;
    }
    const uint8_t pwuzfjqt = size;
    char ret_bam_aux2A_diccd = bam_aux2A(&pwuzfjqt);
    // Ensure dataflow is valid (i.e., non-null)
    if (!header) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_pfmkm) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_zbfuc) {
    	return 0;
    }
    int ret_sam_hdr_remove_except_smiyf = sam_hdr_remove_except(header, ret_bam_flag2str_pfmkm, ret_bam_flag2str_zbfuc, &ret_bam_aux2A_diccd);
    if (ret_sam_hdr_remove_except_smiyf < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    bam1_t *b = bam_init1();
    if (b == NULL) {
        bam_hdr_destroy(header);
        hts_close(file);
        remove(tmpl);
        return 0;
    }

    int ret = sam_read1(file, header, b);
    if (ret < 0) {
        bam_destroy1(b);
        bam_hdr_destroy(header);
        hts_close(file);
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    // Note: sam_idx_save requires a valid index, which we do not have in this context.
    // This function call is likely incorrect and should be replaced with a more appropriate test.
    // int result = sam_idx_save(file);

    // Clean up
    bam_destroy1(b);
    bam_hdr_destroy(header);
    hts_close(file);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
