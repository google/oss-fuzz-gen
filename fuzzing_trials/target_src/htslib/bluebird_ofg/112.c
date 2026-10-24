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

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_read1 to bam_mods_at_qpos
    size_t ret_sam_hdr_length_fshco = sam_hdr_length(NULL);
    if (ret_sam_hdr_length_fshco < 0){
    	return 0;
    }
    hts_base_mod_state* ret_hts_base_mod_state_alloc_pziwe = hts_base_mod_state_alloc();
    if (ret_hts_base_mod_state_alloc_pziwe == NULL){
    	return 0;
    }
    sam_hdr_t ihlrsqwf;
    memset(&ihlrsqwf, 0, sizeof(ihlrsqwf));
    size_t ret_sam_hdr_length_guzcq = sam_hdr_length(&ihlrsqwf);
    if (ret_sam_hdr_length_guzcq < 0){
    	return 0;
    }
    hts_base_mod tupebabg;
    memset(&tupebabg, 0, sizeof(tupebabg));
    // Ensure dataflow is valid (i.e., non-null)
    if (!aln) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_hts_base_mod_state_alloc_pziwe) {
    	return 0;
    }
    int ret_bam_mods_at_qpos_jdrhp = bam_mods_at_qpos(aln, (int )ret_sam_hdr_length_fshco, ret_hts_base_mod_state_alloc_pziwe, &tupebabg, (int )ret_sam_hdr_length_guzcq);
    if (ret_bam_mods_at_qpos_jdrhp < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
