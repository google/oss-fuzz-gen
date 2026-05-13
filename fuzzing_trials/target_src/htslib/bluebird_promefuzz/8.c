#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/hfile.h"
#include "htslib/sam.h"
#include "htslib/hts.h"

static char *create_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *fp = fopen("./dummy_file", "wb");
    if (!fp) {
        return NULL;
    }
    fwrite(Data, 1, Size, fp);
    fclose(fp);
    return "./dummy_file";
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy file with the input data
    const char *dummy_filename = create_dummy_file(Data, Size);
    if (!dummy_filename) {
        return 0;
    }

    // Fuzz hts_open_format
    htsFormat fmt;
    memset(&fmt, 0, sizeof(htsFormat));
    fmt.specific = NULL; // No specific options needed
    htsFile *file = hts_open_format(dummy_filename, "r", &fmt);
    if (file) {
        hts_close(file);
    }

    // Fuzz sam_open_mode_opts
    char *mode_opts = sam_open_mode_opts(dummy_filename, "r", NULL);
    if (mode_opts) {
        free(mode_opts);
    }

    // Fuzz sam_index_build
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of sam_index_build
    sam_index_build(dummy_filename, BAM_CHARD_CLIP);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Fuzz sam_open_mode
    char mode[8];
    sam_open_mode(mode, dummy_filename, NULL);

    // Fuzz haddextension

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_open_mode to hts_open

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_open_mode to bam_aux_update_str
    const bam1_t hrhmcebm;
    memset(&hrhmcebm, 0, sizeof(hrhmcebm));
    bam1_t* ret_bam_dup1_uzrmx = bam_dup1(&hrhmcebm);
    if (ret_bam_dup1_uzrmx == NULL){
    	return 0;
    }
    const uint8_t rgjqivut = 1;
    int64_t ret_bam_aux2i_eykkv = bam_aux2i(&rgjqivut);
    if (ret_bam_aux2i_eykkv < 0){
    	return 0;
    }
    char* ret_bam_flag2str_zerco = bam_flag2str(BAM_USER_OWNS_DATA);
    if (ret_bam_flag2str_zerco == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_dup1_uzrmx) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!mode) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_zerco) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bam_flag2str to bam_aux_update_float
    bam1_t* ret_bam_dup1_njeop = bam_dup1(ret_bam_dup1_uzrmx);
    if (ret_bam_dup1_njeop == NULL){
    	return 0;
    }
    int64_t ret_bam_aux2i_qplps = bam_aux2i((const uint8_t *)&ret_bam_aux2i_eykkv);
    if (ret_bam_aux2i_qplps < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_dup1_njeop) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_zerco) {
    	return 0;
    }
    int ret_bam_aux_update_float_tanbg = bam_aux_update_float(ret_bam_dup1_njeop, ret_bam_flag2str_zerco, (float )ret_bam_aux2i_qplps);
    if (ret_bam_aux_update_float_tanbg < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of bam_aux_update_str
    int ret_bam_aux_update_str_qnand = bam_aux_update_str(ret_bam_dup1_njeop, mode, (int)ret_bam_aux2i_eykkv, ret_bam_flag2str_zerco);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (ret_bam_aux_update_str_qnand < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char* ret_bam_flag2str_dnsyn = bam_flag2str(BAM_FSUPPLEMENTARY);
    if (ret_bam_flag2str_dnsyn == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_dnsyn) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!mode) {
    	return 0;
    }
    htsFile* ret_hts_open_pujzf = hts_open(ret_bam_flag2str_dnsyn, mode);
    if (ret_hts_open_pujzf == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    kstring_t buffer;
    memset(&buffer, 0, sizeof(kstring_t));
    char *modified_filename = haddextension(&buffer, dummy_filename, 0, ".csi");
    if (modified_filename) {
        free(buffer.s);
    }

    // Fuzz hts_hopen
    hFILE *hfile = hopen(dummy_filename, "rb");
    if (hfile) {
        htsFile *hfile_open = hts_hopen(hfile, dummy_filename, "r");
        if (hfile_open) {
            hts_close(hfile_open);
        } else {
            hclose(hfile);  // Close only if hts_hopen fails
        }
    }

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
