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

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
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
    const char jthxrmtn[1024] = "bdhnh";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of hts_open_format
    htsFile *file = hts_open_format(dummy_filename, jthxrmtn, &fmt);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (file) {
        hts_close(file);
    }

    // Fuzz sam_open_mode_opts
    char *mode_opts = sam_open_mode_opts(dummy_filename, "r", NULL);
    if (mode_opts) {
        free(mode_opts);
    }

    // Fuzz sam_index_build
    sam_index_build(dummy_filename, 0);

    // Fuzz sam_open_mode
    char mode[8];
    sam_open_mode(mode, dummy_filename, NULL);

    // Fuzz haddextension

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_open_mode to sam_hdr_remove_except
    sam_hdr_t hvezrmhq;
    memset(&hvezrmhq, 0, sizeof(hvezrmhq));
    sam_hdr_incr_ref(&hvezrmhq);
    char* ret_bam_flag2str_buuvw = bam_flag2str(HTS_RESIZE_CLEAR);
    if (ret_bam_flag2str_buuvw == NULL){
    	return 0;
    }
    char* ret_bam_flag2str_vunbd = bam_flag2str(HTS_VERSION);
    if (ret_bam_flag2str_vunbd == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!mode) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_buuvw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_vunbd) {
    	return 0;
    }
    int ret_sam_hdr_remove_except_zhmlm = sam_hdr_remove_except(&hvezrmhq, mode, ret_bam_flag2str_buuvw, ret_bam_flag2str_vunbd);
    if (ret_sam_hdr_remove_except_zhmlm < 0){
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from haddextension to bam_parse_cigar
    char* ret_bam_flag2str_pyqvn = bam_flag2str(FT_UNKN);
    if (ret_bam_flag2str_pyqvn == NULL){
    	return 0;
    }
    bam1_t* ret_bam_dup1_piibz = bam_dup1(NULL);
    if (ret_bam_dup1_piibz == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_pyqvn) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!modified_filename) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_dup1_piibz) {
    	return 0;
    }
    ssize_t ret_bam_parse_cigar_vpovu = bam_parse_cigar(ret_bam_flag2str_pyqvn, &modified_filename, ret_bam_dup1_piibz);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
