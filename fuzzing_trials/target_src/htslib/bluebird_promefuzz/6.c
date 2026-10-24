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

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
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
    const char ufgfdkiv[1024] = "nursd";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of hts_open_format
    htsFile *file = hts_open_format(dummy_filename, ufgfdkiv, &fmt);
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
    kstring_t buffer;
    memset(&buffer, 0, sizeof(kstring_t));
    char *modified_filename = haddextension(&buffer, dummy_filename, 0, ".csi");
    if (modified_filename) {
        free(buffer.s);
    }

    // Fuzz hts_hopen

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from haddextension to bam_parse_cigar
    char* ret_bam_flag2str_hhnsb = bam_flag2str(FT_VCF);
    if (ret_bam_flag2str_hhnsb == NULL){
    	return 0;
    }
    const bam1_t uhdnuzyy;
    memset(&uhdnuzyy, 0, sizeof(uhdnuzyy));
    bam1_t* ret_bam_dup1_udily = bam_dup1(&uhdnuzyy);
    if (ret_bam_dup1_udily == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_hhnsb) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!modified_filename) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_dup1_udily) {
    	return 0;
    }
    ssize_t ret_bam_parse_cigar_przug = bam_parse_cigar(ret_bam_flag2str_hhnsb, &modified_filename, ret_bam_dup1_udily);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bam_parse_cigar to sam_open_mode_opts
    const uint8_t uphzzevn = 1;
    char ret_bam_aux2A_stmrk = bam_aux2A(&uphzzevn);
    const uint8_t vksbbdtd = -1;
    char ret_bam_aux2A_rdfgl = bam_aux2A(&vksbbdtd);
    // Ensure dataflow is valid (i.e., non-null)
    if (!modified_filename) {
    	return 0;
    }
    char* ret_sam_open_mode_opts_rnmdj = sam_open_mode_opts(&ret_bam_aux2A_stmrk, modified_filename, &ret_bam_aux2A_rdfgl);
    if (ret_sam_open_mode_opts_rnmdj == NULL){
    	return 0;
    }
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
