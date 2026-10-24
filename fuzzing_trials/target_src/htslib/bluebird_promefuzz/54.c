#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "htslib/sam.h"

static sam_hdr_t *create_dummy_header() {
    // Create a dummy sam_hdr_t for testing
    const char *header_text = "@HD\tVN:1.0\n@SQ\tSN:chr1\tLN:248956422\n";
    return sam_hdr_parse(strlen(header_text), header_text);
}

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Ensure null-terminated input for sam_hdr_parse
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) {
        return 0;
    }
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    // Test sam_hdr_parse
    sam_hdr_t *header = sam_hdr_parse(Size, null_terminated_data);

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sam_hdr_parse to sam_hdr_remove_except using the plateau pool
    const char *type = "SQ";
    const char *key = "SN";
    const char *value = "ref1";
    // Ensure dataflow is valid (i.e., non-null)
    if (!header) {
    	return 0;
    }
    int ret_sam_hdr_remove_except_ictej = sam_hdr_remove_except(header, type, key, value);
    if (ret_sam_hdr_remove_except_ictej < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    free(null_terminated_data);
    if (!header) {
        return 0;
    }

    // Test sam_hdr_dup
    sam_hdr_t *dup_header = sam_hdr_dup(header);
    if (dup_header) {
        sam_hdr_destroy(dup_header);
    }

    // Test sam_hdr_incr_ref
    sam_hdr_incr_ref(header);

    // Test sam_hdr_length
    size_t length = sam_hdr_length(header);
    if (length == SIZE_MAX) {
        // Handle error if needed
    }

    // Test bam_hdr_dup

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_hdr_length to hts_idx_init
    const uint8_t nzekoalb = Size;
    int64_t ret_bam_aux2i_jqlwh = bam_aux2i(&nzekoalb);
    if (ret_bam_aux2i_jqlwh < 0){
    	return 0;
    }
    int64_t ret_bam_aux2i_nmeef = bam_aux2i((const uint8_t *)&length);
    if (ret_bam_aux2i_nmeef < 0){
    	return 0;
    }
    double ret_bam_aux2f_kpmro = bam_aux2f((const uint8_t *)&length);
    if (ret_bam_aux2f_kpmro < 0){
    	return 0;
    }
    double ret_bam_aux2f_acxbo = bam_aux2f((const uint8_t *)&length);
    if (ret_bam_aux2f_acxbo < 0){
    	return 0;
    }
    hts_idx_t* ret_hts_idx_init_hrwmf = hts_idx_init((int )ret_bam_aux2i_jqlwh, (int )length, (uint64_t )ret_bam_aux2i_nmeef, (int )ret_bam_aux2f_kpmro, (int )ret_bam_aux2f_acxbo);
    if (ret_hts_idx_init_hrwmf == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    sam_hdr_t *bam_dup_header = bam_hdr_dup(header);
    if (bam_dup_header) {
        bam_hdr_destroy(bam_dup_header);
    }

    // Clean up the original header
    sam_hdr_destroy(header);

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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
