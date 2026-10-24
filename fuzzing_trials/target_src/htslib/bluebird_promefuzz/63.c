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

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_hdr_parse to sam_write1
    htsFile ofwoxztm;
    memset(&ofwoxztm, 0, sizeof(ofwoxztm));
    sam_hdr_t* ret_sam_hdr_read_fptmw = sam_hdr_read(&ofwoxztm);
    if (ret_sam_hdr_read_fptmw == NULL){
    	return 0;
    }
    bam1_t* ret_bam_dup1_kgpvi = bam_dup1(NULL);
    if (ret_bam_dup1_kgpvi == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!header) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_dup1_kgpvi) {
    	return 0;
    }
    int ret_sam_write1_jyiio = sam_write1(&ofwoxztm, header, ret_bam_dup1_kgpvi);
    if (ret_sam_write1_jyiio < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
