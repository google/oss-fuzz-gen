#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // For mkstemp, write, close, and remove
#include "htslib/hts.h"

int dsrljleo(void*, const char*){
	return NULL;
}
int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate an htsFile
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

    // Close the file descriptor so hts_open can open it
    close(fd);

    // Open the temporary file with hts_open
    htsFile *file = hts_open(tmpl, "r");
    if (file == NULL) {
        return 0;
    }

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from hts_open to hts_reglist_create
    char* ret_bam_flag2str_yrjrm = bam_flag2str(FT_GZ);
    if (ret_bam_flag2str_yrjrm == NULL){
    	return 0;
    }
    const uint8_t kykwqwzc = 64;
    int64_t ret_bam_aux2i_pycnq = bam_aux2i(&kykwqwzc);
    if (ret_bam_aux2i_pycnq < 0){
    	return 0;
    }
    const uint8_t hwzavpmx = 0;
    uint32_t ret_bam_auxB_len_apdek = bam_auxB_len(&hwzavpmx);
    if (ret_bam_auxB_len_apdek < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bam_flag2str_yrjrm) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    hts_reglist_t* ret_hts_reglist_create_jtkvj = hts_reglist_create(&ret_bam_flag2str_yrjrm, (int )ret_bam_aux2i_pycnq, (int *)&ret_bam_auxB_len_apdek, (void *)file, dsrljleo);
    if (ret_hts_reglist_create_jtkvj == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    hts_flush(file);

    // Clean up
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

    LLVMFuzzerTestOneInput_184(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
